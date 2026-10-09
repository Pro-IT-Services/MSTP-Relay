package relay

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/emersion/go-message"
	_ "github.com/emersion/go-message/charset" // decode non-UTF-8 text parts
	"github.com/emersion/go-message/mail"
	"github.com/emersion/go-message/textproto"

	"graphrelay/internal/graph"
)

// prepared is a message ready to hand to Graph.
type prepared struct {
	raw     []byte // headers rewritten, body untouched
	subject string
}

// prepare rewrites the headers of raw:
//   - From is set to the host's mailbox (keeping the display name) when rewriteFrom is on,
//   - envelope recipients missing from To/Cc/Bcc are added as Bcc, because Graph
//     delivers to header recipients, not to the SMTP envelope.
func prepare(raw []byte, envRcpts []string, mailbox string, rewriteFrom bool) (*prepared, error) {
	br := bufio.NewReader(bytes.NewReader(raw))
	th, err := textproto.ReadHeader(br)
	if err != nil {
		return nil, fmt.Errorf("malformed message header: %w", err)
	}
	body, _ := io.ReadAll(br)
	h := mail.Header{Header: message.Header{Header: th}}

	if rewriteFrom {
		name := ""
		if list, err := h.AddressList("From"); err == nil && len(list) > 0 {
			name = list[0].Name
		}
		h.SetAddressList("From", []*mail.Address{{Name: name, Address: mailbox}})
		h.Del("Sender")
	}

	present := map[string]bool{}
	for _, key := range []string{"To", "Cc", "Bcc"} {
		list, _ := h.AddressList(key)
		for _, a := range list {
			present[strings.ToLower(a.Address)] = true
		}
	}
	bcc, _ := h.AddressList("Bcc")
	added := false
	for _, r := range envRcpts {
		if !present[strings.ToLower(r)] {
			bcc = append(bcc, &mail.Address{Address: r})
			present[strings.ToLower(r)] = true
			added = true
		}
	}
	if added {
		h.SetAddressList("Bcc", bcc)
	}

	subject, _ := h.Subject()

	var out bytes.Buffer
	out.Grow(len(raw) + 256)
	if err := textproto.WriteHeader(&out, h.Header.Header); err != nil {
		return nil, err
	}
	out.Write(body)
	return &prepared{raw: out.Bytes(), subject: subject}, nil
}

// toGraphMessage decomposes a MIME message for the large-message (draft) path.
func toGraphMessage(raw []byte) (*graph.Message, error) {
	mr, err := mail.CreateReader(bytes.NewReader(raw))
	if err != nil && !message.IsUnknownCharset(err) {
		return nil, err
	}
	defer mr.Close()

	m := &graph.Message{}
	h := mr.Header
	m.Subject, _ = h.Subject()
	m.To = addrs(h, "To")
	m.Cc = addrs(h, "Cc")
	m.Bcc = addrs(h, "Bcc")
	m.ReplyTo = addrs(h, "Reply-To")
	if from := addrs(h, "From"); len(from) > 0 {
		m.From = &from[0]
	}
	m.Importance = importance(h)

	var plain, html string
	var havePlain, haveHTML bool
	n := 0
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil && !message.IsUnknownCharset(err) {
			return nil, err
		}
		if p == nil {
			continue
		}
		data, err := io.ReadAll(p.Body)
		if err != nil {
			return nil, err
		}
		n++
		switch ph := p.Header.(type) {
		case *mail.InlineHeader:
			ct, _, _ := ph.ContentType()
			switch {
			case ct == "text/html" && !haveHTML:
				html, haveHTML = string(data), true
			case (ct == "text/plain" || ct == "") && !havePlain:
				plain, havePlain = string(data), true
			default:
				m.Attachments = append(m.Attachments, attachment(&ph.Header, ct, "", data, n))
			}
		case *mail.AttachmentHeader:
			ct, _, _ := ph.ContentType()
			name, _ := ph.Filename()
			m.Attachments = append(m.Attachments, attachment(&ph.Header, ct, name, data, n))
		}
	}
	if haveHTML {
		m.HTML, m.Body = true, html
	} else {
		m.Body = plain
	}
	return m, nil
}

func attachment(h *message.Header, ct, name string, data []byte, n int) graph.Attachment {
	if ct == "" {
		ct = "application/octet-stream"
	}
	cid := strings.Trim(h.Get("Content-Id"), "<> ")
	disp, params, _ := h.ContentDisposition()
	if name == "" {
		name = params["filename"]
	}
	if name == "" {
		_, ctParams, _ := h.ContentType()
		name = ctParams["name"]
	}
	if name == "" {
		name = fmt.Sprintf("part%d%s", n, extFor(ct))
	}
	return graph.Attachment{
		Name:        name,
		ContentType: ct,
		ContentID:   cid,
		Inline:      cid != "" && disp != "attachment",
		Data:        data,
	}
}

func extFor(ct string) string {
	if i := strings.IndexByte(ct, '/'); i >= 0 {
		sub := ct[i+1:]
		switch sub {
		case "plain":
			return ".txt"
		case "jpeg", "png", "gif", "pdf", "html", "csv", "xml", "zip":
			return "." + sub
		}
	}
	return ".bin"
}

func addrs(h mail.Header, key string) []graph.Address {
	list, _ := h.AddressList(key)
	out := make([]graph.Address, 0, len(list))
	for _, a := range list {
		out = append(out, graph.Address{Name: a.Name, Email: a.Address})
	}
	return out
}

func importance(h mail.Header) string {
	v := strings.ToLower(h.Get("Importance"))
	switch {
	case v == "high" || v == "low" || v == "normal":
		return v
	}
	p := strings.TrimSpace(h.Get("X-Priority"))
	switch {
	case strings.HasPrefix(p, "1"), strings.HasPrefix(p, "2"):
		return "high"
	case strings.HasPrefix(p, "4"), strings.HasPrefix(p, "5"):
		return "low"
	}
	return ""
}
