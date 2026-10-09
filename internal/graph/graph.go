// Package graph sends mail through Microsoft Graph using the OAuth2
// client-credentials flow (application permissions).
//
// Required application permissions on the app registration:
//   - Mail.Send       (all messages)
//   - Mail.ReadWrite  (messages larger than ~3 MB, which are built as drafts)
package graph

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Endpoints; variables so tests can point them at a fake server.
var (
	graphBase = "https://graph.microsoft.com/v1.0"
	loginBase = "https://login.microsoftonline.com"
)

// MaxMIMEBytes is the largest raw message sent in one sendMail call. Graph caps the
// request at 4 MB and the MIME body is base64 encoded (+33%).
const MaxMIMEBytes = 2_900_000

// Attachments up to this size are posted directly; larger ones use an upload session.
const directAttachmentLimit = 2_500_000

const uploadChunk = 10 * 320 * 1024 // must be a multiple of 320 KiB

// SetEndpoints overrides the Graph and login base URLs. Intended for tests.
func SetEndpoints(graphURL, loginURL string) { graphBase, loginBase = graphURL, loginURL }

type Client struct {
	tenant, clientID, secret string
	http                     *http.Client

	mu          sync.Mutex
	token       string
	tokenExpiry time.Time
}

func New(tenant, clientID, secret string, timeout time.Duration) *Client {
	return &Client{tenant: tenant, clientID: clientID, secret: secret, http: &http.Client{Timeout: timeout}}
}

// Error is a non-2xx response from Graph or the token endpoint.
type Error struct {
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("graph %d %s: %s", e.Status, e.Code, e.Message)
	}
	return fmt.Sprintf("graph %d: %s", e.Status, e.Message)
}

// Temporary reports whether the error is worth retrying later.
// Network errors (non-*Error) are treated as temporary.
func Temporary(err error) bool {
	var ge *Error
	if errors.As(err, &ge) {
		return ge.Status == 429 || ge.Status >= 500
	}
	return true
}

func (c *Client) accessToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Now().Before(c.tokenExpiry) {
		return c.token, nil
	}
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {c.clientID},
		"client_secret": {c.secret},
		"scope":         {"https://graph.microsoft.com/.default"},
	}
	endpoint := loginBase + "/" + url.PathEscape(c.tenant) + "/oauth2/v2.0/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var body struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK || body.AccessToken == "" {
		return "", &Error{Status: resp.StatusCode, Code: body.Error, Message: firstLine(body.Description)}
	}
	c.token = body.AccessToken
	c.tokenExpiry = time.Now().Add(time.Duration(body.ExpiresIn)*time.Second - 2*time.Minute)
	return c.token, nil
}

// CheckToken verifies that the credentials work.
func (c *Client) CheckToken(ctx context.Context) error {
	_, err := c.accessToken(ctx)
	return err
}

// do performs an authenticated Graph request, retrying throttled/unavailable responses.
// If out is non-nil the JSON response is decoded into it.
func (c *Client) do(ctx context.Context, method, path, contentType string, body []byte, out any) error {
	var lastErr error
	for attempt := 0; attempt < 4; attempt++ {
		token, err := c.accessToken(ctx)
		if err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, method, graphBase+path, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		resp, err := c.http.Do(req)
		if err != nil {
			return err
		}
		if resp.StatusCode < 300 {
			defer resp.Body.Close()
			if out != nil {
				return json.NewDecoder(resp.Body).Decode(out)
			}
			io.Copy(io.Discard, resp.Body)
			return nil
		}
		lastErr = readError(resp)
		resp.Body.Close()
		if resp.StatusCode == 401 {
			c.mu.Lock()
			c.token = ""
			c.mu.Unlock()
		}
		if resp.StatusCode != 429 && resp.StatusCode != 503 && resp.StatusCode != 401 {
			return lastErr
		}
		wait := time.Duration(attempt+1) * 2 * time.Second
		if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 {
			wait = min(time.Duration(s)*time.Second, 30*time.Second)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
	return lastErr
}

func readError(resp *http.Response) error {
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var body struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	ge := &Error{Status: resp.StatusCode}
	if json.Unmarshal(raw, &body) == nil && body.Error.Code != "" {
		ge.Code, ge.Message = body.Error.Code, body.Error.Message
	} else {
		ge.Message = firstLine(string(raw))
	}
	return ge
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	return s
}

func userPath(mailbox string) string { return "/users/" + url.PathEscape(mailbox) }

// SendMIME sends a complete RFC 5322 message as-is. Recipients are taken from the
// To/Cc/Bcc headers. Size must not exceed MaxMIMEBytes.
func (c *Client) SendMIME(ctx context.Context, mailbox string, raw []byte) error {
	enc := make([]byte, base64.StdEncoding.EncodedLen(len(raw)))
	base64.StdEncoding.Encode(enc, raw)
	return c.do(ctx, http.MethodPost, userPath(mailbox)+"/sendMail", "text/plain", enc, nil)
}

// Message is used for the large-message path, where the MIME has been
// decomposed and is rebuilt as a Graph draft.
type Message struct {
	Subject     string
	HTML        bool
	Body        string
	From        *Address // display name only; the address is always the mailbox
	To, Cc, Bcc []Address
	ReplyTo     []Address
	Importance  string // "low", "normal", "high" or ""
	Attachments []Attachment
}

type Address struct{ Name, Email string }

type Attachment struct {
	Name        string
	ContentType string
	ContentID   string
	Inline      bool
	Data        []byte
}

type jsonRecipient struct {
	EmailAddress struct {
		Name    string `json:"name,omitempty"`
		Address string `json:"address"`
	} `json:"emailAddress"`
}

func recipients(list []Address) []jsonRecipient {
	out := make([]jsonRecipient, 0, len(list))
	for _, a := range list {
		var r jsonRecipient
		r.EmailAddress.Name, r.EmailAddress.Address = a.Name, a.Email
		out = append(out, r)
	}
	return out
}

// SendLarge creates a draft in the mailbox, attaches files (using upload sessions
// for big ones), then sends it. The draft is deleted if any step fails.
func (c *Client) SendLarge(ctx context.Context, mailbox string, m *Message) (err error) {
	draft := map[string]any{
		"subject":      m.Subject,
		"body":         map[string]string{"contentType": map[bool]string{true: "HTML", false: "Text"}[m.HTML], "content": m.Body},
		"toRecipients": recipients(m.To),
		"ccRecipients": recipients(m.Cc),
	}
	if len(m.Bcc) > 0 {
		draft["bccRecipients"] = recipients(m.Bcc)
	}
	if len(m.ReplyTo) > 0 {
		draft["replyTo"] = recipients(m.ReplyTo)
	}
	if m.From != nil && m.From.Name != "" {
		draft["from"] = recipients([]Address{{Name: m.From.Name, Email: mailbox}})[0]
	}
	if m.Importance != "" {
		draft["importance"] = m.Importance
	}
	payload, _ := json.Marshal(draft)
	var created struct {
		ID string `json:"id"`
	}
	if err := c.do(ctx, http.MethodPost, userPath(mailbox)+"/messages", "application/json", payload, &created); err != nil {
		return fmt.Errorf("create draft: %w", err)
	}
	msgPath := userPath(mailbox) + "/messages/" + url.PathEscape(created.ID)
	defer func() {
		if err != nil {
			// Best effort: don't leave half-built drafts behind.
			cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			defer cancel()
			c.do(cctx, http.MethodDelete, msgPath, "", nil, nil)
		}
	}()

	for i := range m.Attachments {
		a := &m.Attachments[i]
		if len(a.Data) <= directAttachmentLimit {
			err = c.addAttachment(ctx, msgPath, a)
		} else {
			err = c.uploadAttachment(ctx, msgPath, a)
		}
		if err != nil {
			return fmt.Errorf("attachment %q: %w", a.Name, err)
		}
	}
	if err = c.do(ctx, http.MethodPost, msgPath+"/send", "", nil, nil); err != nil {
		return fmt.Errorf("send draft: %w", err)
	}
	return nil
}

func (c *Client) addAttachment(ctx context.Context, msgPath string, a *Attachment) error {
	body := map[string]any{
		"@odata.type":  "#microsoft.graph.fileAttachment",
		"name":         a.Name,
		"contentType":  a.ContentType,
		"contentBytes": base64.StdEncoding.EncodeToString(a.Data),
		"isInline":     a.Inline,
	}
	if a.ContentID != "" {
		body["contentId"] = a.ContentID
	}
	payload, _ := json.Marshal(body)
	return c.do(ctx, http.MethodPost, msgPath+"/attachments", "application/json", payload, nil)
}

func (c *Client) uploadAttachment(ctx context.Context, msgPath string, a *Attachment) error {
	item := map[string]any{
		"attachmentType": "file",
		"name":           a.Name,
		"size":           len(a.Data),
		"contentType":    a.ContentType,
		"isInline":       a.Inline,
	}
	if a.ContentID != "" {
		item["contentId"] = a.ContentID
	}
	payload, _ := json.Marshal(map[string]any{"AttachmentItem": item})
	var session struct {
		UploadURL string `json:"uploadUrl"`
	}
	if err := c.do(ctx, http.MethodPost, msgPath+"/attachments/createUploadSession", "application/json", payload, &session); err != nil {
		return fmt.Errorf("create upload session: %w", err)
	}
	total := len(a.Data)
	for start := 0; start < total; start += uploadChunk {
		end := min(start+uploadChunk, total)
		// The upload URL is pre-authorised; sending a bearer token to it is rejected.
		req, err := http.NewRequestWithContext(ctx, http.MethodPut, session.UploadURL, bytes.NewReader(a.Data[start:end]))
		if err != nil {
			return err
		}
		req.ContentLength = int64(end - start)
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end-1, total))
		resp, err := c.http.Do(req)
		if err != nil {
			return err
		}
		if resp.StatusCode >= 300 {
			err := readError(resp)
			resp.Body.Close()
			return err
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	return nil
}
