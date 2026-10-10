// Command graphrelay is an SMTP relay that delivers mail through Microsoft Graph.
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/emersion/go-smtp"

	"graphrelay/internal/config"
	"graphrelay/internal/firewall"
	"graphrelay/internal/graph"
	"graphrelay/internal/portal"
	"graphrelay/internal/relay"
	"graphrelay/internal/store"
	"graphrelay/internal/tlsmgr"
)

var version = "dev"

func main() {
	configPath := flag.String("config", "config.yaml", "path to the configuration file")
	resetPW := flag.Bool("reset-admin-password", false, "set a new random portal admin password, print it and exit")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}
	level := slog.LevelInfo
	if os.Getenv("LOG_LEVEL") == "debug" {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	if err := run(log, *configPath, *resetPW); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger, configPath string, resetPW bool) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return err
	}
	st, err := store.Open(filepath.Join(cfg.DataDir, "relay.db"))
	if err != nil {
		return fmt.Errorf("database: %w", err)
	}
	defer st.Close()

	if resetPW {
		pw := randomPassword()
		if err := portal.SetAdminPassword(st, pw); err != nil {
			return err
		}
		fmt.Printf("New admin password: %s\n", pw)
		return nil
	}
	if generated, err := portal.EnsureAdmin(st, cfg.Portal.InitialAdminPassword); err != nil {
		return err
	} else if generated != "" {
		log.Warn("created portal admin account — change this password after signing in",
			"username", "admin", "password", generated)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Info("setting up TLS", "mode", cfg.TLS.Mode, "hostname", cfg.Hostname)
	tm, err := tlsmgr.Setup(ctx, cfg)
	if err != nil {
		return err
	}
	for _, w := range tm.Warnings {
		log.Warn(w)
	}

	gc := graph.New(cfg.Graph.TenantID, cfg.Graph.ClientID, cfg.Graph.ClientSecret, cfg.Graph.Timeout)
	go func() {
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		if err := gc.CheckToken(cctx); err != nil {
			log.Error("Microsoft Graph authentication failed — check graph.* settings", "err", err)
		} else {
			log.Info("Microsoft Graph authentication OK")
		}
	}()

	rl := &relay.Relay{Store: st, Graph: gc, Matcher: relay.NewMatcher(st), Log: log, SendTimeout: cfg.Graph.Timeout}

	hostsChanged := func() {}
	if cfg.Firewall.AllowlistFile != "" {
		fw := &firewall.Exporter{Store: st, Resolve: rl.Matcher.Resolve, Path: cfg.Firewall.AllowlistFile, Log: log}
		hostsChanged = fw.Notify
		go fw.Run(ctx)
	}

	// --- SMTP listeners ---
	var servers []*smtp.Server
	errc := make(chan error, 4)
	startSMTP := func(addr, label string, implicitTLS, requireTLS bool) error {
		if addr == "" {
			return nil
		}
		s := smtp.NewServer(rl.Backend(label, requireTLS))
		s.Domain = cfg.Hostname
		s.MaxMessageBytes = cfg.SMTP.MaxMessageBytes
		s.MaxRecipients = cfg.SMTP.MaxRecipients
		s.ReadTimeout = cfg.SMTP.ReadTimeout
		s.WriteTimeout = cfg.SMTP.WriteTimeout
		s.EnableSMTPUTF8 = true
		s.ErrorLog = smtpLogger{log.With("listener", label)}
		var ln net.Listener
		var err error
		if implicitTLS {
			ln, err = tls.Listen("tcp", addr, tm.TLSConfig)
		} else {
			s.TLSConfig = tm.TLSConfig // advertises STARTTLS
			ln, err = net.Listen("tcp", addr)
		}
		if err != nil {
			return fmt.Errorf("listen %s (%s): %w", addr, label, err)
		}
		servers = append(servers, s)
		log.Info("SMTP listening", "addr", addr, "type", label)
		go func() { errc <- s.Serve(ln) }()
		return nil
	}
	if err := startSMTP(cfg.SMTP.Plain, "25", false, false); err != nil {
		return err
	}
	if err := startSMTP(cfg.SMTP.SMTPS, "465", true, true); err != nil {
		return err
	}
	if err := startSMTP(cfg.SMTP.Submission, "587", false, cfg.SMTP.RequireTLSOnSubmission); err != nil {
		return err
	}

	// --- portal ---
	var web *http.Server
	if cfg.Portal.Listen != "" {
		p := &portal.Portal{Cfg: cfg, Store: st, Graph: gc, TLS: tm, Matcher: rl.Matcher, Log: log, Started: time.Now(),
			HostsChanged: hostsChanged}
		h, err := p.Handler()
		if err != nil {
			return err
		}
		web = &http.Server{
			Addr:              cfg.Portal.Listen,
			Handler:           h,
			TLSConfig:         tm.TLSConfig,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       time.Minute,
			WriteTimeout:      2 * time.Minute,
			ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelDebug),
		}
		ln, err := net.Listen("tcp", cfg.Portal.Listen)
		if err != nil {
			return fmt.Errorf("listen portal %s: %w", cfg.Portal.Listen, err)
		}
		log.Info("management portal listening", "url", "https://"+cfg.Hostname+portSuffix(cfg.Portal.Listen))
		go func() { errc <- web.ServeTLS(ln, "", "") }()
	}

	go pruneLoop(ctx, log, st, cfg.LogRetentionDays)

	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case err := <-errc:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("listener stopped", "err", err)
		}
	}
	sctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, s := range servers {
		s.Shutdown(sctx)
	}
	if web != nil {
		web.Shutdown(sctx)
	}
	return nil
}

func pruneLoop(ctx context.Context, log *slog.Logger, st *store.Store, days int) {
	if days <= 0 {
		return
	}
	t := time.NewTicker(6 * time.Hour)
	defer t.Stop()
	for {
		if n, err := st.PruneLog(time.Now().AddDate(0, 0, -days)); err != nil {
			log.Error("prune message log", "err", err)
		} else if n > 0 {
			log.Info("pruned message log", "rows", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func portSuffix(addr string) string {
	if _, port, err := net.SplitHostPort(addr); err == nil && port != "443" {
		return ":" + port
	}
	return ""
}

type smtpLogger struct{ l *slog.Logger }

func (s smtpLogger) Printf(format string, v ...any) { s.l.Debug(fmt.Sprintf(format, v...)) }
func (s smtpLogger) Println(v ...any)               { s.l.Debug(fmt.Sprint(v...)) }

func randomPassword() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
