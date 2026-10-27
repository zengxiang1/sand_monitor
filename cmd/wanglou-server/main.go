package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"
	"wanglou/internal/proto"
	"wanglou/internal/server/alert"
	"wanglou/internal/server/heartbeat"
	"wanglou/internal/server/ingest"
	"wanglou/internal/server/panel"
	"wanglou/internal/server/peer"
	status "wanglou/internal/server/public"
	"wanglou/internal/server/store"
)

func main() {
	if e := run(os.Args[1:]); e != nil {
		log.Print(e)
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: wanglou-server serve|node|admin|migrate|healthcheck [--config path]")
	}
	if args[0] == "healthcheck" {
		return healthcheckCommand(args[1:])
	}
	command := args[0]
	args = args[1:]
	if command == "node" || command == "admin" {
		if len(args) == 0 {
			return fmt.Errorf("%s requires a subcommand", command)
		}
		command += " " + args[0]
		args = args[1:]
	}
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	path := fs.String("config", defaultConfig, "local config path")
	insecure := fs.Bool("insecure-http", false, "allow local development HTTP")
	name := fs.String("name", "", "node name")
	user := fs.String("user", "", "admin username")
	passwordStdin := fs.Bool("password-stdin", false, "read password from standard input")
	pub := fs.String("pubkey", "", "wanglou-ed25519 public key line")
	if e := fs.Parse(args); e != nil {
		return e
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments")
	}
	switch command {
	case "serve", "migrate", "node add", "node list", "node revoke", "admin add", "admin passwd", "admin reset-totp", "admin list", "admin remove":
	default:
		return fmt.Errorf("unknown command %q", command)
	}
	c, e := loadConfig(*path)
	if e != nil {
		return e
	}
	if e = os.MkdirAll(filepath.Dir(c.Database), 0700); e != nil {
		return e
	}
	s, e := store.Open(c.Database)
	if e != nil {
		return e
	}
	defer s.Close()
	s.RetentionDays = c.RetentionDays
	s.Location = c.Location
	// Panel templates, charts and logs format times in the process zone; containers default to UTC.
	time.Local = c.Location
	s.Interval = c.Alerts.Interval
	switch command {
	case "admin add", "admin passwd", "admin reset-totp", "admin list", "admin remove":
		return panel.Admin(s, command[len("admin "):], *user, *passwordStdin, os.Stdin, os.Stdout)
	case "migrate":
		return s.Migrate()
	case "node add":
		key, e := proto.ParsePublicKey(*pub)
		if e != nil {
			return e
		}
		if e = s.AddNode(*name, key, time.Now()); e != nil {
			return e
		}
		fmt.Println(proto.Fingerprint(key))
		return nil
	case "node revoke":
		return s.Revoke(*name, time.Now())
	case "node list":
		nodes, e := s.Nodes()
		if e != nil {
			return e
		}
		for _, n := range nodes {
			state := "online"
			if n.RevokedAt != 0 {
				state = "revoked"
			} else if n.LastSeen == 0 {
				state = "never_seen"
			} else if time.Since(time.Unix(n.LastSeen, 0)) > 3*c.Alerts.Interval {
				state = "offline"
			}
			fmt.Printf("%s\t%s\t%s\t%d\n", n.Name, n.Fingerprint, state, n.LastSeen)
		}
		return nil
	}
	if e = c.validateTransport(*insecure); e != nil {
		return e
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	engine := alert.New(s, c.Alerts)
	heart := &heartbeat.Loop{URL: c.HeartbeatURL}
	exporter := &status.Exporter{Store: s, Dir: c.PublicDir}
	dispatcher := &alert.Dispatcher{Store: s, Scope: c.AlertScope}
	if c.WebhookURL != "" {
		dispatcher.Notifiers = append(dispatcher.Notifiers, alert.Webhook{URL: c.WebhookURL, Instance: c.InstanceName})
	}
	if c.TelegramToken != "" {
		dispatcher.Notifiers = append(dispatcher.Notifiers, alert.Telegram{Token: c.TelegramToken, ChatID: c.TelegramChatID, Instance: c.InstanceName, Location: c.Location})
	}
	peerCheck := &peer.Loop{URL: c.PeerURL, Notifiers: dispatcher.Notifiers}
	var wg sync.WaitGroup
	worker := func(fn func()) { wg.Add(1); go func() { defer wg.Done(); fn() }() }
	worker(func() { s.RunCleanup(ctx) })
	worker(func() { dispatcher.Run(ctx) })
	if c.PeerURL != "" {
		worker(func() { peerCheck.Run(ctx) })
	}
	worker(func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			if e := engine.CheckOffline(time.Now()); e != nil {
				log.Printf("offline check: %v", e)
			} else {
				heart.Offline.Store(time.Now().Unix())
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	})
	worker(func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			if err := s.CheckReminders(time.Now()); err != nil {
				log.Printf("reminder check: %v", err)
			} else {
				heart.Reminders.Store(time.Now().Unix())
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	})
	worker(func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			if err := s.Rollup(ctx, time.Now()); err != nil {
				log.Printf("rollup: %v", err)
			} else {
				heart.Rollup.Store(time.Now().Unix())
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	})

	if c.HeartbeatURL != "" {
		worker(func() {
			ticker := time.NewTicker(60 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if err := heart.Check(ctx, time.Now()); err != nil {
						log.Printf("%v", err)
					}
				}
			}
		})
	}
	if c.PublicDir != "" {
		worker(func() { exporter.Run(ctx) })
	}
	handler := ingest.New(s, engine)
	handler.TrustedProxies = c.TrustedProxies
	worker(func() { handler.RunLogging(ctx) })

	servers := []*http.Server{}
	addServer := func(addr string, handler http.Handler) {
		servers = append(servers, &http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}})
	}
	addServer(c.Listen, handler)
	if c.PanelListen != "" {
		channels := []string{}
		if c.TelegramToken != "" {
			channels = append(channels, "Telegram")
		}
		if c.WebhookURL != "" {
			channels = append(channels, "Webhook")
		}
		addServer(c.PanelListen, panel.New(s, handler, panel.Config{PeerStatus: peerCheck.Status, BackupIngestURL: c.BackupIngestURL, MemoryThreshold: c.Alerts.MemoryThreshold, DiskThreshold: c.Alerts.DiskThreshold, Sustain: c.Alerts.Sustain, PublicDir: c.PublicDir, PublicURL: c.PublicURL, HeartbeatURL: c.HeartbeatURL, HeartbeatStatus: heart.Status, Exporter: exporter, CookieSecure: c.PanelCookieSecure, PublicIngestURL: c.PublicIngestURL, TrustedProxies: c.TrustedProxies, Interval: c.Alerts.Interval, Channels: channels}))
	}
	worker(func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, server := range servers {
			if err := server.Shutdown(shutdown); err != nil {
				_ = server.Close()
			}
		}
	})
	results := make(chan error, len(servers))
	for _, server := range servers {
		worker(func() {
			var err error
			if *insecure || c.ListenPlain {
				err = server.ListenAndServe()
			} else {
				err = server.ListenAndServeTLS(c.TLSCert, c.TLSKey)
			}
			results <- err
		})
	}
	e = <-results
	stop()
	wg.Wait()
	if errors.Is(e, http.ErrServerClosed) {
		return nil
	}
	return e
}
