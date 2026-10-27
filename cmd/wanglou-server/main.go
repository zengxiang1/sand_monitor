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
	"wanglou/internal/server/ingest"
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
		return fmt.Errorf("usage: wanglou-server serve|node add|node list|node revoke|migrate|healthcheck [--config path]")
	}
	if args[0] == "healthcheck" {
		return healthcheckCommand(args[1:])
	}
	command := args[0]
	args = args[1:]
	if command == "node" {
		if len(args) == 0 {
			return fmt.Errorf("node requires add|list|revoke")
		}
		command += " " + args[0]
		args = args[1:]
	}
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	path := fs.String("config", defaultConfig, "local config path")
	insecure := fs.Bool("insecure-http", false, "allow local development HTTP")
	name := fs.String("name", "", "node name")
	pub := fs.String("pubkey", "", "wanglou-ed25519 public key line")
	if e := fs.Parse(args); e != nil {
		return e
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments")
	}
	switch command {
	case "serve", "migrate", "node add", "node list", "node revoke":
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
	switch command {
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
	dispatcher := &alert.Dispatcher{Store: s}
	if c.WebhookURL != "" {
		dispatcher.Notifiers = append(dispatcher.Notifiers, alert.Webhook{URL: c.WebhookURL})
	}
	if c.TelegramToken != "" {
		dispatcher.Notifiers = append(dispatcher.Notifiers, alert.Telegram{Token: c.TelegramToken, ChatID: c.TelegramChatID})
	}
	var wg sync.WaitGroup
	worker := func(fn func()) { wg.Add(1); go func() { defer wg.Done(); fn() }() }
	worker(func() { s.RunCleanup(ctx) })
	worker(func() { dispatcher.Run(ctx) })
	worker(func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			if e := engine.CheckOffline(time.Now()); e != nil {
				log.Printf("offline check: %v", e)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	})
	handler := ingest.New(s, engine)
	handler.TrustedProxies = c.TrustedProxies
	worker(func() { handler.RunLogging(ctx) })
	server := &http.Server{Addr: c.Listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	worker(func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if e := server.Shutdown(shutdown); e != nil {
			_ = server.Close()
		}
	})
	if *insecure || c.ListenPlain {
		e = server.ListenAndServe()
	} else {
		e = server.ListenAndServeTLS(c.TLSCert, c.TLSKey)
	}
	stop()
	wg.Wait()
	if errors.Is(e, http.ErrServerClosed) {
		return nil
	}
	return e
}
