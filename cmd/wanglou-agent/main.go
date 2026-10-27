package main

import (
	"context"
	"crypto/ed25519"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
	"wanglou/internal/agent"
	"wanglou/internal/agent/collect"
	"wanglou/internal/proto"
)

var version = "dev"

func main() {
	if e := run(os.Args[1:]); e != nil {
		log.Print(e)
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: wanglou-agent init|fingerprint|enroll|run|version")
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	switch args[0] {
	case "version":
		fmt.Println(version)
		return nil
	case "init":
		name := fs.String("name", "", "node name")
		server := fs.String("server", "", "HTTPS server base URL")
		backup := fs.String("backup-server", "", "backup HTTPS server base URL")
		keyPath := fs.String("key", agent.DefaultKey, "private key path")
		config := fs.String("config", agent.DefaultConfig, "local config path")
		state := fs.String("state", "/var/lib/wanglou/agent.seq", "durable sequence path")
		procRoot := fs.String("proc-root", collect.DefaultProcRoot, "local proc mount")
		rootFS := fs.String("root-fs", collect.DefaultRootFS, "local root filesystem mount for statfs")
		wtmpPath := fs.String("wtmp-path", collect.DefaultWtmpPath, "local wtmp file")
		force := fs.Bool("force", false, "replace existing key and config")
		insecure := fs.Bool("insecure-http", false, "allow local development HTTP")
		if e := fs.Parse(args[1:]); e != nil {
			return e
		}
		if fs.NArg() != 0 {
			return fmt.Errorf("unexpected arguments")
		}
		c := agent.Config{Name: *name, Server: *server, BackupServer: *backup, Key: *keyPath, StateFile: *state, Interval: 5 * time.Second, InsecureHTTP: *insecure, ProcRoot: *procRoot, RootFS: *rootFS, WtmpPath: *wtmpPath}
		if e := c.Validate(); e != nil {
			return e
		}
		if *config == *keyPath || *state == *keyPath || *state == *config {
			return fmt.Errorf("key, config and state paths must differ")
		}
		if !*force {
			if _, e := os.Lstat(*config); e == nil {
				return fmt.Errorf("config already exists")
			} else if !os.IsNotExist(e) {
				return e
			}
		}
		key, e := agent.GenerateKey(*keyPath, *force)
		if e != nil {
			return e
		}
		if e = agent.WriteConfig(*config, c, *force); e != nil {
			return e
		}
		pub := key.Public().(ed25519.PublicKey)
		fmt.Println(proto.PublicKeyLine(pub, *name))
		fmt.Println(proto.Fingerprint(pub))
		return nil
	case "fingerprint":
		keyPath := fs.String("key", agent.DefaultKey, "private key path")
		if e := fs.Parse(args[1:]); e != nil {
			return e
		}
		if fs.NArg() != 0 {
			return fmt.Errorf("unexpected arguments")
		}
		key, e := agent.LoadKey(*keyPath)
		if e != nil {
			return e
		}
		fmt.Println(proto.Fingerprint(key.Public().(ed25519.PublicKey)))
		return nil
	case "enroll":
		backup := fs.Bool("backup", false, "submit to backup_server")
		if len(args) < 2 || len(args[1]) != 9 || args[1][4] != '-' {
			return fmt.Errorf("usage: wanglou-agent enroll <CODE> [--config path]")
		}
		path := fs.String("config", agent.DefaultConfig, "local config path")
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return fmt.Errorf("unexpected arguments")
		}
		c, err := agent.LoadConfig(*path)
		if err != nil {
			return err
		}
		key, err := agent.LoadKey(c.Key)
		if err != nil {
			return err
		}
		client, err := agent.NewClient(c, key)
		if err != nil {
			return err
		}
		target := "primary"
		if *backup {
			target = "backup"
		}
		if err = client.EnrollTo(context.Background(), target, args[1]); err != nil {
			return err
		}
		fmt.Println(proto.Fingerprint(key.Public().(ed25519.PublicKey)))
		fmt.Println("公钥已提交，请去面板核对指纹后启用")
		return nil
	case "run":
		path := fs.String("config", agent.DefaultConfig, "local config path")
		if e := fs.Parse(args[1:]); e != nil {
			return e
		}
		if fs.NArg() != 0 {
			return fmt.Errorf("unexpected arguments")
		}
		c, e := agent.LoadConfig(*path)
		if e != nil {
			return e
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return agent.Run(ctx, c)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}
