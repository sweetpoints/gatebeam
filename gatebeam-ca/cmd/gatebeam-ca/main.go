package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"gatebeam-ca/internal/modules/pki"
	"gatebeam-ca/internal/modules/pki/application"
	"gatebeam-ca/internal/platform/postgres"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, output io.Writer) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprintln(output, "usage: gatebeam-ca <serve|migrate|migrate-roles|bootstrap|import|authorize|issue-eab|inspect|disable|revoke> [flags]")
		return nil
	}
	command := args[0]
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	switch command {
	case "bootstrap":
		var c application.BootstrapCommand
		flags.StringVar(&c.RootDirectory, "offline", "", "new directory for offline root")
		flags.StringVar(&c.OnlineDirectory, "online", "", "new directory for online CA material")
		flags.StringVar(&c.RootName, "root-name", "", "root subject common name")
		flags.StringVar(&c.IntermediateName, "issuer-name", "", "issuer subject common name")
		flags.StringVar(&c.StatusOrigin, "status-origin", "", "canonical HTTP status origin")
		if err := parse(flags, args[1:]); err != nil {
			return err
		}
		if _, err := originHost(c.StatusOrigin, "http"); err != nil {
			return err
		}
		return pki.BootstrapOffline(ctx, c)
	case "import":
		var c application.ImportCommand
		flags.StringVar(&c.SourceDirectory, "source", "", "offline source directory")
		flags.StringVar(&c.OnlineDirectory, "online", "", "new directory for online CA material")
		if err := parse(flags, args[1:]); err != nil {
			return err
		}
		return pki.ImportOffline(ctx, c)
	case "migrate", "migrate-roles":
		file := flags.String("database-file", "", "file containing owner PostgreSQL DSN")
		if err := parse(flags, args[1:]); err != nil {
			return err
		}
		db, err := postgres.Open(ctx, *file)
		if err != nil {
			return err
		}
		defer db.Close()
		if command == "migrate" {
			return postgres.Migrate(ctx, db)
		}
		return postgres.MigrateRoles(ctx, db)
	case "serve":
		path := flags.String("config", "", "server JSON configuration")
		if err := parse(flags, args[1:]); err != nil {
			return err
		}
		c, err := readConfig(*path)
		if err != nil {
			return err
		}
		return serve(ctx, c)
	case "authorize", "issue-eab", "inspect", "disable", "revoke":
		return administer(ctx, flags, args[1:], output)
	default:
		return fmt.Errorf("unknown command %q", command)
	}
}

func parse(flags *flag.FlagSet, args []string) error {
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	return nil
}
