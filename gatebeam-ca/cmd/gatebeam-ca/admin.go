package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"strings"
	"time"

	"gatebeam-ca/internal/modules/pki"
	"gatebeam-ca/internal/modules/pki/application"
	"gatebeam-ca/internal/modules/pki/domain"
	"gatebeam-ca/internal/platform/postgres"
	"gatebeam-ca/internal/platform/transaction"

	"github.com/jackc/pgx/v5"
)

type adminAction struct{ runner *postgres.Runner }

func (a adminAction) Within(ctx context.Context, actor application.ActorRef, fn func(transaction.Scope) error) error {
	return a.runner.Within(ctx, func(scope transaction.Scope) error {
		err := postgres.Use(scope, func(ctx context.Context, tx pgx.Tx) error {
			var allowed bool
			err := tx.QueryRow(ctx, `
				SELECT session_user::text = $1 AND current_user = session_user
				   AND pg_has_role(session_user, 'gatebeam_ca_admin', 'USAGE')
				   AND NOT pg_has_role(session_user, 'gatebeam_ca_runtime', 'MEMBER')
				   AND NOT pg_has_role(session_user, 'gatebeam_ca_runtime', 'SET')
				   AND NOT (rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls)
				   AND NOT pg_has_role(session_user, c.relowner, 'USAGE')
				   AND NOT pg_has_role(session_user, n.nspowner, 'USAGE')
				FROM pg_roles r
				JOIN pg_class c ON c.oid = 'pki_principals'::regclass
				JOIN pg_namespace n ON n.oid = c.relnamespace
				WHERE r.rolname = session_user`, actor.UserID).Scan(&allowed)
			if err != nil || !allowed {
				return errors.New("a separate restricted CA administrator database login is required")
			}
			return nil
		})
		if err != nil {
			return err
		}
		return fn(scope)
	})
}

func administer(ctx context.Context, flags *flag.FlagSet, args []string, output io.Writer) error {
	path := flags.String("config", "", "administrator JSON configuration")
	var directory, names, expires, grantID, destination, principal, issuer, serial string
	var reason int
	switch flags.Name() {
	case "authorize":
		flags.StringVar(&directory, "directory", "", "ACME directory (server or client)")
		flags.StringVar(&names, "names", "", "comma-separated exact DNS names")
		flags.StringVar(&expires, "expires", "", "grant expiration in RFC 3339 format")
	case "issue-eab":
		flags.StringVar(&grantID, "grant", "", "grant ID")
		flags.StringVar(&destination, "output", "", "new private file for EAB credentials")
	case "disable":
		flags.StringVar(&principal, "principal", "", "principal ID")
	case "revoke":
		flags.StringVar(&issuer, "issuer", "", "issuer ID")
		flags.StringVar(&serial, "serial", "", "40-digit lowercase hexadecimal certificate serial")
		flags.IntVar(&reason, "reason", 0, "standard CRL reason code")
	}
	if err := parse(flags, args); err != nil {
		return err
	}
	c, err := readConfig(*path)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	db, err := postgres.Open(ctx, c.DatabaseFile)
	if err != nil {
		return err
	}
	defer db.Close()
	var actor application.ActorRef
	if err := db.QueryRow(ctx, "SELECT session_user").Scan(&actor.UserID); err != nil {
		return errors.New("could not identify the CA administrator database login")
	}
	security := adminAction{runner: postgres.NewRunner(db)}
	switch flags.Name() {
	case "inspect":
		if _, err := originHost(c.Origin, "https"); err != nil {
			return err
		}
		data, err := pki.NewQueries(db, security, c.Origin).Read(ctx, actor)
		if err != nil {
			return err
		}
		return json.NewEncoder(output).Encode(data)
	case "revoke":
		return pki.NewRevocations(db, security).Revoke(ctx, actor, issuer, serial, reason)
	}
	grants, err := pki.NewGrants(db, security, c.Recipient, pki.GrantConfig{
		ServerNames: c.ServerNames, ClientNames: c.ClientNames, Recipients: c.Recipients,
	})
	if err != nil {
		return err
	}
	switch flags.Name() {
	case "authorize":
		var usage domain.Usage
		switch directory {
		case "server":
			usage = domain.ServerAuth
		case "client":
			usage = domain.ClientAuth
		default:
			return errors.New("directory must be server or client")
		}
		expiration, err := time.Parse(time.RFC3339, expires)
		if err != nil {
			return errors.New("grant expiration must be in RFC 3339 format")
		}
		grant, err := grants.Authorize(ctx, actor, application.GrantSpec{
			Directory: directory, Purpose: usage, Names: strings.Split(names, ","), Expires: expiration,
		})
		if err != nil {
			return err
		}
		return json.NewEncoder(output).Encode(grant)
	case "disable":
		return grants.DisablePrincipal(ctx, actor, principal)
	case "issue-eab":
		file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		credential, err := grants.IssueEAB(ctx, actor, grantID)
		if err == nil {
			err = json.NewEncoder(file).Encode(credential)
		}
		if err == nil {
			err = file.Sync()
		}
		if err = errors.Join(err, file.Close()); err != nil {
			return errors.Join(err, os.Remove(destination))
		}
		return nil
	}
	return errors.New("unknown administration command")
}
