package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/user"
	"strings"

	"github.com/chrismfz/goddns/internal/config"
	"github.com/chrismfz/goddns/internal/service"
)

// cmdUser manages the admin UI's database logins. It runs on the server's
// console, so it acts with the admin role (as the operator who can already
// edit goddns.conf); every change goes through the service layer like the UI,
// with the same validation, last-admin guard and audit line.
//
//	goddns user list
//	goddns user add <name> [-role user|admin]   (password prompted, or piped)
//	goddns user passwd <name>
//	goddns user role <name> admin|user
//	goddns user disable|enable <name>
//	goddns user grant|revoke <name> <zone>
//	goddns user del <name>
func cmdUser(args []string) {
	if len(args) < 1 {
		userUsage()
		os.Exit(2)
	}
	sub := args[0]
	fs := flag.NewFlagSet("user", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConf, "config file")
	role := fs.String("role", service.RoleUser, "role for add: user or admin")
	fs.Parse(flagsFirst(args[1:], "-role", "--role", "-config", "--config"))
	rest := fs.Args()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fatal("config: %v", err)
	}
	st := openStore(cfg)
	defer healDBOwnership(cfg.DBPath)
	defer st.Close()
	svc := service.New(func() *config.Config { return cfg }, st)
	logf, closeLog := cliAuditLog(cfg)
	defer closeLog()
	svc.Logf = logf
	a := cliActor()

	need := func(n int) {
		if len(rest) != n {
			userUsage()
			os.Exit(2)
		}
	}
	switch sub {
	case "list":
		need(0)
		users, err := svc.Users(a)
		if err != nil {
			fatal("%v", err)
		}
		if len(users) == 0 {
			fmt.Println("no logins (add one: goddns user add <name> -role admin)")
			return
		}
		fmt.Printf("%-24s %-6s %-9s %-12s %-10s %s\n", "USER", "ROLE", "STATE", "SOURCE", "CREATED", "ZONES")
		for _, u := range users {
			state, src := "enabled", "db"
			if u.Disabled {
				state = "disabled"
			}
			if u.Config {
				src = "goddns.conf"
			} else if u.Shadowed {
				src = "db(shadowed)"
			}
			zones := strings.Join(u.Zones, ",")
			if zones == "" {
				zones = "-"
			}
			fmt.Printf("%-24s %-6s %-9s %-12s %-10s %s\n", u.Name, u.Role, state, src, u.Created, zones)
		}
	case "add":
		need(1)
		pass := readNewPassword()
		check(svc.UserAdd(a, rest[0], string(pass), *role))
		fmt.Printf("added %s (%s)\n", rest[0], *role)
	case "passwd":
		need(1)
		pass := readNewPassword()
		check(svc.UserSetPassword(a, rest[0], string(pass)))
		fmt.Printf("password set for %s — their sessions have ended\n", rest[0])
	case "role":
		need(2)
		check(svc.UserSetRole(a, rest[0], rest[1]))
		fmt.Printf("%s is now %s\n", rest[0], rest[1])
	case "disable", "enable":
		need(1)
		check(svc.UserSetDisabled(a, rest[0], sub == "disable"))
		fmt.Printf("%sd %s\n", sub, rest[0])
	case "grant", "revoke":
		need(2)
		if sub == "grant" {
			check(svc.Grant(a, rest[0], rest[1]))
			fmt.Printf("%s may now manage %s\n", rest[0], service.NormZone(rest[1]))
		} else {
			check(svc.Revoke(a, rest[0], rest[1]))
			fmt.Printf("revoked %s from %s\n", service.NormZone(rest[1]), rest[0])
		}
	case "del":
		need(1)
		check(svc.UserDel(a, rest[0]))
		fmt.Printf("deleted %s\n", rest[0])
	default:
		userUsage()
		os.Exit(2)
	}
}

// flagsFirst moves flags (and the value of each named flag that takes one)
// ahead of the positional arguments, so "user add alice -role admin" works:
// Go's flag package stops at the first non-flag and would otherwise ignore
// -role silently and create a plain user.
func flagsFirst(args []string, withValue ...string) []string {
	takes := map[string]bool{}
	for _, f := range withValue {
		takes[f] = true
	}
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			pos = append(pos, args[i+1:]...)
			i = len(args)
		case len(a) > 1 && a[0] == '-':
			flags = append(flags, a)
			if takes[a] && i+1 < len(args) {
				flags = append(flags, args[i+1])
				i++
			}
		default:
			pos = append(pos, a)
		}
	}
	// "--" ends flag parsing, so a positional that starts with '-' (after a
	// "--" the caller typed) stays a positional. flag.Parse consumes it.
	return append(append(flags, "--"), pos...)
}

// cliAuditLog returns where the CLI's admin-audit lines go: stderr, as
// before, and the daemon's log_file too when one is configured, so the
// server's log shows who changed logins from the console. The file is opened
// for append only and never created here (a root CLI run must not leave a
// root-owned log behind for the unprivileged daemon); O_APPEND keeps a line
// whole next to the daemon's own writes.
func cliAuditLog(cfg *config.Config) (func(string, ...any), func()) {
	toErr := log.New(os.Stderr, "", log.LstdFlags)
	if cfg.LogFile == "" {
		return toErr.Printf, func() {}
	}
	f, err := os.OpenFile(cfg.LogFile, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		toErr.Printf("warning: audit not written to %s: %v", cfg.LogFile, err)
		return toErr.Printf, func() {}
	}
	toFile := log.New(f, "", log.LstdFlags)
	return func(format string, a ...any) {
		toErr.Printf(format, a...)
		toFile.Printf(format, a...)
	}, func() { f.Close() }
}

// cliActor names the console operator in audit lines ("cli:<unix user>").
func cliActor() service.Actor {
	name := "cli"
	if u, err := user.Current(); err == nil {
		name = "cli:" + u.Username
	}
	return service.Actor{User: name, Peer: "local", Role: service.RoleAdmin}
}

func check(err error) {
	if err != nil {
		fatal("%v", err)
	}
}

func userUsage() {
	fmt.Fprint(os.Stderr, `Usage:
  goddns user list
  goddns user add <name> [-role user|admin]   # password prompted (or one line on stdin)
  goddns user passwd <name>
  goddns user role <name> admin|user
  goddns user disable|enable <name>
  goddns user grant <name> <zone>             # the zone must be one named.conf serves
  goddns user revoke <name> <zone>
  goddns user del <name>
  (all take [-config path])

An admin can do everything in the admin UI. A user manages only the zones
granted to it (view, history, record edits, restore, its DDNS tokens) and
its own password. A grant is one zone, not its subzones.
goddns.conf [admin] users are always admins and are edited in that file.
`)
}
