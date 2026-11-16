package main

import (
	"flag"
	"fmt"
	"os"
	"os/user"

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
		fmt.Printf("%-24s %-6s %-9s %-12s %s\n", "USER", "ROLE", "STATE", "SOURCE", "CREATED")
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
			fmt.Printf("%-24s %-6s %-9s %-12s %s\n", u.Name, u.Role, state, src, u.Created)
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
  goddns user del <name>
  (all take [-config path])

An admin can do everything in the admin UI; a user can sign in and change
their own password (zones are granted to users in a later release).
goddns.conf [admin] users are always admins and are edited in that file.
`)
}
