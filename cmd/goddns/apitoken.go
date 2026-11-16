package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/chrismfz/goddns/internal/config"
	"github.com/chrismfz/goddns/internal/service"
)

// cmdAPIToken manages machine-API tokens from the console (as an admin,
// audited as cli:<unix user>, through the same service checks as the UI).
//
//	goddns apitoken list [-user name]
//	goddns apitoken add <name> -user <login> -scopes zones:read,ddns:write [-allow 10.0.0.0/8] [-expires 90]
//	goddns apitoken revoke <id>
func cmdAPIToken(args []string) {
	if len(args) < 1 {
		apiTokenUsage()
		os.Exit(2)
	}
	sub := args[0]
	fs := flag.NewFlagSet("apitoken", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConf, "config file")
	user := fs.String("user", "", "the login the token acts as")
	scopes := fs.String("scopes", "", "comma-separated scopes: "+strings.Join(service.AllScopes(), ","))
	allow := fs.String("allow", "", "comma-separated source CIDRs (empty = anywhere)")
	expires := fs.Int("expires", 0, "days until it expires (0 = never)")
	fs.Parse(flagsFirst(args[1:], "-config", "--config", "-user", "--user", "-scopes", "--scopes", "-allow", "--allow", "-expires", "--expires"))
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

	switch sub {
	case "list":
		ts, err := svc.APITokens(a, *user)
		check(err)
		if len(ts) == 0 {
			fmt.Println("no API tokens")
			return
		}
		fmt.Printf("%-5s %-16s %-20s %-10s %-16s %-11s %s\n", "ID", "USER", "NAME", "EXPIRES", "LAST USED", "ALLOW", "SCOPES")
		for _, t := range ts {
			exp := t.Expires
			if t.Expired {
				exp += "!"
			}
			nets := strings.Join(t.AllowNets, ",")
			if nets == "" {
				nets = "anywhere"
			}
			fmt.Printf("%-5d %-16s %-20s %-10s %-16s %-11s %s\n", t.ID, t.User, t.Name, exp, t.LastUsed, nets, strings.Join(t.Scopes, ","))
		}
	case "add":
		if len(rest) != 1 || *user == "" || *scopes == "" {
			apiTokenUsage()
			os.Exit(2)
		}
		t, tok, err := svc.APITokenCreate(a, *user, rest[0], strings.Split(*scopes, ","), splitComma(*allow), *expires)
		check(err)
		fmt.Printf("API token #%d %q for %s (scopes %s, expires %s)\n", t.ID, t.Name, t.User, strings.Join(t.Scopes, ","), t.Expires)
		fmt.Printf("Token (store it now, shown once):\n  %s\n\n", tok)
		fmt.Printf("Use it as a header, never in a URL:\n  curl -H \"Authorization: Bearer %s\" https://%s%s/api/v1/me\n", tok, serverHost(cfg), listenPort(cfg))
	case "revoke":
		if len(rest) != 1 {
			apiTokenUsage()
			os.Exit(2)
		}
		id, err := strconv.ParseInt(rest[0], 10, 64)
		if err != nil || id <= 0 {
			fatal("revoke takes a token id (see goddns apitoken list)")
		}
		check(svc.APITokenRevoke(a, id))
		fmt.Printf("revoked API token #%d\n", id)
	default:
		apiTokenUsage()
		os.Exit(2)
	}
}

func splitComma(s string) []string {
	var out []string
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

func apiTokenUsage() {
	fmt.Fprintf(os.Stderr, `Usage:
  goddns apitoken list [-user name]
  goddns apitoken add <name> -user <login> -scopes <s1,s2> [-allow cidr,...] [-expires days]
  goddns apitoken revoke <id>
  (all take [-config path])

Scopes: %s
A token acts as its login (never with more than its role and zone grants),
narrowed by its scopes. Send it as "Authorization: Bearer <token>".
`, strings.Join(service.AllScopes(), ", "))
}
