package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/chrismfz/goddns/internal/config"
	"github.com/chrismfz/goddns/internal/service"
)

// cmdZoneManage creates or deletes a goddns-managed zone from the console
// (as root, directly; same service checks and audit as the UI):
//
//	goddns zone create <zone> [-ns ns1.example.com,ns2.example.com] [-assign user] [-y]
//	goddns zone delete <zone> [-y]
func cmdZoneManage(sub string, args []string) {
	fs := flag.NewFlagSet("zone "+sub, flag.ExitOnError)
	cfgPath := fs.String("config", defaultConf, "config file")
	ns := fs.String("ns", "", "comma-separated apex nameservers (default: zone_ns)")
	assign := fs.String("assign", "", "grant the new zone to this user-role login")
	yes := fs.Bool("y", false, "apply without the confirmation prompt")
	fs.Parse(flagsFirst(args, "-config", "--config", "-ns", "--ns", "-assign", "--assign"))
	if fs.NArg() != 1 {
		fmt.Fprintf(os.Stderr, "usage: goddns zone %s <zone>%s [-y] [-config path]\n", sub,
			map[string]string{"create": " [-ns ns1,ns2] [-assign user]", "delete": ""}[sub])
		os.Exit(2)
	}
	zone := fs.Arg(0)
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fatal("config: %v", err)
	}
	cfg.ZonedSocket = "" // the console is root: act directly, not through the helper
	st := openStore(cfg)
	defer healDBOwnership(cfg.DBPath)
	defer st.Close()
	svc := service.New(func() *config.Config { return cfg }, st)
	logf, closeLog := cliAuditLog(cfg)
	defer closeLog()
	svc.Logf = logf
	a := cliActor()

	run := func(apply bool) *service.ZoneChange {
		var p *service.ZoneChange
		var err error
		if sub == "create" {
			p, err = svc.ZoneCreate(a, zone, splitComma(*ns), *assign, apply)
		} else {
			p, err = svc.ZoneDelete(a, zone, apply)
		}
		check(err)
		return p
	}
	p := run(false)
	if sub == "create" {
		fmt.Printf("zone file %s:\n%s\ninclude stanza (%s):\n  %s\n", p.File, p.Content, cfg.ManagedInclude, p.Stanza)
		if p.Parent != "" {
			fmt.Printf("\nNOTE: inside %s (served here). These records of %s stop being answered:\n", p.Parent, p.Parent)
			for _, r := range p.Shadowed {
				fmt.Printf("  %s\n", r)
			}
			if !p.Delegated {
				fmt.Printf("and %s has no NS for %s yet — add the delegation for resolvers outside.\n", p.Parent, p.Zone)
			}
		}
	} else {
		fmt.Printf("remove from %s:\n  %s\nthe file %s is moved aside (.deleted-<time>); grants on the zone are removed.\n", cfg.ManagedInclude, p.Stanza, p.File)
	}
	if !*yes && !confirmPrompt(sub+" zone "+p.Zone+"?") {
		fmt.Println("aborted")
		return
	}
	p = run(true)
	if sub == "create" {
		fmt.Printf("created %s (%s)", p.Zone, p.File)
		if p.AssignedTo != "" {
			fmt.Printf(", assigned to %s", p.AssignedTo)
		}
		fmt.Println()
	} else {
		fmt.Printf("deleted %s (file moved to %s)\n", p.Zone, p.MovedTo)
	}
}
