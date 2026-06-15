package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/chrismfz/goddns/internal/config"
	"github.com/chrismfz/goddns/internal/vhostmut"
)

// cmdVhost manages goddns-owned reverse-proxy vhosts as proxy.d/ drop-in
// fragments. It never edits the hand-written goddns.conf (the invariant): a
// vhost defined there is shown read-only and refused for set/del.
//
//	goddns vhost list
//	goddns vhost show <host>
//	goddns vhost set  <host> -upstream URL [flags]
//	goddns vhost del  <host>
func cmdVhost(args []string) {
	if len(args) < 1 {
		vhostUsage()
		os.Exit(2)
	}
	sub := args[0]
	// For host-taking subcommands the host comes right after the subcommand,
	// then the flags — so `vhost set <host> -upstream ...` parses correctly
	// (flag.Parse stops at the first positional).
	var host string
	flagArgs := args[1:]
	switch sub {
	case "set", "show", "del", "rm", "remove":
		if len(args) < 2 || strings.HasPrefix(args[1], "-") {
			fatal("usage: goddns vhost %s <host> ...", sub)
		}
		host, flagArgs = args[1], args[2:]
	}

	fs := flag.NewFlagSet("vhost", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConf, "config file")
	yes := fs.Bool("y", false, "apply without the confirmation prompt")
	upstream := fs.String("upstream", "", "upstream URL, http(s)://host[:port] (set)")
	allow := fs.String("allow", "", "comma-separated client CIDRs (set)")
	auth := fs.String("auth", "", "comma-separated user:bcrypt-hash basic-auth entries (set)")
	rate := fs.Int("rate", 0, "max requests/sec per client IP, 0 = unlimited (set)")
	verify := fs.Bool("verify", false, "verify the upstream's TLS cert (set)")
	preserve := fs.Bool("preserve-host", false, "keep the inbound Host header (set)")
	fs.Parse(flagArgs)

	ed := &vhostmut.Editor{ConfPath: *cfgPath}

	switch sub {
	case "list":
		vhostList(ed)
	case "show":
		vhostShow(ed, host)
	case "set":
		if *upstream == "" {
			fatal("set needs -upstream")
		}
		rule := config.ProxyRule{
			Upstream:       *upstream,
			UpstreamVerify: *verify,
			PreserveHost:   *preserve,
			Allow:          splitList(*allow),
			BasicAuth:      splitList(*auth),
			RateLimit:      *rate,
		}
		vhostSet(ed, host, rule, *yes)
	case "del", "rm", "remove":
		vhostDel(ed, host, *yes)
	default:
		vhostUsage()
		os.Exit(2)
	}
}

func vhostList(ed *vhostmut.Editor) {
	entries, err := ed.List()
	if err != nil {
		fatal("%v", err)
	}
	if len(entries) == 0 {
		fmt.Println("(no proxy vhosts configured)")
		return
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "HOST\tUPSTREAM\tMANAGED\tSOURCE")
	for _, e := range entries {
		managed := "no"
		src := "goddns.conf"
		if e.Managed {
			managed = "yes"
			src = "proxy.d/" + e.Host + ".conf"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", e.Host, e.Rule.Upstream, managed, src)
	}
	tw.Flush()
}

func vhostShow(ed *vhostmut.Editor, host string) {
	entries, err := ed.List()
	if err != nil {
		fatal("%v", err)
	}
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	for _, e := range entries {
		if e.Host != host {
			continue
		}
		fmt.Printf("host:           %s\n", e.Host)
		fmt.Printf("upstream:       %s\n", e.Rule.Upstream)
		fmt.Printf("upstream_verify: %t\n", e.Rule.UpstreamVerify)
		fmt.Printf("preserve_host:  %t\n", e.Rule.PreserveHost)
		fmt.Printf("allow:          %s\n", strings.Join(e.Rule.Allow, ", "))
		fmt.Printf("rate_limit:     %d\n", e.Rule.RateLimit)
		fmt.Printf("basic_auth:     %d entr%s\n", len(e.Rule.BasicAuth), plural(len(e.Rule.BasicAuth)))
		fmt.Printf("managed:        %t (%s)\n", e.Managed, e.Source)
		return
	}
	fatal("no vhost %q", host)
}

func vhostSet(ed *vhostmut.Editor, host string, rule config.ProxyRule, yes bool) {
	res, err := ed.PreviewSet(host, rule)
	if err != nil {
		fatal("%v", err)
	}
	fmt.Printf("%s vhost %s -> %s\n\n%s\n", res.Action, res.Host, res.File, res.Fragment)
	if !yes && !confirmPrompt(res.Action+" "+res.Host+"?") {
		fmt.Println("aborted")
		return
	}
	if _, err := ed.Set(host, rule); err != nil {
		fatal("write: %v", err)
	}
	fmt.Printf("wrote %s — applies within reload_interval, or now with: systemctl reload goddns\n", res.File)
}

func vhostDel(ed *vhostmut.Editor, host string, yes bool) {
	res, err := ed.PreviewRemove(host)
	if err != nil {
		fatal("%v", err)
	}
	fmt.Printf("remove vhost %s (%s)\n", res.Host, res.File)
	if !yes && !confirmPrompt("remove "+res.Host+"?") {
		fmt.Println("aborted")
		return
	}
	if _, err := ed.Remove(host); err != nil {
		fatal("remove: %v", err)
	}
	fmt.Printf("removed %s — applies within reload_interval, or now with: systemctl reload goddns\n", res.File)
}

func splitList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

func vhostUsage() {
	fmt.Fprintf(os.Stderr, `goddns vhost — manage reverse-proxy vhosts as proxy.d/ fragments

  goddns vhost list                              list vhosts (and whether goddns manages each)
  goddns vhost show <host>                        show one vhost's settings
  goddns vhost set  <host> -upstream URL [flags]  create/replace a managed vhost
  goddns vhost del  <host>                         remove a managed vhost

set flags (set replaces the whole vhost):
  -upstream URL     http(s)://host[:port]                       (required)
  -allow  a,b       client CIDRs (e.g. 10.0.0.0/8); empty = open
  -auth   u:h,..    user:bcrypt-hash entries (make with goddns passwd)
  -rate   N         requests/sec per client IP; 0 = unlimited
  -verify           verify the upstream's TLS cert (default off: BMCs self-sign)
  -preserve-host    keep the inbound Host header
  -y                skip the confirmation prompt

goddns manages one vhost per file (proxy.d/<host>.conf); a vhost you put in
goddns.conf by hand is shown read-only and never overwritten.
`)
}
