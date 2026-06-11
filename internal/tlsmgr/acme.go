package tlsmgr

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/rfc2136"
	"go.uber.org/zap"
)

// ACMEOptions configures the self-issued certificate path. The DNS-01
// challenge TXT record is written through the local BIND with RFC2136/TSIG,
// so issuance never needs port 80/443 — goddns stays on its own port.
type ACMEOptions struct {
	Domain       string   // certificate hostname
	ExtraDomains []string // additional hostnames (proxy mode), each gets its own cert
	Email        string
	CA           string // ACME directory; empty = Let's Encrypt production
	Storage      string // directory for account + certs
	DNSServer    string // addr:port of the BIND that serves the zone
	TSIGName     string
	TSIGAlgo     string // hmac-sha256 etc. (named.conf spelling)
	TSIGSecret   string // base64
}

// ACME wraps a certmagic Config; renewals happen in the background and the
// renewed cert is served from memory — no restart, no reload needed.
type ACME struct {
	magic *certmagic.Config
}

func NewACME(ctx context.Context, o ACMEOptions) (*ACME, error) {
	if o.TSIGSecret == "" {
		return nil, fmt.Errorf("acme: TSIG secret not set (acme_tsig_secret / GODDNS_ACME_TSIG_SECRET)")
	}
	logger, err := zap.NewProduction()
	if err != nil {
		logger = zap.NewNop()
	}

	var magic *certmagic.Config
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) {
			return magic, nil
		},
		Logger: logger,
	})
	magic = certmagic.New(cache, certmagic.Config{
		Storage: &certmagic.FileStorage{Path: o.Storage},
		Logger:  logger,
	})

	ca := o.CA
	if ca == "" {
		ca = certmagic.LetsEncryptProductionCA
	}
	issuer := certmagic.NewACMEIssuer(magic, certmagic.ACMEIssuer{
		CA:                      ca,
		Email:                   o.Email,
		Agreed:                  true,
		DisableHTTPChallenge:    true,
		DisableTLSALPNChallenge: true,
		DNS01Solver: &certmagic.DNS01Solver{
			DNSManager: certmagic.DNSManager{
				DNSProvider: &rfc2136.Provider{
					Server:  o.DNSServer,
					KeyName: o.TSIGName,
					KeyAlg:  o.TSIGAlgo,
					Key:     o.TSIGSecret,
				},
				// Records land directly on the authoritative server;
				// query it instead of the resolver chain.
				Resolvers:          []string{o.DNSServer},
				PropagationTimeout: 2 * time.Minute,
				Logger:             logger,
			},
		},
		Logger: logger,
	})
	magic.Issuers = []certmagic.Issuer{issuer}

	// Loads from storage or obtains from the CA, then keeps it renewed.
	domains := append([]string{o.Domain}, o.ExtraDomains...)
	if err := magic.ManageSync(ctx, domains); err != nil {
		return nil, fmt.Errorf("acme: obtaining certificate for %v: %w", domains, err)
	}
	return &ACME{magic: magic}, nil
}

// Manage adds domains to the managed set (idempotent; cached certs are
// no-ops). Used when a config reload introduces new proxied hostnames.
func (a *ACME) Manage(ctx context.Context, domains []string) error {
	return a.magic.ManageSync(ctx, domains)
}

// GetCertificate is plugged into tls.Config.GetCertificate.
func (a *ACME) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return a.magic.GetCertificate(hello)
}
