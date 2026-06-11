# scripts/

Helper scripts shipped to `/usr/share/goddns/scripts/` by the .deb/.rpm
packages (same layout as cfm).

- `certbot-deploy-goddns.sh` — certbot deploy hook that mirrors a renewed
  cert pair into `/etc/goddns/certs` (root:goddns 0640) so the unprivileged
  goddns service can read it. See the header for installation.
