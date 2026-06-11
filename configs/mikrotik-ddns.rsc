# RouterOS scheduler script for goddns.
# System > Scripts (name: goddns-update), then a Scheduler entry every 1-3 min.
#
# The server reads the source IP from the connection, so the router does NOT
# need to know its own WAN IP. If the router is itself behind CGNAT and you
# want the *router's* idea of the address, append ?ip=<addr>.

:local token "PASTE-TOKEN-HERE"
:local host  "sdns.myip.gr"
:local port  "8245"
:local url   ("https://" . $host . ":" . $port . "/update/" . $token)

:do {
    :local res [/tool fetch url=$url mode=https check-certificate=yes \
        as-value output=user]
    :log info ("goddns: " . ($res->"data"))
} on-error={
    :log warning "goddns: update failed"
}
