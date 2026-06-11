# Minimal goddns client for MikroTik RouterOS (v7).
#
# 1. Replace the URL below with your own (host + token).
# 2. Upload this file and run:   /import mikrotik-ddns-minimal.rsc
#
# That's it — it creates a script named "goddns" and a scheduler that runs
# it every 3 minutes. Manage with:
#   /system script run goddns          (test once, by hand)
#   /system scheduler print            (see it / change interval)
#
# output=none matters: without it, fetch saves the response to a new file
# on the router's storage on EVERY run.

/system script add name=goddns source="/tool fetch url=\"https://sdns.myip.gr:8245/update/PASTE-TOKEN-HERE\" output=none"
/system scheduler add name=goddns interval=3m on-event=goddns comment="goddns DDNS update"
