#!/usr/bin/env python3
"""scopeguard in 20 lines: give an agent tools, keep it in scope."""
from scopeguard import Guard, Denied

guard = Guard(
    scope={"authorized_targets": ["example.com", "10.0.0.0/24"], "allow_loopback": True},
    tiers={"read": 1, "scan": 2, "exploit": 3},      # 1=auto, 2=confirm, 3=manual
    deny_always=["lan_scan", "credential_exfiltration"],
)

def approver(tier, tool, target, args):
    return input(f"  allow tier-{tier} {tool} on {target}? [y/N] ").strip().lower() == "y"

for tool, target, args in [
    ("scan", "10.0.0.5", ["-sV"]),      # in scope  -> needs confirm
    ("scan", "8.8.8.8", []),            # OUT of scope -> hard denied
    ("scan", "192.168.1.9", []),        # LAN not in scope -> lan_scan denied
    ("read", "example.com", []),        # in scope, tier 1 -> auto allow
]:
    try:
        ok = guard.authorize(tool, target, args, approver=approver)
        print(f"{tool} {target}: {'RAN' if ok else 'declined'}")
    except Denied as d:
        print(f"{tool} {target}: DENIED ({d})")
