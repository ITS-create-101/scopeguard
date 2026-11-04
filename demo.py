#!/usr/bin/env python3
"""scopeguard demo — a governed agent that cannot act outside its authorized scope.
Run: python3 demo.py   (used to record the project's demo GIF via demo.tape)"""
from scopeguard import Guard, Denied

print("scope: authorized_targets = ['acme-lab.test', '10.0.0.0/24']\n")
g = Guard(
    scope={"authorized_targets": ["acme-lab.test", "10.0.0.0/24"]},
    tiers={"recon": 2, "exploit": 3},
    deny_always=["lan_scan"],
)
for tool, tgt in [("recon", "10.0.0.5"), ("recon", "8.8.8.8"),
                  ("recon", "192.168.1.9"), ("exploit", "acme-lab.test")]:
    try:
        ok = g.authorize(tool, tgt, approver=lambda *a: True)
        print("  %-8s %-16s -> %s" % (tool, tgt, "RAN (in scope)" if ok else "declined"))
    except Denied as d:
        print("  %-8s %-16s -> DENIED  [%s]" % (tool, tgt, d))
print("\nscope-gated . tiered . audited  —  github.com/ITS-create-101/scopeguard")
