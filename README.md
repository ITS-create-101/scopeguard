# scopeguard

**A signed-scope + tiered-permission safety gate for autonomous agents.** Give an LLM agent real
tools — recon, code execution, file ops — *without* letting it act outside an authorized scope.

![status](https://img.shields.io/badge/status-active-brightgreen)
![license](https://img.shields.io/badge/license-MIT-blue)
![deps](https://img.shields.io/badge/dependencies-none-success)
![python](https://img.shields.io/badge/python-3.8%2B-blue)

Autonomous security agents are powerful and dangerous for the same reason: they run tools. `scopeguard`
is the gate every tool call passes through **before** it executes — so an agent can be useful on an
authorized target and physically unable to touch anything else.

## What it enforces
Every action is checked, in this order (a human "yes" can never reach a denied action):

1. **Signed scope required** — a scope must exist and name authorized targets.
2. **Target in scope** — the explicit target *and every real host/IP/URL in the arguments* must be authorized.
3. **No stray hosts** — private/LAN and public hosts not in scope are refused (`lan_scan`, `out_of_scope_target`).
4. **Deny-always** — a hard-block list that approval cannot override.
5. **Tiered permissions** — tier 1 runs automatically, tier 2 confirms, tier 3 needs explicit approval.
6. **Audit log** — every allow/deny is recorded.

Flags (`-sV`) and filenames (`out.txt`) are never mistaken for hosts, so they don't cause false denials.
**No dependencies. Python stdlib only. MIT.**

## Install
```bash
# vendor the single file (no dependencies):
curl -O https://raw.githubusercontent.com/ITS-create-101/scopeguard/main/scopeguard.py
```

## Use
```python
from scopeguard import Guard, Denied

guard = Guard(
    scope={"authorized_targets": ["example.com", "10.0.0.0/24"], "allow_loopback": True},
    tiers={"read": 1, "scan": 2, "exploit": 3},        # 1=auto, 2=confirm, 3=manual
    deny_always=["lan_scan", "credential_exfiltration"],
    audit_log="audit.log",
)

def approver(tier, tool, target, args):
    return input(f"allow tier-{tier} {tool} on {target}? [y/N] ").strip().lower() == "y"

guard.authorize("scan", target="10.0.0.5", args=["-sV"], approver=approver)  # in scope -> confirm
guard.authorize("scan", target="8.8.8.8")                                    # raises Denied
guard.authorize("read", target="example.com")                               # tier 1 -> auto
```

Run the demo: `python3 example.py` · Run the tests: `python3 test_scopeguard.py` (9/9).

## Why this exists
It was extracted from a larger self-hosted security-AI project and generalized, because the pattern —
*scope-gate first, tier second, audit always* — is what makes an autonomous agent safe to point at a
real engagement. It is deliberately tiny and dependency-free so you can drop it into any agent loop.

## Scope file
A scope is a dict or a JSON file:
```json
{ "authorized_targets": ["example.com", "*.lab.internal", "10.0.0.0/24"], "allow_loopback": false }
```
Hostnames match themselves and their subdomains; CIDRs match contained IPs. Replace it with your
signed engagement scope before any real use.

> Use only against systems you are explicitly authorized, in writing, to test.
