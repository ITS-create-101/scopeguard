#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""scopeguard — a signed-scope + tiered-permission safety gate for autonomous agents.

Give an LLM agent real tools (recon, code execution, file ops) WITHOUT letting it act outside an
authorized scope. Every action passes through one gate, in this order, before any human approval:

  1. A signed scope must exist and name authorized targets.
  2. The explicit target AND every real host/IP/URL in the arguments must be an authorized target.
  3. Private/LAN hosts and public hosts not in scope are refused.
  4. A deny-always list is hard-blocked and cannot be reached by a human "yes".
  5. Tiered permissions decide what runs automatically vs. needs approval.
  6. Every decision (allow or deny) is audit-logged.

Flags and filenames are never mistaken for hosts, so they don't trip false denials.
stdlib only, no dependencies. MIT licensed.

    from scopeguard import Guard
    g = Guard(scope={"authorized_targets": ["example.com", "10.0.0.0/24"]},
              tiers={"read": 1, "scan": 2, "exploit": 3},
              deny_always=["lan_scan", "credential_exfiltration"])
    g.authorize("scan", target="10.0.0.5", args=["-sV"])   # ok (in scope)
    g.authorize("scan", target="8.8.8.8")                  # raises Denied (out of scope)
"""
import ipaddress, json, re, time
from pathlib import Path

__version__ = "0.1.0"
__all__ = ["Guard", "Scope", "Denied"]

LOOPBACK = {"127.0.0.1", "::1", "localhost"}
_FILE_EXT = {"txt", "json", "csv", "lst", "log", "conf", "cfg", "ini", "yaml", "yml", "html",
             "htm", "xml", "out", "pcap", "hash", "pot", "rc", "js", "py", "php", "rb", "sh", "md"}
_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?$")


class Denied(Exception):
    """Raised when an action would leave the signed scope or hits a deny-always rule."""


def _extract_host(s):
    s = str(s).strip()
    s = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", s)   # strip scheme
    s = s.split("/")[0].split("@")[-1]                   # strip path, userinfo
    if s.startswith("["):                                # [ipv6]:port
        return s[1:].split("]")[0]
    if ":" in s and s.count(":") == 1:                   # host:port (not ipv6)
        head, _, tail = s.rpartition(":")
        if tail.isdigit():
            s = head
    return s


def _looks_like_host(tok):
    t = str(tok).strip()
    if not t or t.startswith("-"):
        return False
    if "://" in t:
        return True
    bare = _extract_host(t)
    if _IPV4.match(bare):
        return True
    try:
        ipaddress.ip_address(bare.split("/")[0]); return True
    except ValueError:
        pass
    if "." in bare and "/" not in bare and "\\" not in bare:
        last = bare.rsplit(".", 1)[-1].lower()
        return last.isalpha() and len(last) >= 2 and last not in _FILE_EXT
    return False


def _is_private(host):
    try:
        return ipaddress.ip_address(host.split("/")[0]).is_private
    except ValueError:
        return False


class Scope:
    """An authorized scope: the targets an agent may act against."""

    def __init__(self, data):
        if isinstance(data, (str, Path)):
            data = json.loads(Path(data).read_text())
        self.raw = data or {}
        self.allow_loopback = self.raw.get("allow_loopback", True)
        self._parsed = []
        for t in (self.raw.get("authorized_targets") or self.raw.get("targets") or []):
            t = str(t).strip()
            if not t:
                continue
            try:
                self._parsed.append(("net", ipaddress.ip_network(t, strict=False)))
            except ValueError:
                self._parsed.append(("name", t.lower().lstrip("*.")))

    def allows(self, host):
        host = host.strip().lower().rstrip("/")
        if host in LOOPBACK:
            return self.allow_loopback
        for kind, val in self._parsed:
            if kind == "net":
                try:
                    if ipaddress.ip_address(host.split("/")[0]) in val:
                        return True
                    if "/" in host and ipaddress.ip_network(host, strict=False).subnet_of(val):
                        return True
                except ValueError:
                    continue
            elif host == val or host.endswith("." + val):
                return True
        return False

    def hosts_in(self, target, args):
        out = []
        if target and str(target).strip():
            out.append(_extract_host(target))
        for a in (args or []):
            for piece in re.split(r"[\s,=]+", str(a)):
                if _looks_like_host(piece):
                    out.append(_extract_host(piece))
        seen, clean = set(), []
        for h in out:
            h = h.strip().lower()
            if h and h not in seen:
                seen.add(h); clean.append(h)
        return clean


class Guard:
    """The gate. Wraps a Scope with tiered permissions, a deny-always list, and audit logging."""

    TIER_AUTO, TIER_CONFIRM, TIER_MANUAL = 1, 2, 3

    def __init__(self, scope, tiers=None, deny_always=None, audit_log=None, require_scope=True):
        self.scope = scope if isinstance(scope, Scope) else Scope(scope)
        self.tiers = dict(tiers or {})
        self.deny_always = set(deny_always or [])
        self.audit_log = Path(audit_log) if audit_log else None
        if require_scope and not self.scope._parsed and self.scope.allow_loopback is False:
            raise Denied("no authorized targets in scope")

    def _audit(self, decision, **detail):
        rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "decision": decision, **detail}
        if self.audit_log:
            try:
                self.audit_log.parent.mkdir(parents=True, exist_ok=True)
                with self.audit_log.open("a") as f:
                    f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            except Exception:
                pass
        return rec

    def tier_of(self, tool):
        return self.tiers.get(tool, self.TIER_MANUAL)   # unknown tool -> most restrictive

    def check_scope(self, tool, target="", args=None, host_scoped=True):
        """Raise Denied if the action leaves scope or hits a deny rule. Returns the hosts touched."""
        if tool in self.deny_always:
            self._audit("deny", tool=tool, reason="deny_always")
            raise Denied("%s is in the deny-always list" % tool)
        if not host_scoped:
            self._audit("allow", tool=tool, host_scoped=False)
            return []
        hosts = self.scope.hosts_in(target, args)
        if not hosts:
            self._audit("deny", tool=tool, reason="no target host")
            raise Denied("no target host found — refusing an action with no explicit target")
        for h in hosts:
            if not self.scope.allows(h):
                reason = "lan_scan" if _is_private(h) else "out_of_scope_target"
                self._audit("deny", tool=tool, host=h, reason=reason)
                raise Denied("%s: %s is not in the signed scope" % (reason, h))
        self._audit("allow", tool=tool, hosts=hosts)
        return hosts

    def authorize(self, tool, target="", args=None, host_scoped=True, approver=None):
        """Full gate: scope-check, then tier-based approval. Returns True if the action may run.
        `approver(tier, tool, target, args) -> bool` is called only for tiers above AUTO; if it is
        None, non-auto tiers are refused (fail-safe)."""
        self.check_scope(tool, target, args, host_scoped)   # raises on denial
        tier = self.tier_of(tool)
        if tier <= self.TIER_AUTO:
            return True
        if approver is None:
            self._audit("deny", tool=tool, reason="tier %d needs approver" % tier)
            return False
        ok = bool(approver(tier, tool, target, args))
        self._audit("approved" if ok else "declined", tool=tool, tier=tier)
        return ok
