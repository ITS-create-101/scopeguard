from scopeguard import Guard, Denied
G = lambda: Guard(scope={"authorized_targets": ["example.com", "10.0.0.0/24"]},
                  tiers={"read": 1, "scan": 2}, deny_always=["lan_scan", "out_of_scope_target"])
def ok(f):
    try: f(); return True
    except Denied: return False

def test_in_scope():          assert ok(lambda: G().check_scope("scan", "10.0.0.5", ["-sV"]))
def test_out_of_scope():      assert not ok(lambda: G().check_scope("scan", "8.8.8.8"))
def test_lan():               assert not ok(lambda: G().check_scope("scan", "192.168.1.9"))
def test_flag_not_host():     assert ok(lambda: G().check_scope("scan", "example.com", ["-sV", "-oN", "out.txt"]))
def test_host_in_args():      assert not ok(lambda: G().check_scope("scan", "", ["-u", "http://8.8.8.8/x"]))
def test_no_target():         assert not ok(lambda: G().check_scope("scan", "", ["-sV"]))
def test_tier_auto():         assert G().authorize("read", "example.com") is True
def test_tier_needs_approve():assert G().authorize("scan", "10.0.0.5") is False  # no approver -> fail-safe
def test_approver_yes():      assert G().authorize("scan", "10.0.0.5", approver=lambda *a: True) is True

if __name__ == "__main__":
    import sys
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    p = 0
    for fn in fns:
        try: fn(); print("PASS", fn.__name__); p += 1
        except AssertionError: print("FAIL", fn.__name__)
    print("\n%d/%d passed" % (p, len(fns))); sys.exit(0 if p == len(fns) else 1)
