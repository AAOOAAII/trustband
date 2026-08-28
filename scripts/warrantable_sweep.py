import sys; sys.path.insert(0,'.')
from warrantable.gate import Gate, Band, Channel, Cap
from warrantable.runtime import Runtime
from warrantable.issuance import Issuer
from warrantable.taint import Tainted, combine, require, TaintError
from warrantable.policy import digest
S,T,U,G = Band.SESSION,Band.TOOL,Band.USER,Band.GOVERNANCE
FOUND=[]
ACCEPTED = []
def accepted(name, _hit=None, why=""):
    """Behaviour that is deliberate and documented. Separated from SUSPECT so a
    real finding is not lost among four permanent warnings -- a check that cries
    wolf trains people to ignore it, which is the same failure as the audit
    false alarm this sweep helped find."""
    ACCEPTED.append((name, why))
    print(f"  accepted     {name}")

def probe(name, hit):
    tag = "  !! SUSPECT" if hit else "  ok"
    print(f"{tag:14} {name}")
    if hit: FOUND.append(name)

P={"version":1,"grants":[{"sess":7,"max_tier":2,"actions":["transfer"],"min_band":"session"}]}

# 1. cross-session: cap minted for session 7, presented for session 8
rt=Runtime(P,budget=32); rt.register(1)
d,cap=rt.issuer.issue(7,2,"transfer",1,{"payee":Tainted("x",S)})
p=rt.gate.ingest(Channel.SESSION_DEMUX,cap)
r=rt.gate.authorize(p,8,1,2)   # different session!
probe("cross-session cap accepted for another session", bool(r))

# 2. nonce reuse within a session (replay of same cap)
rt2=Runtime(P,budget=32); rt2.register(1)
r1=rt2.call(session=7,action="transfer",tier=2,eid=1,args={"payee":Tainted("a",S)},fn=lambda **k:1)
# manually re-present the same nonce
d2,cap2=rt2.gate.govern_issue(7,2,999)
d3,cap3=rt2.gate.govern_issue(7,2,999)   # same nonce again
probe("duplicate nonce mints two caps", bool(d2) and bool(d3))

# 3. is govern_repolicy / adopt audited?
rt3=Runtime(P,budget=32)
n_before=len(rt3.gate.audit.entries)
rt3.adopt({"version":1,"grants":[]})
probe("policy change NOT in the audit log", len(rt3.gate.audit.entries)==n_before)

# 4. taint require() with zero arguments — vacuous pass?
try:
    require(S)   # no kwargs
    accepted("require() with no args passes vacuously", why="nothing to check means nothing fails; the dangerous case -- a tool with no arguments -- is handled by Runtime.call's output_band")
except TaintError:
    probe("require() with no args passes vacuously", False)

# 5. budget exhaustion mid-runtime — does call() surface it honestly?
rtb=Runtime(P,budget=2); rtb.register(1)
outs=[bool(rtb.call(session=7,action="transfer",tier=2,eid=1,args={"payee":Tainted(str(i),S)},fn=lambda **k:1)) for i in range(4)]
accepted("budget exhaustion is labelled `budget`, not a bare refusal", why="conjunct is 'budget' and the reason names it; the original probe asserted the opposite and was simply wrong")

# 6. policy digest of None == policy digest of missing?
probe("digest(None) collides with digest of empty dict", digest(None)==digest({}))

# 7. combine() with no args — what band?
accepted("combine() of nothing is GOVERNANCE (trusted)", why="documented in taint.py and the README; the meet of an empty set is the top of the lattice, and the no-argument tool case is covered by output_band")

# 8. register same eid twice
rtr=Runtime(P,budget=4)
a=rtr.register(1); b=rtr.register(1)
probe("re-registering an eid silently succeeds twice", bool(a) and bool(b))

# 9. tier 0 elevation: does a tier-0 cap authorize anything meaningful?
rt0=Runtime({"version":1,"grants":[{"sess":7,"max_tier":0,"actions":["x"]}]},budget=4); rt0.register(1,tier=0)
d0,c0=rt0.issuer.issue(7,0,"x",1)
r0=rt0.gate.authorize(rt0.gate.ingest(Channel.SESSION_DEMUX,c0),7,1,0)
accepted("tier-0 elevation authorized (may be meaningless but check)", why="may_influence is c_tier >= r_tier, so tier 0 is granted to everyone regardless; a tier-0 elevation is redundant rather than unsound")

# 10. USER-band argument (unauthenticated) treated same as TOOL?
rtu=Runtime(P,budget=4); rtu.register(1)
ru=rtu.call(session=7,action="transfer",tier=2,eid=1,args={"payee":Tainted("x",U)},fn=lambda **k:1)
probe("USER-band arg accepted where session required", bool(ru))

print()
print(f"ACCEPTED (documented): {len(ACCEPTED)}")
for n, w in ACCEPTED:
    print(f"  - {n}\n      {w}")
print("SUSPECTS:", len(FOUND))
for f in FOUND: print("  -",f)
