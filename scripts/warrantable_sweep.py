import sys; sys.path.insert(0,'.')
from warrantable.gate import Gate, Band, Channel, Cap
from warrantable.runtime import Runtime
from warrantable.issuance import Issuer
from warrantable.taint import Tainted, combine, require, TaintError
from warrantable.policy import digest
S,T,U,G = Band.SESSION,Band.TOOL,Band.USER,Band.GOVERNANCE
FOUND=[]
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
    probe("require() with no args passes vacuously", True)
except TaintError:
    probe("require() with no args passes vacuously", False)

# 5. budget exhaustion mid-runtime — does call() surface it honestly?
rtb=Runtime(P,budget=2); rtb.register(1)
outs=[bool(rtb.call(session=7,action="transfer",tier=2,eid=1,args={"payee":Tainted(str(i),S)},fn=lambda **k:1)) for i in range(4)]
probe("budget exhaustion silently reported as ordinary refusal", outs==[True,True,False,False] and rtb.calls==4)

# 6. policy digest of None == policy digest of missing?
probe("digest(None) collides with digest of empty dict", digest(None)==digest({}))

# 7. combine() with no args — what band?
probe("combine() of nothing is GOVERNANCE (trusted)", combine()==G)

# 8. register same eid twice
rtr=Runtime(P,budget=4)
a=rtr.register(1); b=rtr.register(1)
probe("re-registering an eid silently succeeds twice", bool(a) and bool(b))

# 9. tier 0 elevation: does a tier-0 cap authorize anything meaningful?
rt0=Runtime({"version":1,"grants":[{"sess":7,"max_tier":0,"actions":["x"]}]},budget=4); rt0.register(1,tier=0)
d0,c0=rt0.issuer.issue(7,0,"x",1)
r0=rt0.gate.authorize(rt0.gate.ingest(Channel.SESSION_DEMUX,c0),7,1,0)
probe("tier-0 elevation authorized (may be meaningless but check)", bool(r0))

# 10. USER-band argument (unauthenticated) treated same as TOOL?
rtu=Runtime(P,budget=4); rtu.register(1)
ru=rtu.call(session=7,action="transfer",tier=2,eid=1,args={"payee":Tainted("x",U)},fn=lambda **k:1)
probe("USER-band arg accepted where session required", bool(ru))

print()
print("SUSPECTS:", len(FOUND))
for f in FOUND: print("  -",f)
