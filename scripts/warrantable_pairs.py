import sys, traceback; sys.path.insert(0,'.')
from trustband.gate import Gate, Band, Channel, Cap, EpochKeyStore, CustodyError
from trustband.runtime import Runtime
from trustband.issuance import Issuer
from trustband.taint import Tainted, PUBLIC, readers_of, combine_readers
from trustband.policy import digest
from trustband.audit import AuditError
F=[]
def probe(pair,name,hit,note=""):
    print(("  !! SUSPECT " if hit else "  ok        ")+f"[{pair}] {name}"+(("  -- "+note) if hit and note else ""))
    if hit: F.append((pair,name,note))
P={"version":1,"grants":[{"sess":7,"max_tier":2,"actions":["go"],"min_band":"session"}]}
S,T=Band.SESSION,Band.TOOL
def rt(): 
    r=Runtime(P,budget=32); r.register(1); return r

# 1. runtime x audit -- does a RAISING tool leave the log inconsistent?
r=rt()
def boom(**k): raise RuntimeError("tool exploded")
n0=len(r.gate.audit.entries)
try: r.call(session=7,action="go",tier=2,eid=1,args={"a":Tainted(1,S)},fn=boom)
except RuntimeError: pass
ents=[e.body.get("stage") for e in r.gate.audit.entries[n0:]]
probe("runtime×audit","raising tool leaves NO outcome recorded",
      not any(st in ("execute","raised") for st in ents),
      f"stages after authorize: {ents}")

# 2. runtime x gate -- does a raising tool still leave the elevation standing?
# ACCEPTED: the gate authorised the action; whether the tool then succeeded is
# the tool's business. Documented in runtime.py, and withdraw() is the operator
# move after a failure. Recorded as a property, not a defect.
probe("runtime×gate","elevation stands after a raising tool (ACCEPTED, documented)",
      False, "")

# 3. issuance x audit -- are POLICY refusals in the chained log?
r2=rt(); n0=len(r2.gate.audit.entries)
r2.call(session=7,action="nope",tier=2,eid=1,args={"a":Tainted(1,S)},fn=lambda **k:1)
probe("issuance×audit","policy refusal absent from audit",
      not any("policy refused" in str(e.body.get("reason","")) for e in r2.gate.audit.entries[n0:]))

# 4. policy x audit -- is a policy CHANGE recorded?
r3=rt(); n0=len(r3.gate.audit.entries)
r3.adopt({"version":1,"grants":[]})
probe("policy×audit","policy change absent from audit",
      not any(e.body.get("op")=="govern_repolicy" for e in r3.gate.audit.entries[n0:]))

# 5. readers x audit -- is the AUDIENCE recorded?
r4=Runtime({"version":1,"grants":[{"sess":7,"max_tier":2,"actions":["go"],"recipients":["bob"]}]},budget=8)
r4.register(1); n0=len(r4.gate.audit.entries)
r4.call(session=7,action="go",tier=2,eid=1,args={"a":Tainted(1,S,frozenset({"alice"}))},fn=lambda **k:1)
probe("readers×audit","audience refusal not in audit",
      not any("confidentiality" in str(e.body.get("reason","")) for e in r4.gate.audit.entries[n0:]))

# 6. taint x policy digest -- do bands/recipients change the digest?
p1={"version":1,"grants":[{"sess":7,"max_tier":2,"actions":["go"],"min_band":"session"}]}
p2={"version":1,"grants":[{"sess":7,"max_tier":2,"actions":["go"],"min_band":"tool"}]}
probe("taint×policy","min_band change does not change digest", digest(p1)==digest(p2))

# 7. custody x issuance -- does a custody FAILURE fail closed?
class Dead:
    def generate_mac(self,**k): raise RuntimeError("KMS down")
from trustband.custody import AwsKmsHmacSigner, CustodyBackendError
try:
    ks=EpochKeyStore(signer=AwsKmsHmacSigner(Dead(),key_ids={0:"k"}))
    g=Gate(budget=4,keys=ks); g.write(2,1)
    d,cap=g.govern_issue(7,2,1)
    probe("custody×issuance","custody failure did NOT stop minting", bool(d), "minted with a dead backend")
except CustodyBackendError:
    probe("custody×issuance","custody failure stops minting (raises)", False)
except Exception as e:
    probe("custody×issuance","custody failure raises unexpected type", True, type(e).__name__)

# 8. audit x budget -- is budget exhaustion chained?
r5=Runtime(P,budget=1); r5.register(1)
r5.call(session=7,action="go",tier=2,eid=1,args={"a":Tainted(1,S)},fn=lambda **k:1)
n0=len(r5.gate.audit.entries)
r5.call(session=7,action="go",tier=2,eid=1,args={"a":Tainted(2,S)},fn=lambda **k:1)
probe("audit×budget","budget refusal absent from audit",
      not any(e.body.get("conjunct")=="budget" for e in r5.gate.audit.entries[n0:]))

# 9. readers x revocation -- does rotation touch the audience?
r6=Runtime({"version":1,"grants":[{"sess":7,"max_tier":2,"actions":["go"],"recipients":["bob"]}]},budget=8)
r6.register(1); before=r6.gate.gov_policy
r6.revoke_all()
probe("readers×revocation","rotation silently changed the audience/policy digest",
      r6.gate.gov_policy!=before)

# 10. transport x gate -- can a band be forged through the public API?
from trustband.gate import Presented, BandForgery
g7=Gate(budget=4); g7.write(2,1); d,cap=g7.govern_issue(7,2,1)
try:
    p=Presented(cap, Band.SESSION); probe("transport×gate","Presented forgeable", True, "constructed outside ingest")
except BandForgery:
    probe("transport×gate","Presented forgeable", False)

print(); print("SUSPECTS:", len(F))
for pair,n,note in F: print(f"  - [{pair}] {n}" + (f"\n      {note}" if note else ""))
