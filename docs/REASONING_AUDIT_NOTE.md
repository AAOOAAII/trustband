# Reasoning audit — what we can and cannot do at this boundary

**2026-08-31.** The LlamaFirewall row of the composition table. Recorded
honestly rather than left blank.

## The gap, stated plainly

LlamaFirewall's alignment check inspects the model's chain-of-thought for goal
misalignment. It is marked experimental by Meta, and it needs the model's
REASONING trace. Our interception points -- a tool-call hook and an MCP proxy --
see the tool call and its result. They do not see the reasoning behind the call,
because that reasoning happened inside the host's model loop, which we do not
sit in.

So the full alignment check cannot be built at our boundary. Pretending
otherwise would be dishonest.

## What CAN be done here, and is

Two things, both delivered rather than promised:

1. **A plug point.** The detector interface is monotone and content-agnostic. A
   host that DOES have the reasoning trace -- because it wrote the agent loop --
   can run an alignment check over it and return a band floor through the same
   `assess`. We provide the socket; the host that has the data provides the plug.
   This is the honest form of "candidate plugin, band-lowering only".

2. **A task-consistency detector**, `TaskDriftDetector`, over what we DO see: a
   tool argument and the user's stated task. It fires when an argument reaches
   for something the task never mentioned -- an external domain, an account, a
   file outside the task -- lowering its band. It is a weak proxy for alignment,
   not a reasoning audit, and it says so.

## Why this closes the row honestly

The row asked for "a candidate plugin, band-lowering only", because Meta's own
version is unsolved. We deliver exactly that: the interface that makes a
reasoning auditor pluggable where the data exists, and a shipped weak proxy for
where it does not. Nobody has a solid reasoning audit, so claiming one would be
the dishonest move; a socket plus a labelled proxy is the true one.
