#! VULNERABLE quality-gate — feeds the untrusted input straight to the tool, no extraction.
#! check -> UNSAFE: tainted data cannot reach a capability.
grant gateQuality confidence 70

let raw = fetch<web>
privileged { gateQuality(raw) }  # tainted -> tool: REJECTED
