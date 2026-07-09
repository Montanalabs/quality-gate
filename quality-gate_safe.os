#! Data-quality gate — untrusted a batch can only ever become one of a fixed set of decisions over a
#! closed type, never a tool argument. An injected instruction cannot be represented in the
#! closed type, so it is rejected at the trust boundary (and re-clamped at run time by extract).
#! @requires gateQuality — the data-quality gate sink
#! @effect io
#! @confidence 70
#! @taint bridge — extract<Decision> turns the tainted input into a trusted decision
grant gateQuality confidence 70

type QualityTier = CleanQ | WarnQ | DirtyQ
type Decision = GateQual(QualityTier) | Quarantine

let raw = fetch<web>  # UNTRUSTED a batch — tainted
quarantined { let d = extract<Decision>(raw) confidence 70 }  # only a fixed Decision (payloads too) crosses
privileged { gateQuality(d) }  # act on the trusted decision only
