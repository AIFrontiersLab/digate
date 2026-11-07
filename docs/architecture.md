# Digate architecture notes

Digate is a Phase-1 promotion gateway. Scanners seal pass/fail outcomes to a
candidate digest. The gateway only advances release state when the seal matches
the exact digest under promotion.

```mermaid
flowchart LR
  Scanner[Image Scanner] -->|seal digest D| VerdictStore[Signed Verdict]
  CI[Release Candidate] -->|register digest D| Registry[Release Store]
  CI -->|promote request| Gateway[Promotion Gateway]
  VerdictStore --> Gateway
  Gateway -->|digest match + valid sig| Registry
  Gateway -->|mismatch or bad sig| Audit[Audit Log]
  Registry -->|state unchanged or promoted| Audit
```

## Components

| Component | Responsibility |
| --- | --- |
| Release Store | Tracks candidate/promoted digests |
| Verdict Sealer | Ed25519 seals over canonical scan payload |
| Policy | Digest binding, freshness, release binding |
| Gateway | Orchestrates verify-then-act |
| Audit Log | Append-only deny/accept events |
