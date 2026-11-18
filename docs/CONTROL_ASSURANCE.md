# Scoped control assurance

Offline assessment of saved runtime evidence. This is a REVOKELINE-specific checker mapped to selected FINOS requirements, **not an official CCC validator or certification**.

## Reproduce

From the project root, using the actual saved live evidence and live DMN matrix:

```powershell
python -m pytest -q
python -m scripts.control_assurance --evidence evidence/gate5-live-dmn.json --matrix evidence/gate5-dmn-matrix.json --decision-id "618d4f37-e347-11f1-9fac-76863b3dbd01"
$LASTEXITCODE
```

Expected: `PASS_SCOPED_DEMO_ASSURANCE`, exit 0, and `production_readiness: BLOCKED`. The demo gate validates the supplied scenario only. The actual matrix file is generated locally by `scripts.policy_dmn matrix`; Use the saved output of the real engine, not a reconstructed matrix. The pinned ID here is for the observed version 3, not a portable default; use the real ID and matching exports in another deployment.

Negative test (modifies an in-memory copy only):

```powershell
python -m scripts.control_assurance --evidence evidence/gate5-live-dmn.json --matrix evidence/gate5-dmn-matrix.json --decision-id "618d4f37-e347-11f1-9fac-76863b3dbd01" --negative-demo
$LASTEXITCODE
```

Expected: `FAIL_SCOPED_DEMO_ASSURANCE`, exit 1. Also try `--require-production` instead of `--negative-demo`: exit 1 because production readiness is blocked. No actual credentials or external services are used. The checker does not change the live authorization policy.

## Coverage and known gaps

Reference catalog: [CCC v2026.11 CN01](https://ccc.finos.org/catalogs/core/core/controls/v2026.11/ccc.core.cn01/), [CN04](https://ccc.finos.org/catalogs/core/core/controls/v2026.11/ccc.core.cn04/), [CN09](https://ccc.finos.org/catalogs/core/core/controls/v2026.11/ccc.core.cn09/).

- RVL.EVIDENCE.CHAIN: independently recompute the four digests and chain sequence/tip; a fully rewritten chain without a trusted anchor may still pass.
- RVL.RUNTIME.CORRELATION: verify the exported case, provider, versions, pinned DMN decisions/facts, HTTP results, external task and recorded native human-review task. The outer export fields and matrix are not signed or externally attested; their consistency is not proof of origin.
- RVL.DMN.MATRIX: independently check all 16 distinct combinations, pinned definition ID and expected/recorded results. This is an offline check, not a new live engine evaluation.
- CCC CN01.AR01/AR03: known plaintext local HTTP design and recorded accepted HTTP traffic; FAIL. No TLS handshake probe is performed by this offline checker.
- CCC CN04.AR03: PARTIAL; timestamps, decisions, business IDs in the observed two calls, but authenticated caller identity and exhaustive access logging are missing.
- CCC CN09.AR01: FAIL; known same-service in-memory logging design, no protected external log sink. The hash-chain check is not equivalent to this CCC requirement.
- AIGF MI-18 and MI-21: traceability to scoped scenario checks; MI-12 remains unverified (no real RBAC test). References: https://air-governance-framework.finos.org/mitigations/mi-18_agent-authority-least-privilege-framework.html and https://air-governance-framework.finos.org/mitigations/mi-21_agent-decision-audit-and-explainability.html.

CCC assessment rows describe the fixed local prototype and its known gaps; they do not dynamically certify changed deployments. The script's production gate deliberately stays blocked. The negative proof check is not a live security attack or an official CCC test.
