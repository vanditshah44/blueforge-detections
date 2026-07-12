# BLUE-FORGE — Detection-as-Code

[![detections-ci](https://github.com/vanditshah44/blueforge-detections/actions/workflows/ci.yml/badge.svg)](https://github.com/vanditshah44/blueforge-detections/actions/workflows/ci.yml)
![Sigma](https://img.shields.io/badge/rules-Sigma-4c8bf5)
![Sentinel](https://img.shields.io/badge/target-Microsoft%20Sentinel%20(KQL)-0078d4)
![Splunk](https://img.shields.io/badge/target-Splunk%20(SPL)-65a637)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

> Vendor-neutral **Sigma** detections, version-controlled and CI-validated, that
> compile automatically to **Microsoft Sentinel (KQL)** and **Splunk (SPL)**.
> Every rule is mapped to **MITRE ATT&CK** and must pass lint, policy tests, and
> cross-SIEM compilation before it merges.

This is the detection engineering backbone of my home lab, **BLUE-FORGE**. The
lab emulates adversary techniques against a Windows + Sysmon estate; the
detections that catch them live here, treated like software: reviewed in pull
requests, tested in CI, and deployed to two SIEMs from a single source of truth.

**Why this exists:** I don't just monitor a SIEM — I *build* the detections,
automate their validation, and ship them as code. That is the difference between
a SOC analyst who clicks through alerts and a detection engineer who owns the
pipeline.

---

## The detection-as-code pipeline

```
                    ┌─────────────────────────────────────────────┐
                    │   rules/**/*.yml   (Sigma — one source)       │
                    └───────────────────────┬─────────────────────┘
                                            │
         ┌──────────────────┬───────────────┼───────────────────┐
         ▼                  ▼               ▼                   ▼
   sigma check         pytest        tools/convert.py     ATT&CK mapping
   (schema lint)   (policy tests)   (pySigma backends)   (tags per rule)
         │                  │               │                   │
         └──────────────────┴───────┬───────┴───────────────────┘
                                     ▼
                       GitHub Actions CI  (gate on every PR)
                                     │
                     ┌───────────────┴───────────────┐
                     ▼                               ▼
          build/sentinel/detections.kql     build/splunk/detections.spl
             (Microsoft Sentinel)                  (Splunk)
```

A rule is only "done" when it lints as valid Sigma, satisfies the repo's
metadata policy (ATT&CK tag, severity, unique ID, documented false positives),
and compiles cleanly to every SIEM that carries its data source. CI enforces all
three. Compilation is **log-source aware**: endpoint detections (process,
registry) compile to both Splunk and Sentinel/Defender, while the DNS network
detection currently targets Splunk — Defender XDR has no first-class DNS-query
table, so that mapping is handled explicitly rather than forced. A rule that
*fails* to compile to a target it should support breaks the build.

---

## Rule catalogue

| Rule | ATT&CK | Tactic | Severity | Log source |
|------|--------|--------|----------|------------|
| PowerShell EncodedCommand Execution | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Execution | high | process_creation |
| LSASS Credential Dump via LOLBin | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | Credential Access | critical | process_creation |
| Scheduled Task Creation via schtasks | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Persistence | medium | process_creation |
| Registry Run Key Persistence | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Persistence | medium | registry_set |
| Suspicious DNS Query to Public DoH Resolver | [T1071.004](https://attack.mitre.org/techniques/T1071/004/) | Command & Control | medium | dns_query |

ATT&CK coverage is tracked in [`docs/ATTACK_COVERAGE.md`](docs/ATTACK_COVERAGE.md).
The detection engineering workflow (hypothesis → rule → validate → tune →
deploy) is documented in [`docs/DETECTION_LIFECYCLE.md`](docs/DETECTION_LIFECYCLE.md).

---

## Quickstart

```bash
python -m venv .venv && source .venv/bin/activate
make install         # pySigma + backends + test deps

make lint            # sigma check rules/       (schema validity)
make test            # pytest -q                (metadata / policy)
make convert         # compile to SPL + KQL into build/
make all             # everything CI runs
```

Generated queries land in `build/splunk/detections.spl` and
`build/sentinel/detections.kql`, ready to paste into a Sentinel analytics rule
or a Splunk saved search.

---

## Repository layout

```
blueforge-detections/
├── rules/                       # Sigma rules — the single source of truth
│   ├── windows/process_creation/
│   ├── windows/registry/
│   └── network/
├── tools/convert.py             # batch Sigma -> SPL + KQL (pySigma)
├── tests/test_rules.py          # metadata & policy tests
├── docs/                        # detection lifecycle, ATT&CK coverage
├── .github/workflows/ci.yml     # lint + test + compile on every PR
├── Makefile                     # install / lint / test / convert
└── requirements.txt
```

---

## Toolchain

Built on the [pySigma](https://github.com/SigmaHQ/pySigma) ecosystem — the same
tooling used in production detection-engineering programs:

- **[sigma-cli](https://github.com/SigmaHQ/sigma-cli)** — validation and conversion
- **[pysigma-backend-splunk](https://github.com/SigmaHQ/pySigma-backend-splunk)** — SPL output
- **[pysigma-backend-kusto](https://github.com/SigmaHQ/pySigma-backend-kusto)** — KQL for Sentinel / Defender
- **[pysigma-pipeline-sysmon](https://github.com/SigmaHQ/pySigma-pipeline-sysmon)** — Sysmon field mapping

---

## Roadmap

- [ ] Expand coverage across the ATT&CK matrix (lateral movement, exfiltration)
- [ ] Add a Sentinel ASIM DNS pipeline so network detections also compile to KQL
- [ ] Auto-generate a MITRE ATT&CK Navigator layer from rule tags
- [ ] Purple-team validation: link each rule to the Atomic Red Team test that fires it
- [ ] Alert-enrichment / SOAR microservice (FastAPI) that consumes these detections
- [ ] ML-assisted anomaly detection over the same lab telemetry

---

## About

Built by **Vandit Shah** — M.Sc. Cybersecurity, Security+ & SC-200 certified —
as part of the BLUE-FORGE detection-engineering lab.
Portfolio: [vanditshah.com](https://vanditshah.com) ·
GitHub: [@vanditshah44](https://github.com/vanditshah44)

Licensed under the [MIT License](LICENSE).
