# Conmap Enhancement Roadmap

This roadmap captures the remaining work planned around the new security posture features. It focuses on items **not yet implemented** in the current codebase.

## 1. Conbox Sandbox (Dynamic Analysis)
- [ ] Replace the current metadata-driven simulation with real container/VM isolation (e.g., Firecracker, gVisor) and hardened runtime profiles (seccomp/AppArmor).
- [ ] Implement resource quotas (CPU, memory, network egress) and per-run cleanup for sandbox environments.
- [ ] Add deterministic input harnesses per tool capability (filesystem, HTTP, database) to exercise behavior automatically.
- [ ] Stream sandbox telemetry (syscalls, network flows, file I/O) into structured evidence and SIEM hooks.
- [ ] Surface sandbox job state in `/scan-progress` (queue, running, completed, failed) with retry/backoff policies.

## 2. Runtime Anomaly Analytics
- [ ] Persist historical baselines (success ratio, payload size) across scans and aggregate alerts when drift persists.
- [ ] Correlate anomalies with authentication failures, rate limiting, and infrastructure telemetry.
- [ ] Expose anomaly dashboards/metrics for SecOps (e.g., Prometheus exporters, OpenTelemetry spans).

## 3. Output Safety (DLP) Improvements
- [ ] Expand detector pack with configurable allow/deny patterns, contextual redaction rules, and localization-aware PII detection.
- [ ] Integrate with enterprise DLP services (ICAP/API) for verdicts beyond regex matches.
- [ ] Add configurable severity/thresholds per pattern and support audit/allow modes.

## 4. Tool Vetting Workflow
- [ ] Build registry integration for signature validation (e.g., Sigstore, internal PKI) and artifact attestation.
- [ ] Implement recertification reminders and approval workflows (notifications, ticketing integrations).
- [ ] Capture full approval metadata (owner, reviewer, risk score) and render it in reports.

## 5. Zero Trust & Infrastructure Audits
- [ ] Verify OAuth flows, token scopes, and sender-constrained tokens directly against endpoints.
- [ ] Detect network segmentation gaps (e.g., open administrative ports, missing mTLS) via targeted probes.
- [ ] Report on gateway/WAF rules, rate limiting, and throttling posture.

## 6. Operational Integrations
- [ ] Add configuration management & CLI/REST toggles for new modules (sandbox queues, DLP policies, anomaly thresholds).
- [ ] Push findings and telemetry into SIEM/SOAR pipelines with incident playbooks.
- [ ] Provide automation hooks for containment (auto-disable tool, revoke tokens) when high-severity findings trigger.

---

*Status legend: unchecked items are pending implementation. Completed tasks live in the codebase and are not repeated here.*
