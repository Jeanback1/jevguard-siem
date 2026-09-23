# Product plan

## Goal

Build a portfolio-quality defensive SIEM that explains what it observed, what
rule matched, what Jev decided, and what a human should review.

## Architecture

1. Collectors read local Linux telemetry without modifying the host.
2. Normalization converts telemetry to one event schema.
3. Deterministic rules attach facts and an initial severity.
4. A provider interface performs bounded triage. Local rules, Jev, OpenRouter,
   and OpenAI-compatible services are supported independently.
5. Policy converts the decision and confidence into a review status.
6. SQLite stores events and decisions for the web interface.

## Delivery phases

### Milestone 1: local vertical slice

- Network and authentication collectors
- Event storage and deduplication
- Local decision fallback
- Pluggable decision providers and environment-only credentials
- Dashboard and demo dataset

### Milestone 2: host activity

- [x] Suspicious process lifecycle signals from procfs polling
- [x] User and group changes
- [x] Cron and systemd persistence file changes
- [x] Selected file-integrity monitoring
- [x] Optional auditd process execution stream for short-lived processes

### Milestone 3: correlation

- [x] SSH failure threshold and failures followed by success
- [x] New listener associated with a new process
- [x] Privilege escalation followed by persistence
- Configurable time windows and incident grouping

### Milestone 4: evaluation

- Versioned labeled dataset
- Rules-only, Jev-only, and hybrid comparison
- Precision, recall, false positives, calibration, latency, and cost
- Adversarial log-content tests

### Milestone 5: portfolio release

- Installation package and systemd unit
- Screenshots and two-minute demonstration
- Architecture decision records
- Public evaluation report with known limitations

## MVP acceptance criteria

- Starts without root and clearly reports unavailable telemetry.
- Stores normalized events in SQLite.
- Shows summary, filters, events, and decisions in a browser.
- Operates without Jev through a labeled deterministic fallback.
- Uses only fixed answer options and stores provider provenance.
- Runs without a paid AI service.
- Allows new providers without changing collectors, storage, or the dashboard.
- Never performs containment automatically.
- Does not send raw informational connections to an external model.
- Includes repeatable tests and demo data.
