# Threat model

## Protected assets

- Host telemetry and incident history
- AI-provider API keys
- Integrity of triage decisions
- Availability of the collector and dashboard

## Trust boundaries

- Kernel and `/proc` data are local operating-system inputs.
- Journal messages and process arguments are untrusted attacker-controlled data.
- Jev, OpenRouter, and other configured AI providers are external services.
- Browser input is untrusted.

## Initial controls

- The server binds to loopback by default.
- Database queries use parameters.
- API keys are read only from the environment and are never stored in events.
- Raw evidence is represented as data, never inserted into Jev instructions.
- AI answers must match fixed choices before policy uses them.
- Remote provider URLs require HTTPS; HTTP is limited to local model servers.
- Low-confidence results require human review.
- Containment remains recommendation-only.
- Collector subprocesses avoid a shell and use timeouts.
- Informational socket telemetry is not sent to external AI providers.
- Medium-severity telemetry is retained locally and is not sent externally by default.
- Provider output cannot lower a deterministic high or critical risk floor.
- Persistent hourly, daily, and per-incident cooldown limits bound AI usage.
- The collector excludes sockets owned by its own process and local dashboard.

## Known limitations

- A compromised root account can tamper with local telemetry and the database.
- `/proc` polling can miss short-lived connections.
- `/proc` process polling can miss short-lived processes; auditd is required for
  complete execution telemetry.
- Journal visibility depends on local permissions and distribution configuration.
- Any AI provider can return a valid but incorrect decision.
- Generic LLM confidence is self-reported and is not treated as calibrated.
- The first milestone does not inspect packet payloads.
