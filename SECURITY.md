# Security Policy

## Supported versions

The current `0.1.x` release line is supported. OMP 16.5.1 is the tested host version.

## Reporting a vulnerability

Use GitHub private vulnerability reporting for the repository when it is available. Include:

- OMP Auto Guard and OMP versions
- Operating system
- Tool name and sanitized arguments
- Expected and observed verdicts
- Whether an approval permit was involved
- A minimal reproduction

Do not include credentials, raw audit logs, private conversation content, or destructive proof-of-concept commands in a public issue. If private reporting is unavailable, contact the repository owner before sharing sensitive details.

## Threat model

Auto Guard runs inside the OMP process and observes tool calls before execution. Its goals are to:

- Deny a narrow set of catastrophic operations deterministically.
- Require semantic review for operations whose effects are not statically understood.
- Require explicit approval for material consequences not already authorized.
- Bind one approval to one exact canonical call, working directory, and approval epoch.
- Invalidate permits at lifecycle boundaries, working-directory changes, and pending user input.
- Fail closed when classification or approval cannot complete safely.

Auto Guard is not a security boundary. It does not isolate tools, constrain the host process, replace operating-system authorization, or guarantee that language-model judgments are correct.

An attacker or failure that can modify OMP, disable extensions, bypass the tool-call event, alter this extension, or execute commands outside OMP is outside this threat model.
Exact call binding does not snapshot referenced external state. The same path, branch, tag, URL, query selection, or remote name can resolve to different content after approval. Use immutable identifiers and conditional or versioned operations where supported. Treat residual time-of-check/time-of-use risk as outside the guarantees of generic argument binding.

## Sensitive data

Classifier requests may contain working-directory paths, recent conversation, project/global instructions, and best-effort-redacted tool arguments. The classifier may use a different provider from the main agent. Redaction is not guaranteed to remove every secret.

Audit logs may contain sensitive tool details and raw classifier output. Context logging is especially sensitive. Store logs with restricted permissions, limit retention, and never commit them.
Native approval prompts contain a redacted argument summary capped at 512 characters and a non-authoritative agent rationale capped at 240 characters. Long values can be abbreviated. The exact call is bound by the full internal digest and exact Ask payload, but the user should reject an approval when the visible summary is insufficient.

## Operational guidance

- Use least-privilege credentials and accounts.
- Keep backups or version control for mutable work.
- Review deployments, database changes, permission changes, and credential operations.
- Restart OMP after updating the extension; existing sessions do not hot-reload it.
- Treat classifier `allow` as one defense-in-depth signal, not proof that an operation is safe.
