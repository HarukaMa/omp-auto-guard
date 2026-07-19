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

Plan Mode support trusts only the exact core-generated approval and active-plan reference message shapes, not arbitrary developer messages or tool results. The referenced plan is snapshotted before the next tool executes and remains the immutable authorization baseline. Concrete inline assistant plans become bounded additive amendments only when paired with a later non-synthetic user approval after the current Plan Mode approval marker. If a post-compaction reference is present, amendment recency is measured from the original approval for the same plan. If OMP restarts before Auto Guard captured the baseline, no approval-time digest is available; the extension must snapshot the file identified by OMP's active plan reference.

## Sensitive data

Classifier requests may contain working-directory paths, recent conversation, up to 8,000 characters of best-effort-redacted recent non-Ask tool results, project/global instructions, and best-effort-redacted tool arguments. The classifier may use a different provider from the main agent. Redaction is not guaranteed to remove every secret.
Approved Plan Mode snapshots and approved inline amendments may also be sent to the classifier provider.

Audit logs may contain sensitive tool details and raw classifier output. Context logging is especially sensitive. Store logs with restricted permissions, limit retention, and never commit them.
Native approval prompts contain an agent-supplied, non-authoritative rationale capped at 400 characters. Ordinary calls show a redacted argument summary capped at 512 characters; database calls show the complete redacted classifier input when it fits the 128 KiB classifier limit so multiline SQL remains inspectable. Auto Guard accepts only a non-empty, single-line rationale in the designated option-preview slots, then re-renders and exactly compares every Ask field before display. Reject an approval when the visible information is insufficient.

## Operational guidance

- Use least-privilege credentials and accounts.
- Keep backups or version control for mutable work.
- Review deployments, database changes, permission changes, and credential operations.
- Restart OMP after updating the extension; existing sessions do not hot-reload it.
- Treat classifier `allow` as one defense-in-depth signal, not proof that an operation is safe.
- Database SQL is reviewed as complete model input rather than split or parsed by a dialect-independent static lexer. Raw destructive keywords only focus classifier attention and do not establish whether text is executable, quoted, or commented.
