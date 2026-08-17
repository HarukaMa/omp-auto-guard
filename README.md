## Human written preface

I've always wanted to have something like CC's auto mode in OMP, and GPT 5.6 told me there is the extension system that can run code before each tool call, so I let it wrote this thing as an experiment.

This might work best with `yolo` mode, but it's still an inherently dangerous setting. Be careful when using it.

# OMP Auto Guard

OMP Auto Guard is an experimental [Oh My Pi](https://github.com/can1357/oh-my-pi) extension that reviews selected tool calls before execution. It combines deterministic checks, model-assisted consequence review, and exact single-use approval permits.

It is not a sandbox, an access-control boundary, or a substitute for operating-system permissions, backups, code review, and least-privilege credentials.

## Requirements

- OMP 16.5.1 through 17.x
- Bun 1.3.14 or newer

OMP 17.0.1 is the version exercised by this repository. OMP 16.5.1 was also verified before the 17.x upgrade. Prompt rendering and extension APIs may change in later OMP releases.

## Installation

From a source checkout:

```sh
bun install --frozen-lockfile
omp plugin link .
```

Restart OMP after installation. Extensions are loaded once when a session starts; existing sessions do not hot-reload changed files.

For local development without plugin linking:

```sh
omp --extension ./index.ts
```

## Behavior

Every tool call receives one static policy decision:

- `allow`: execute without additional review.
- `ask`: require an explicit native Ask selection.
- `deny`: block a narrowly defined catastrophic operation.
- `classify`: send the call to the configured safety classifier.

For semantically reviewed calls, the classifier reports an effect level instead of choosing the final verdict directly. Auto Guard derives the verdict as follows:

- `bounded`: allow, regardless of semantic task scope or authorization.
- `material`: allow only when the operation and target are authoritatively requested or approved; otherwise ask.
- `unknown`: ask when a plausible material operational effect cannot be established from the concrete executable, command, arguments, and technical evidence.
- `prohibited`: deny.

Reversible repository-local edits, unpushed local commits, formatting, builds, tests, disposable test data, and established bounded verification are not approval boundaries merely because they are tangential to a plan. Finite named temporary, staging, and build artifacts on a user-controlled host are likewise bounded when they do not change active service behavior, durable production data, credentials, publication, or funds. Remote location, persistence, or a write alone does not make an operation material; production activation, availability, durable shared state, access, assets, publication, significant cost, and difficult rollback do. A loopback bind address is not sufficient evidence that a process is bounded: executable and command effects such as persistence, credential access, file writes, privilege, and outbound traffic still require classification.

Empty, invalid, or provider-failed classifier responses are retried once within the original deadline. Exhausted retries, unavailable models, oversized inputs, and timeouts fail closed to `ask`.

Classifier output is accepted only as one unwrapped JSON object with exactly the documented fields and scalar types. Leading or trailing prose, code fences, arrays, duplicate keys, legacy `decision` fields, aliases, extra fields, invalid labels, and multiline reasons are treated as invalid and therefore fail closed.

Approval identity is a SHA-256 digest over the approval epoch, working directory, tool name, and canonicalized arguments. A permit is single-use, expires five minutes after approval is recorded (not five minutes after the Ask is issued), and is invalidated by lifecycle changes, working-directory changes, or queued input or advice. While input is pending, statically proven non-sensitive reads and `todo` may proceed, but classified calls, Ask, and writes remain paused. `Review batch` grants no permit; it returns control to the agent to present one concrete revised batch for explicit user approval. Rejecting, timing out, redirecting to chat, entering custom Ask text, or changing protected Ask fields does not authorize the call.

Hub launches have one explicit scoped continuation so agents do not request approval for every process lifecycle step. After a successfully permitted `hub start` (including an exact launch retried after native approval), Auto Guard remembers the retained process name and launch arguments for the current session and working directory. An unchanged launch plus name-bound `stop`, `restart`, and signal operations can then proceed without another Ask. Failed launches record nothing; changed launch arguments, different process names, process text/keys, and unknown lifecycle shapes remain under semantic review. A complete approved plan or authoritative proposal/response pair may separately authorize covered process input. Agent turn boundaries preserve the launch scope, while session start, switch, branch, and tree boundaries clear it. When a `hub start` needs native approval, the approval option discloses this continuation before the user selects it.

OMP Plan Mode approval is recognized only from the exact core-generated approval or active-plan reference message. Auto Guard snapshots the referenced `local://` plan before the next tool executes and supplies the complete snapshot, up to 128 KiB, as the immutable baseline authority. It preserves up to eight non-timeout native Ask decisions within a 64 KiB budget independently from up to sixteen adjacent assistant-proposal/user-response pairs within a 32 KiB budget, then merges them by branch sequence. The classifier receives only a complete chronological suffix: if any later decision is omitted by a count or size limit, all older authority is omitted too. This prevents ordinary conversation within the separate budget from evicting native Ask authority without allowing an older approval to outlive a missing later restriction. The pairs remain neutral context rather than pre-classified approvals: the classifier interprets questions, conditions, corrections, rejections, typos, and any language semantically. Guard-owned single-use Ask prompts are excluded. Assistant text never self-authorizes, later user restrictions take precedence, and later plan-file edits do not expand authorization.

Manual skill invocations are recognized only from the exact host-generated, user-attributed `skill-prompt` envelope. Auto Guard supplies a bounded snapshot of that invocation as authoritative user conversation so the classifier can follow the skill's explicit or contextual workflow without asking again for each covered mutation. Skills loaded by the agent, tool-returned skill text, malformed lookalikes, and non-user skill prompts cannot grant authorization.

The Ask template shows a short fingerprint and, for ordinary calls, a redacted argument summary capped at 512 characters. Database calls instead show the complete redacted classifier input when it fits the 128 KiB classifier limit, preserving multiline SQL for inspection. Before calling Ask, the agent must replace the designated approval-option preview placeholder with a non-empty, single-line rationale; the rationale is capped at 400 characters and remains explicitly non-authoritative. Auto Guard re-renders the complete expected input from its own template and the validated rationale before exact comparison. The full call digest remains internal.

Exact arguments do not freeze resources referenced by those arguments. A path, branch, tag, URL, database selection, or remote name may resolve to different state between approval and execution. Prefer immutable identifiers and tool-supported preconditions, such as commit SHAs, object versions, expected revisions, and conditional writes. Auto Guard cannot generically eliminate this time-of-check/time-of-use risk.

Tool arguments are classified in full after best-effort secret redaction. Inputs above 128 KiB are not classified from a partial representation; they require approval instead.

Database operations always use the strong classifier tier with the complete redacted tool arguments. Auto Guard does not split SQL or attempt dialect-independent parsing of comments, literals, or statements. Suspicious raw keywords such as `DROP`, `TRUNCATE`, and `FLUSHALL` are supplied as classifier observations, not treated as proof that the text is executable.

## Configuration

All configuration is optional.

| Variable | Default | Purpose |
| --- | --- | --- |
| `OMP_AUTO_GUARD_FAST_MODEL` | `pi/tiny`, then `pi/smol`, then `pi/default` | Model candidate for fast-tier reviews. |
| `OMP_AUTO_GUARD_STRONG_MODEL` | `pi/smol`, then `pi/default` | Model candidate for strong-tier reviews. |
| `OMP_AUTO_GUARD_FAST_EFFORT` | `low` | Reasoning effort for fast-tier models that support reasoning. |
| `OMP_AUTO_GUARD_STRONG_EFFORT` | `medium` | Reasoning effort for strong-tier models that support reasoning. |
| `OMP_AUTO_GUARD_TIMEOUT_MS` | `12000` | Classifier deadline, clamped to 1000-28000 ms. |
| `OMP_AUTO_GUARD_LOG_PATH` | unset | Append classifier audit records as JSONL. |
| `OMP_AUTO_GUARD_LOG_INCLUDE_CONTEXT` | unset | Set to `1` to include classifier payloads and full content blocks from invalid responses. |
| `OMP_AUTO_GUARD_TIMING` | unset | Set to `1` to print classifier model and latency information. |

If configured classifier candidates cannot be resolved, Auto Guard falls back to the current session model. If no model is available, it requires approval.

## Data handling

Model classification can transmit the following to the resolved classifier provider:

- Working-directory path
- The first authoritative user message plus the existing bounded selection of recent user and assistant conversation
- Bounded snapshots of exact host-generated, user-attributed manual skill invocations
- Up to 16 recent non-Ask tool results within an 8,000-character budget; evidence relevant to the proposed call may use up to 2,000 characters and other results up to 500
- Immutable approved Plan Mode content, when active
- Up to eight complete native Ask decisions within 64 KiB and up to sixteen ordinary assistant-proposal/user-response pairs within 32 KiB, merged as a complete chronological branch suffix
- Unambiguous configured SSH alias, host, username, and port mappings
- Project and global instructions extracted from the OMP system prompt
- The isolated proposed tool name and best-effort-redacted arguments
- Static policy observation

Redaction is not a reliable data-loss-prevention mechanism. Commands, paths, SQL, conversation text, and model responses may contain sensitive data. Configure classifier providers and credentials accordingly.

When audit logging is enabled, records include the classifier model, effort, latency, attempt count, normalized token usage, tool name, policy observation, raw model response, effect level, risk level, authorization assessment, and derived verdict. Retried failures and invalid responses include attempt diagnostics. `OMP_AUTO_GUARD_LOG_INCLUDE_CONTEXT=1` additionally records the classifier payload and full invalid response content blocks. Protect audit logs as sensitive data and do not commit them.

## Security model and limitations

Auto Guard is intended to reduce accidental high-consequence actions by a cooperative coding agent. It does not defend against:

- A compromised OMP runtime or extension loader
- Tools that bypass OMP tool-call hooks
- Direct commands run outside OMP
- Malicious or incorrect classifier models
- Complete command-language or SQL parsing
- Secrets already exposed to the main agent or selected classifier provider
- Users approving a harmful operation
- Mutable resources changing after approval while the exact tool arguments remain unchanged

Classifier schema validation establishes only that a response is well formed. A syntactically valid but incorrect `effectLevel` or `userAuthorization` judgment, including one influenced by prompt injection in untrusted tool data, can still produce an incorrect allow; this is part of the malicious-or-incorrect-classifier limitation above.

Deterministic shell patterns remain defense in depth, not complete parsers. SQL is routed to dialect-aware semantic review instead of being treated as statically proven safe.
Ordinary approval summaries deliberately limit conversation growth and may abbreviate long values. Database approvals show the complete redacted classifier input when it fits the classifier limit. Reject the call whenever the displayed information is insufficient for an informed decision.

See [SECURITY.md](SECURITY.md) for reporting and threat-model details.

## Development

```sh
bun install --frozen-lockfile
bun run typecheck
bun test
bun run check
```

The test preload clears Auto Guard environment variables so tests do not write to a real audit log or inherit local classifier configuration.

## License

OMP Auto Guard is licensed under the GNU General Public License, version 3 only. See [LICENSE](LICENSE).
