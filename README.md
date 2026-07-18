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

Classifier failures, invalid responses, unavailable models, oversized inputs, and timeouts fail closed to `ask`.

Approval identity is a SHA-256 digest over the approval epoch, working directory, tool name, and canonicalized arguments. A permit is single-use, expires five minutes after approval is recorded (not five minutes after the Ask is issued), and is invalidated by lifecycle changes, working-directory changes, or queued input or advice. Rejecting, timing out, redirecting to chat, entering custom Ask text, or changing protected Ask fields does not authorize the call.

OMP Plan Mode approval is recognized only from the exact core-generated approval or active-plan reference message. Auto Guard snapshots the referenced `local://` plan before the next tool executes and supplies the complete snapshot, up to 128 KiB, as scoped classifier authority. Later plan-file edits do not expand authorization; a new Plan Mode approval is required. Missing, unreadable, malformed, or oversized plans grant no authority.

The Ask template shows a short fingerprint and a redacted argument summary capped at 512 characters. Before calling Ask, the agent must replace the designated preview placeholder with the same non-empty, single-line rationale in both options; the rationale is capped at 400 characters and remains explicitly non-authoritative. Auto Guard re-renders the complete expected input from its own template and the validated rationale before exact comparison. The full call digest remains internal.

Exact arguments do not freeze resources referenced by those arguments. A path, branch, tag, URL, database selection, or remote name may resolve to different state between approval and execution. Prefer immutable identifiers and tool-supported preconditions, such as commit SHAs, object versions, expected revisions, and conditional writes. Auto Guard cannot generically eliminate this time-of-check/time-of-use risk.

Tool arguments are classified in full after best-effort secret redaction. Inputs above 128 KiB are not classified from a partial representation; they require approval instead.

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
- Selected recent user and assistant conversation
- Immutable approved Plan Mode content, when active
- Project and global instructions extracted from the OMP system prompt
- Tool name and best-effort-redacted arguments
- Static policy observation

Redaction is not a reliable data-loss-prevention mechanism. Commands, paths, SQL, conversation text, and model responses may contain sensitive data. Configure classifier providers and credentials accordingly.

When audit logging is enabled, records include the classifier model, effort, latency, normalized token usage, tool name, policy observation, raw model response, and verdict. Invalid responses also include stop, error, and content-type diagnostics. `OMP_AUTO_GUARD_LOG_INCLUDE_CONTEXT=1` additionally records the classifier payload and full invalid response content blocks. Protect audit logs as sensitive data and do not commit them.

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

Deterministic shell and SQL patterns are defense in depth, not complete parsers. Ambiguous operations should be routed to semantic review rather than treated as proven safe.
Approval summaries deliberately limit conversation growth and may abbreviate long values. Review the visible effect-bearing fields and reject the call when the summary is insufficient to make an informed decision.

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
