import { describe, expect, test } from "bun:test";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setCompleteImplementation } from "./test-preload";
import autoGuard, { CLASSIFIER_PROMPT, classifierTimeoutMs } from "./index";
import { MAX_CLASSIFIER_INPUT_BYTES } from "./policy";

interface ToolCall {
	toolCallId: string;
	toolName: string;
	input: Record<string, unknown>;
}

interface ToolCallResult {
	block?: boolean;
	reason?: string;
}

interface ToolResult {
	toolCallId: string;
	toolName: string;
	input: Record<string, unknown>;
	content: Array<{ type: "text"; text: string }>;
	details: unknown;
	isError: boolean;
}

interface ToolResultUpdate {
	content?: Array<{ type: "text"; text: string }>;
}

interface AskInput {
	questions: Array<{
		id: string;
		question: string;
		header?: string;
		options: Array<{ label: string; description?: string; preview?: string }>;
		multi?: boolean;
		recommended?: number;
	}>;
}

type ToolCallHandler = (event: ToolCall, context: unknown) => Promise<ToolCallResult | undefined>;
type ToolResultHandler = (event: ToolResult) => ToolResultUpdate | undefined | Promise<ToolResultUpdate | undefined>;

const ASK_INPUT_MARKER = "Native Ask input (use exactly after replacing the rationale placeholder):\n";
const RATIONALE_PREFIX = "Agent rationale (non-authoritative):\n";
const RATIONALE_PLACEHOLDER = "__OMP_AUTO_GUARD_AGENT_RATIONALE__";
const APPROVAL_CLEAR_EVENTS = [
	"session_start",
	"session_before_switch",
	"session_before_branch",
	"session_before_tree",
	"before_agent_start",
	"agent_end",
] as const;

function setupGuard(hasUI = true) {
	let toolCallHandler: ToolCallHandler | undefined;
	let toolResultHandler: ToolResultHandler | undefined;
	const sessionHandlers = new Map<string, () => void>();
	let confirmCalls = 0;
	let sendMessageCalls = 0;
	let pendingMessages = false;
	let branch: unknown[] = [];

	const pi = {
		on(event: string, handler: unknown) {
			if (event === "tool_call") toolCallHandler = handler as ToolCallHandler;
			if (event === "tool_result") toolResultHandler = handler as ToolResultHandler;
			if ((APPROVAL_CLEAR_EVENTS as readonly string[]).includes(event)) {
				sessionHandlers.set(event, handler as () => void);
			}
		},
		sendMessage() {
			sendMessageCalls += 1;
		},
	};
	const context = {
		cwd: "C:/workspace",
		hasPendingMessages() {
			return pendingMessages;
		},
		sessionManager: {
			getBranch() {
				return branch;
			},
		},
		hasUI,
		model: undefined as unknown,
		modelRegistry: {
			async getApiKey() {
				return "test-key";
			},
		},
		models: { resolve: () => undefined },
		getSystemPrompt() {
			return "";
		},
		ui: {
			confirm() {
				confirmCalls += 1;
				throw new Error("detached confirmation must not be used");
			},
			notify() {},
			setStatus() {},
		},
	};

	autoGuard(pi as never);
	if (!toolCallHandler) throw new Error("tool_call handler was not registered");
	if (!toolResultHandler) throw new Error("tool_result handler was not registered");
	for (const event of APPROVAL_CLEAR_EVENTS) {
		if (!sessionHandlers.has(event)) throw new Error(`${event} handler was not registered`);
	}
	return {
		context,
		get confirmCalls() {
			return confirmCalls;
		},
		get sendMessageCalls() {
			return sendMessageCalls;
		},
		setPendingMessages(value: boolean) {
			pendingMessages = value;
		},
		setBranch(value: unknown[]) {
			branch = value;
		},
		setCwd(value: string) {
			context.cwd = value;
		},
		setModel(value: unknown) {
			context.model = value;
		},
		sessionHandlers,
		toolCallHandler,
		toolResultHandler,
	};
}

function guardedRead(toolCallId: string, path = "C:/Users/me/.ssh/id_ed25519"): ToolCall {
	return {
		toolCallId,
		toolName: "read",
		input: { path, selector: "raw" },
	};
}

function extractAskInput(result: ToolCallResult | undefined): AskInput {
	const reason = result?.reason ?? "";
	const markerIndex = reason.indexOf(ASK_INPUT_MARKER);
	if (markerIndex < 0) throw new Error(`missing Ask payload in block reason: ${reason}`);
	return JSON.parse(reason.slice(markerIndex + ASK_INPUT_MARKER.length)) as AskInput;
}

function withAgentRationale(
	template: AskInput,
	rationale = "This exact call is needed to complete the requested operation.",
): AskInput {
	const input = structuredClone(template);
	for (const option of input.questions[0]?.options ?? []) {
		option.preview = `${RATIONALE_PREFIX}${rationale}`;
	}
	return input;
}

function askCall(toolCallId: string, input: AskInput): ToolCall {
	return { toolCallId, toolName: "ask", input: input as unknown as Record<string, unknown> };
}

function askDetails(
	input: AskInput,
	selectedOptions: string[],
	overrides: Record<string, unknown> = {},
): Record<string, unknown> {
	const question = input.questions[0];
	if (!question) throw new Error("expected one Ask question");
	return {
		question: question.question,
		options: question.options.map(option => option.label),
		multi: false,
		selectedOptions,
		...overrides,
	};
}

function askResult(
	toolCallId: string,
	input: AskInput,
	details: unknown,
	isError = false,
): ToolResult {
	return {
		toolCallId,
		toolName: "ask",
		input: input as unknown as Record<string, unknown>,
		content: [{ type: "text", text: "native Ask result" }],
		details,
		isError,
	};
}

async function beginHandshake(
	guard: ReturnType<typeof setupGuard>,
	call: ToolCall,
	askToolCallId: string,
): Promise<AskInput> {
	const blocked = await guard.toolCallHandler(call, guard.context);
	expect(blocked?.block).toBe(true);
	const input = withAgentRationale(extractAskInput(blocked));
	const allowedAsk = await guard.toolCallHandler(askCall(askToolCallId, input), guard.context);
	expect(allowedAsk).toBeUndefined();
	return input;
}

async function approveHandshake(
	guard: ReturnType<typeof setupGuard>,
	call: ToolCall,
	askToolCallId: string,
): Promise<{ askInput: AskInput; update: ToolResultUpdate | undefined }> {
	const askInput = await beginHandshake(guard, call, askToolCallId);
	const update = await guard.toolResultHandler(
		askResult(askToolCallId, askInput, askDetails(askInput, ["Approve once"], { timedOut: false })),
	);
	return { askInput, update };
}

describe("classifier authorization policy", () => {
	test("treats bounded remote reads as authorized work rather than a locality gate", () => {
		expect(CLASSIFIER_PROMPT).toContain("consequence-based safety review, not repeated permission checking");
		expect(CLASSIFIER_PROMPT).toContain('Phrases such as "check it" are authorization for those reads');
		expect(CLASSIFIER_PROMPT).toContain("SSH, remote execution, production, or shared infrastructure alone is never a reason to ask");
		expect(CLASSIFIER_PROMPT).toContain("bounded, non-sensitive reads");
		expect(CLASSIFIER_PROMPT).toContain("generic uncertainty is not enough");
		expect(CLASSIFIER_PROMPT).not.toContain("remote/shared/production changes");
	});

	test("still requires semantic review and explicit authorization for side effects", () => {
		expect(CLASSIFIER_PROMPT).toContain("Authoritative user excerpts are evidence of the user's intent and authorization");
		expect(CLASSIFIER_PROMPT).toContain("Inspect the complete command and its arguments for side effects");
		expect(CLASSIFIER_PROMPT).toContain("genuinely unclear whether a shell command writes state");
		expect(CLASSIFIER_PROMPT).toContain("specific material risk that is not already covered");
		expect(CLASSIFIER_PROMPT).toContain("explicitly requests or approves that operation");
		expect(CLASSIFIER_PROMPT).toContain("Merely mentioning, discussing, or asking about a possible mutation does not authorize it");
		expect(CLASSIFIER_PROMPT).toContain("do not ask again for individual deployment, restart, migration, remote-write");
		expect(CLASSIFIER_PROMPT).toContain("production/shared mutations require");
		expect(CLASSIFIER_PROMPT).toContain("immutable identifiers and tool-supported preconditions");
	});

	test("does not use mere irrelevance as a hard safety denial", () => {
		expect(CLASSIFIER_PROMPT).toContain("Mere task irrelevance or a low-consequence scope mismatch is never enough to deny");
		expect(CLASSIFIER_PROMPT).toContain("Task relevance alone is not a safety boundary");
	});
});

describe("classifier runtime limits", () => {
	test("keeps the default timeout and caps overrides below the host deadline", () => {
		expect(classifierTimeoutMs("not-a-number")).toBe(12_000);
		expect(classifierTimeoutMs("500")).toBe(1_000);
		expect(classifierTimeoutMs("60000")).toBe(28_000);
	});
	test("omits the output cap and logs invalid response diagnostics", async () => {
		const guard = setupGuard();
		const logPath = join(tmpdir(), `omp-auto-guard-${crypto.randomUUID()}.jsonl`);
		const previousLogPath = process.env.OMP_AUTO_GUARD_LOG_PATH;
		const previousIncludeContext = process.env.OMP_AUTO_GUARD_LOG_INCLUDE_CONTEXT;
		const content = [{ type: "thinking", thinking: "unfinished classifier response" }] as const;
		let requestOptions: Record<string, unknown> | undefined;

		process.env.OMP_AUTO_GUARD_LOG_PATH = logPath;
		process.env.OMP_AUTO_GUARD_LOG_INCLUDE_CONTEXT = "1";
		guard.setModel({ provider: "openai-codex", id: "gpt-5.6-terra", reasoning: true });
		setCompleteImplementation((...args) => {
			requestOptions = args[2] as Record<string, unknown>;
			return Promise.resolve({
				content,
				responseId: "response-1",
				stopReason: "length",
				usage: { input: 10, output: 300 },
			});
		});

		try {
			const result = await guard.toolCallHandler(
				{
					toolCallId: "invalid-classifier",
					toolName: "write",
					input: { path: "C:/tmp/output.txt", content: "test" },
				},
				guard.context,
			);
			expect(result?.block).toBe(true);
			expect(requestOptions).not.toHaveProperty("maxTokens");

			const record = JSON.parse((await Bun.file(logPath).text()).trim());
			expect(record.rawResponse).toBe("");
			expect(record.verdict.category).toBe("classifier-invalid");
			expect(record.invalidResponse).toMatchObject({
				responseId: "response-1",
				stopReason: "length",
				usage: { input: 10, output: 300 },
				contentTypes: ["thinking"],
				content,
			});
		} finally {
			setCompleteImplementation();
			if (previousLogPath === undefined) delete process.env.OMP_AUTO_GUARD_LOG_PATH;
			else process.env.OMP_AUTO_GUARD_LOG_PATH = previousLogPath;
			if (previousIncludeContext === undefined) delete process.env.OMP_AUTO_GUARD_LOG_INCLUDE_CONTEXT;
			else process.env.OMP_AUTO_GUARD_LOG_INCLUDE_CONTEXT = previousIncludeContext;
			await Bun.file(logPath).delete();
		}
	});
});

describe("native Ask approval retry", () => {
	test("blocks with an exact fail-safe Ask payload and never starts detached confirmation", async () => {
		const guard = setupGuard();
		const call = guardedRead("original-1");

		const blocked = await guard.toolCallHandler(call, guard.context);
		expect(blocked?.block).toBe(true);
		expect(blocked?.reason).toContain("Invoke the native ask tool exactly once");
		expect(blocked?.reason).toContain("Replace \"__OMP_AUTO_GUARD_AGENT_RATIONALE__\"");
		expect(blocked?.reason).toContain("Do not use resolve");
		const input = extractAskInput(blocked);
		expect(input.questions).toHaveLength(1);
		expect(input.questions[0]?.id).toStartWith("omp-auto-guard:");
		expect(input.questions[0]?.question).toContain("C:/Users/me/.ssh/id_ed25519");
		expect(input.questions[0]?.options.map(option => option.label)).toEqual(["Approve once", "Reject"]);
		expect(input.questions[0]?.multi).toBe(false);
		expect(input.questions[0]?.recommended).toBe(1);
		expect(guard.confirmCalls).toBe(0);
		expect(guard.sendMessageCalls).toBe(0);

		const askInput = withAgentRationale(input);
		const allowedAsk = await guard.toolCallHandler(askCall("ask-1", askInput), guard.context);
		expect(allowedAsk).toBeUndefined();
		const prematureRetry = await guard.toolCallHandler({ ...call, toolCallId: "original-2" }, guard.context);
		expect(prematureRetry?.block).toBe(true);
		expect(prematureRetry?.reason).toContain("waiting for the native Ask result");
	});
	test("keeps approval prompts compact and puts agent rationale in both previews", async () => {
		const guard = setupGuard();
		const blocked = await guard.toolCallHandler(
			{
				toolCallId: "compact-1",
				toolName: "custom_mutation",
				input: { command: `deploy ${"x".repeat(MAX_CLASSIFIER_INPUT_BYTES)}`, body: "y".repeat(10_000) },
			},
			guard.context,
		);
		const template = extractAskInput(blocked);
		const question = template.questions[0]!.question;
		const summary = question
			.split("Arguments (redacted summary; long values may be abbreviated):\n")[1]!
			.split("\n\nAllow this exact blocked tool call once?")[0]!;
		expect(summary.length).toBeLessThanOrEqual(512);
		expect(summary).toContain("command:");
		expect(summary).toContain("chars");
		expect(question).toMatch(/Call fingerprint: sha256:[0-9a-f]{16}/);
		expect(question).not.toContain("x".repeat(1_000));
		expect(template.questions[0]!.options.every(option => option.preview?.endsWith(RATIONALE_PLACEHOLDER))).toBe(
			true,
		);

		const input = withAgentRationale(template, "I need this exact mutation to finish the approved release.");
		expect(input.questions[0]!.options.map(option => option.preview)).toEqual([
			`${RATIONALE_PREFIX}I need this exact mutation to finish the approved release.`,
			`${RATIONALE_PREFIX}I need this exact mutation to finish the approved release.`,
		]);
		expect(await guard.toolCallHandler(askCall("compact-ask", input), guard.context)).toBeUndefined();
	});

	test("accepts only one bounded single-line rationale without other template changes", async () => {
		const guard = setupGuard();
		const call = guardedRead("rationale-1");
		const blocked = await guard.toolCallHandler(call, guard.context);
		const template = extractAskInput(blocked);
		const invalidInputs = [
			template,
			withAgentRationale(template, ""),
			withAgentRationale(template, "line one\nline two"),
			withAgentRationale(template, "x".repeat(401)),
			withAgentRationale(template, " padded "),
		];
		const unequal = withAgentRationale(template, "first");
		unequal.questions[0]!.options[1]!.preview = `${RATIONALE_PREFIX}second`;
		invalidInputs.push(unequal);
		const changed = withAgentRationale(template, "valid rationale");
		changed.questions[0]!.question += " changed";
		invalidInputs.push(changed);

		for (const [index, input] of invalidInputs.entries()) {
			const result = await guard.toolCallHandler(askCall(`invalid-rationale-${index}`, input), guard.context);
			expect(result?.block, String(index)).toBe(true);
			expect(result?.reason, String(index)).toContain("mismatched guard approval Ask");
		}

		const valid = withAgentRationale(template, "x".repeat(400));
		expect(await guard.toolCallHandler(askCall("valid-rationale", valid), guard.context)).toBeUndefined();
	});


	test("records an actual approval and grants one canonical exact retry", async () => {
		const guard = setupGuard();
		const call: ToolCall = {
			toolCallId: "original-1",
			toolName: "read",
			input: { selector: "raw", path: "C:/Users/me/.ssh/id_ed25519" },
		};
		const { update } = await approveHandshake(guard, call, "ask-1");
		expect(update?.content?.at(-1)?.text).toContain("recorded approval");
		expect(update?.content?.at(-1)?.text).toContain("single-use");

		const retry = await guard.toolCallHandler(
			{
				toolCallId: "original-2",
				toolName: call.toolName,
				input: { path: "C:/Users/me/.ssh/id_ed25519", selector: "raw" },
			},
			guard.context,
		);
		expect(retry).toBeUndefined();

		const replay = await guard.toolCallHandler({ ...call, toolCallId: "original-3" }, guard.context);
		expect(replay?.block).toBe(true);
		const replayAsk = extractAskInput(replay);
		expect(replayAsk.questions[0]?.id).toStartWith("omp-auto-guard:");
	});

	test("starts the five-minute permit window when approval is recorded", async () => {
		const realDateNow = Date.now;
		let now = 1_000_000;
		Date.now = () => now;
		try {
			const validGuard = setupGuard();
			const validCall = guardedRead("approval-time-valid-1");
			const validAsk = await beginHandshake(validGuard, validCall, "approval-time-valid-ask");
			now += 2 * 60 * 60_000;
			await validGuard.toolResultHandler(
				askResult(
					"approval-time-valid-ask",
					validAsk,
					askDetails(validAsk, ["Approve once"], { timedOut: false }),
				),
			);
			now += 5 * 60_000 - 1;
			expect(
				await validGuard.toolCallHandler(
					{ ...validCall, toolCallId: "approval-time-valid-2" },
					validGuard.context,
				),
			).toBeUndefined();

			const expiredGuard = setupGuard();
			const expiredCall = guardedRead("approval-time-expired-1");
			const expiredAsk = await beginHandshake(
				expiredGuard,
				expiredCall,
				"approval-time-expired-ask",
			);
			now += 2 * 60 * 60_000;
			await expiredGuard.toolResultHandler(
				askResult(
					"approval-time-expired-ask",
					expiredAsk,
					askDetails(expiredAsk, ["Approve once"], { timedOut: false }),
				),
			);
			now += 5 * 60_000 + 1;
			const expiredRetry = await expiredGuard.toolCallHandler(
				{ ...expiredCall, toolCallId: "approval-time-expired-2" },
				expiredGuard.context,
			);
			expect(expiredRetry?.block).toBe(true);
		} finally {
			Date.now = realDateNow;
		}
	});

	test("changed arguments do not consume the approved exact-call permit", async () => {
		const guard = setupGuard();
		const original = guardedRead("original-1");
		await approveHandshake(guard, original, "ask-1");

		const changed = await guard.toolCallHandler(
			guardedRead("changed-1", "C:/Users/me/.ssh/id_rsa"),
			guard.context,
		);
		expect(changed?.block).toBe(true);

		const originalRetry = await guard.toolCallHandler({ ...original, toolCallId: "original-2" }, guard.context);
		expect(originalRetry).toBeUndefined();
	});
	test("working-directory changes invalidate exact-call permits", async () => {
		const guard = setupGuard();
		const call = guardedRead("cwd-1");
		await approveHandshake(guard, call, "cwd-ask-1");
		guard.setCwd("C:/different-workspace");

		const retry = await guard.toolCallHandler({ ...call, toolCallId: "cwd-2" }, guard.context);
		expect(retry?.block).toBe(true);
		expect(extractAskInput(retry).questions[0]?.id).toStartWith("omp-auto-guard:");
	});

	test("pending input or advice invalidates permits and pauses execution", async () => {
		const guard = setupGuard();
		const call = guardedRead("pending-input-1");
		await approveHandshake(guard, call, "pending-input-ask-1");
		guard.setPendingMessages(true);

		const paused = await guard.toolCallHandler(
			{ ...call, toolCallId: "pending-input-2" },
			guard.context,
		);
		expect(paused?.block).toBe(true);
		expect(paused?.reason).toContain("queued input or an advisory is pending");

		guard.setPendingMessages(false);
		const retry = await guard.toolCallHandler(
			{ ...call, toolCallId: "pending-input-3" },
			guard.context,
		);
		expect(retry?.block).toBe(true);
	});
	test("discards an in-flight classifier result when user input arrives", async () => {
		const guard = setupGuard();
		const call: ToolCall = {
			toolCallId: "pending-classifier-1",
			toolName: "custom_mutation",
			input: { target: "shared-state" },
		};

		const inFlight = guard.toolCallHandler(call, guard.context);
		guard.setPendingMessages(true);
		const paused = await inFlight;
		expect(paused?.block).toBe(true);
		expect(paused?.reason).toContain("user input arrived while classification was in flight");

		guard.setPendingMessages(false);
		const retry = await guard.toolCallHandler(
			{ ...call, toolCallId: "pending-classifier-2" },
			guard.context,
		);
		expect(retry?.block).toBe(true);
	});




	test("preserves reserved object keys in exact-call identity", async () => {
		const guard = setupGuard();
		const original: ToolCall = {
			toolCallId: "original-proto-1",
			toolName: "read",
			input: JSON.parse(
				'{"path":"C:/Users/me/.ssh/id_ed25519","selector":"raw","__proto__":"approved"}',
			) as Record<string, unknown>,
		};
		const { askInput } = await approveHandshake(guard, original, "ask-proto-1");
		expect(askInput.questions[0]?.question).toContain("__proto__");

		const changedInput = JSON.parse(
			'{"path":"C:/Users/me/.ssh/id_ed25519","selector":"raw","__proto__":"changed"}',
		) as Record<string, unknown>;
		const changed = await guard.toolCallHandler(
			{ ...original, toolCallId: "changed-proto-1", input: changedInput },
			guard.context,
		);
		expect(changed?.block).toBe(true);
		expect(
			await guard.toolCallHandler({ ...original, toolCallId: "original-proto-2" }, guard.context),
		).toBeUndefined();
	});

	test("reject, timeout, cancellation, custom input, notes, and chat redirect never authorize", async () => {
		const cases: Array<{
			name: string;
			makeResult: (askToolCallId: string, input: AskInput) => ToolResult;
		}> = [
			{
				name: "reject",
				makeResult: (id, input) => askResult(id, input, askDetails(input, ["Reject"])),
			},
			{
				name: "timeout",
				makeResult: (id, input) =>
					askResult(id, input, askDetails(input, ["Approve once"], { timedOut: true })),
			},
			{
				name: "cancel",
				makeResult: (id, input) => askResult(id, input, undefined, true),
			},
			{
				name: "custom input",
				makeResult: (id, input) =>
					askResult(id, input, askDetails(input, ["Approve once"], { customInput: "approve" })),
			},
			{
				name: "qualified approval note",
				makeResult: (id, input) =>
					askResult(
						id,
						input,
						askDetails(input, ["Approve once"], { note: "only after creating a backup" }),
					),
			},
			{
				name: "chat redirect",
				makeResult: (id, input) =>
					askResult(id, input, { chatRedirect: true, questions: [input.questions[0]?.question] }),
			},
		];

		for (const [index, item] of cases.entries()) {
			const guard = setupGuard();
			const call = guardedRead(`original-${index}`);
			const askToolCallId = `ask-${index}`;
			const input = await beginHandshake(guard, call, askToolCallId);
			const update = await guard.toolResultHandler(item.makeResult(askToolCallId, input));
			expect(update?.content?.at(-1)?.text, item.name).toContain("did not record approval");
			const retry = await guard.toolCallHandler({ ...call, toolCallId: `retry-${index}` }, guard.context);
			expect(retry?.block, item.name).toBe(true);
			expect(extractAskInput(retry).questions[0]?.id, item.name).not.toBe(input.questions[0]?.id);
		}
	});

	test("wrong Ask payloads and call ids cannot mint a permit", async () => {
		const guard = setupGuard();
		const call = guardedRead("original-1");
		const blocked = await guard.toolCallHandler(call, guard.context);
		const template = extractAskInput(blocked);
		const expected = withAgentRationale(template);
		const wrong: AskInput = structuredClone(expected);
		wrong.questions[0]!.id = "ordinary-question";

		const mismatchedAsk = await guard.toolCallHandler(askCall("wrong-ask", wrong), guard.context);
		expect(mismatchedAsk?.block).toBe(true);
		expect(mismatchedAsk?.reason).toContain("mismatched guard approval Ask");
		expect(
			await guard.toolResultHandler(
				askResult("wrong-ask", wrong, askDetails(wrong, ["Approve once"], { timedOut: false })),
			),
		).toBeUndefined();
		const stillPending = await guard.toolCallHandler({ ...call, toolCallId: "original-2" }, guard.context);
		expect(extractAskInput(stillPending)).toEqual(template);

		expect(await guard.toolCallHandler(askCall("real-ask", expected), guard.context)).toBeUndefined();
		expect(
			await guard.toolResultHandler(
				askResult("different-id", expected, askDetails(expected, ["Approve once"], { timedOut: false })),
			),
		).toBeUndefined();
		const waiting = await guard.toolCallHandler({ ...call, toolCallId: "original-3" }, guard.context);
		expect(waiting?.reason).toContain("waiting for the native Ask result");

		const approved = await guard.toolResultHandler(
			askResult("real-ask", expected, askDetails(expected, ["Approve once"], { timedOut: false })),
		);
		expect(approved?.content?.at(-1)?.text).toContain("recorded approval");
		expect(await guard.toolCallHandler({ ...call, toolCallId: "original-4" }, guard.context)).toBeUndefined();
	});

	test("session and agent boundaries clear pending requests and approved permits", async () => {
		for (const [index, event] of APPROVAL_CLEAR_EVENTS.entries()) {
			const pendingGuard = setupGuard();
			const pendingCall = guardedRead(`pending-${index}`);
			const pending = await pendingGuard.toolCallHandler(pendingCall, pendingGuard.context);
			const oldPendingId = extractAskInput(pending).questions[0]?.id;
			pendingGuard.sessionHandlers.get(event)!();
			const afterPendingClear = await pendingGuard.toolCallHandler(
				{ ...pendingCall, toolCallId: `pending-retry-${index}` },
				pendingGuard.context,
			);
			expect(extractAskInput(afterPendingClear).questions[0]?.id, event).not.toBe(oldPendingId);

			const approvedGuard = setupGuard();
			const approvedCall = guardedRead(`approved-${index}`);
			await approveHandshake(approvedGuard, approvedCall, `approved-ask-${index}`);
			approvedGuard.sessionHandlers.get(event)!();
			const afterApprovedClear = await approvedGuard.toolCallHandler(
				{ ...approvedCall, toolCallId: `approved-retry-${index}` },
				approvedGuard.context,
			);
			expect(afterApprovedClear?.block, event).toBe(true);
		}
	});


	test("discards classifier completions after a lifecycle change", async () => {
		const guard = setupGuard();
		const classifiedCall: ToolCall = {
			toolCallId: "classified-1",
			toolName: "custom_mutation",
			input: { target: "shared-state" },
		};

		const inFlight = guard.toolCallHandler(classifiedCall, guard.context);
		guard.sessionHandlers.get("session_before_switch")!();
		const stale = await inFlight;
		expect(stale?.block).toBe(true);
		expect(stale?.reason).toContain("discarded a stale custom_mutation review");
		expect(stale?.reason).not.toContain(ASK_INPUT_MARKER);

		const fresh = await guard.toolCallHandler(
			{ ...classifiedCall, toolCallId: "classified-2" },
			guard.context,
		);
		expect(extractAskInput(fresh).questions[0]?.id).toStartWith("omp-auto-guard:");
	});

	test("requires approval without classification when the complete action is too large", async () => {
		const guard = setupGuard();
		const result = await guard.toolCallHandler(
			{
				toolCallId: "oversized-1",
				toolName: "custom_mutation",
				input: { command: "x".repeat(MAX_CLASSIFIER_INPUT_BYTES) },
			},
			guard.context,
		);
		expect(result?.block).toBe(true);
		expect(result?.reason).toContain("classifier-input-too-large");
		expect(extractAskInput(result).questions[0]?.question).toContain(
			`Tool arguments exceed the ${MAX_CLASSIFIER_INPUT_BYTES}-byte classifier limit`,
		);
	});

	test("fails closed without UI and creates no Ask handshake", async () => {
		const guard = setupGuard(false);
		const result = await guard.toolCallHandler(guardedRead("headless-1"), guard.context);
		expect(result?.block).toBe(true);
		expect(result?.reason).toContain("no interactive UI is available");
		expect(result?.reason).not.toContain(ASK_INPUT_MARKER);
		expect(guard.confirmCalls).toBe(0);
	});
});
