export type GuardDecision = "allow" | "ask" | "deny" | "classify";

export interface GuardVerdict {
	decision: GuardDecision;
	category: string;
	reason: string;
}

export interface ClassifierVerdict {
	decision: "allow" | "ask" | "deny";
	category: string;
	reason: string;
	reviewId?: string;
}


export interface ConversationExcerpt {
	role: "user" | "assistant";
	authoritative: boolean;
	text: string;
}

export interface TechnicalExcerpt {
	toolName: string;
	isError: boolean;
	text: string;
}

export interface ApprovedPlanAmendment {
	approval: string;
	content: string;
}

export interface ApprovedPlanReference {
	markerId: string;
	path: string;
	kind: "approval" | "reference";
}

export type ClassifierTier = "fast" | "strong";
export const CLASSIFIER_EFFORTS = ["minimal", "low", "medium", "high", "xhigh", "max"] as const;
export type ConfiguredEffort = (typeof CLASSIFIER_EFFORTS)[number];

const FAST_SERENA_TOOL = /^mcp__serena_(?:insert_after_symbol|insert_before_symbol|replace_symbol_body|replace_content|replace_in_files|rename_symbol|safe_delete_symbol|edit_memory|write_memory)$/;

export function classifierTier(toolName: string): ClassifierTier {
	if (toolName === "edit" || toolName === "write" || toolName === "ast_edit" || toolName === "lsp") {
		return "fast";
	}
	if (FAST_SERENA_TOOL.test(toolName)) return "fast";
	return "strong";
}

export function classifierModelCandidates(tier: ClassifierTier, configuredModel?: string): string[] {
	const fallbackRoles = tier === "fast" ? ["pi/tiny", "pi/smol", "pi/default"] : ["pi/smol", "pi/default"];
	return [...new Set([configuredModel?.trim(), ...fallbackRoles].filter(Boolean) as string[])];
}

export function modelSpecEffort(
	modelSpec: string,
	resolvedModel: string,
): ConfiguredEffort | undefined {
	const normalized = modelSpec.trim();
	if (normalized === resolvedModel) return undefined;
	const match = normalized.match(/:(minimal|low|medium|high|xhigh|max)$/);
	return match?.[1] as ConfiguredEffort | undefined;
}

const SAFE_TOOLS = new Set([
	"ask",
	"ast_grep",
	"checkpoint",
	"glob",
	"grep",
	"inspect_image",
	"read",
	"recall",
	"reflect",
	"rewind",
	"search_tool_bm25",
	"todo",
	"web_search",
]);

const XDEV_BUILTIN_TOOLS: Record<string, true> = {
	ast_edit: true,
	ast_grep: true,
	browser: true,
	checkpoint: true,
	debug: true,
	github: true,
	inspect_image: true,
	lsp: true,
	memory_edit: true,
	recall: true,
	reflect: true,
	retain: true,
	rewind: true,
	web_search: true,
};

export function unwrapBuiltinXdevCall(
	toolName: string,
	input: Record<string, unknown>,
): { toolName: string; input: Record<string, unknown> } {
	const original = { toolName, input };
	if (toolName !== "write" || typeof input.path !== "string" || typeof input.content !== "string") {
		return original;
	}
	const path = input.path.trim();
	if (path.slice(0, 5).toLowerCase() !== "xd://") return original;
	const mountedToolName = path.slice(5);
	if (XDEV_BUILTIN_TOOLS[mountedToolName] !== true) return original;
	try {
		const mountedInput: unknown = JSON.parse(input.content);
		if (!mountedInput || typeof mountedInput !== "object" || Array.isArray(mountedInput)) return original;
		return { toolName: mountedToolName, input: mountedInput as Record<string, unknown> };
	} catch {
		return original;
	}
}

const READ_ONLY_LSP_ACTIONS = new Set([
	"capabilities",
	"definition",
	"diagnostics",
	"hover",
	"implementation",
	"references",
	"status",
	"symbols",
	"type_definition",
]);

const READ_ONLY_DEBUG_ACTIONS = new Set([
	"disassemble",
	"loaded_sources",
	"modules",
	"output",
	"read_memory",
	"scopes",
	"sessions",
	"stack_trace",
	"threads",
	"variables",
]);

const SENSITIVE_PATH = /(?:^|[\\/])(?:\.env(?:\.|$)|\.ssh(?:[\\/]|$)|\.aws(?:[\\/]|$)|\.kube(?:[\\/]|$)|credentials(?:\.|$)|id_(?:rsa|ecdsa|ed25519)(?:\.|$)|\.npmrc$|\.pypirc$)/i;
const METADATA_URL = /https?:\/\/(?:169\.254\.169\.254|metadata\.google\.internal)(?:[\/:]|$)/i;
const DATABASE_TOOL = /(?:database|postgres|psql|mysql|mariadb|sqlite|redis|mongo|clickhouse|snowflake|bigquery|sql)/i;
const DATABASE_CLIENT = /\b(?:psql|mysql|mariadb|sqlite3|redis-cli|mongosh|clickhouse-client|bq)\b/i;

const CATASTROPHIC_SHELL_PATTERNS: readonly [RegExp, string][] = [
	[/\brm\s+(?:-[^\s]*r[^\s]*f|-[^\s]*f[^\s]*r|--recursive\s+--force|--force\s+--recursive)\s+(?:--no-preserve-root\s+)?\/(?:\s|$)/i, "recursive deletion of the filesystem root"],
	[/\bmkfs(?:\.[a-z0-9]+)?\s+\/dev\//i, "formatting a block device"],
	[/\b(?:shutdown|poweroff|reboot|halt)\b/i, "host shutdown or restart"],
	[/\bdd\b[^\n]*\bof=\/dev\/(?:sd|nvme|vd|xvd|mmcblk)/i, "raw write to a block device"],
	[/\b(?:curl|wget)\b[^\n|;&]*(?:\||&&|;)\s*(?:sudo\s+)?(?:bash|sh|zsh|pwsh|powershell)\b/i, "remote content executed directly by a shell"],
];

const SUSPICIOUS_DATABASE_PATTERNS: readonly [RegExp, string][] = [
	[/\bdrop\b/i, "DROP"],
	[/\btruncate\b/i, "TRUNCATE"],
	[/\bflushall\b/i, "FLUSHALL"],
	[/\bdb\s*\.\s*dropDatabase\s*\(/i, "db.dropDatabase()"],
];

const SQL_ARGUMENT_KEY = /^(?:command|query|queryText|sql|statement)$/i;
const REDACTED_KEY = /(?:authorization|cookie|credential|password|private.?key|secret|token|api.?key)/i;
export const MAX_CLASSIFIER_INPUT_BYTES = 128 * 1024;

function verdict(decision: GuardDecision, category: string, reason: string): GuardVerdict {
	return { decision, category, reason };
}

function scalarStrings(value: unknown, output: string[]): void {
	if (typeof value === "string") {
		output.push(value);
		return;
	}
	if (Array.isArray(value)) {
		for (const item of value) scalarStrings(item, output);
		return;
	}
	if (value && typeof value === "object") {
		for (const item of Object.values(value as Record<string, unknown>)) scalarStrings(item, output);
	}
}

function namedStrings(value: unknown, keyPattern: RegExp, output: string[]): void {
	if (Array.isArray(value)) {
		for (const item of value) namedStrings(item, keyPattern, output);
		return;
	}
	if (!value || typeof value !== "object") return;
	for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
		if (keyPattern.test(key) && typeof item === "string") output.push(item);
		else namedStrings(item, keyPattern, output);
	}
}


export function inspectSql(sql: string): GuardVerdict {
	for (const [pattern, keyword] of SUSPICIOUS_DATABASE_PATTERNS) {
		if (pattern.test(sql)) {
			return verdict(
				"classify",
				"database-suspicious",
				`SQL contains suspicious ${keyword} text; determine whether it is executable, quoted, or commented`,
			);
		}
	}
	return verdict("classify", "database", "complete SQL requires dialect-aware semantic review");
}

function inspectSensitiveRead(input: Record<string, unknown>): GuardVerdict | undefined {
	const strings: string[] = [];
	scalarStrings(input, strings);
	const joined = strings.join("\n");
	if (SENSITIVE_PATH.test(joined)) {
		return verdict("ask", "sensitive-read", "reading a credential or secret-bearing path requires review");
	}
	if (METADATA_URL.test(joined)) {
		return verdict("deny", "credential-access", "cloud instance metadata access is blocked");
	}
	return undefined;
}

function inspectDatabaseCall(toolName: string, input: Record<string, unknown>): GuardVerdict | undefined {
	const execution =
		toolName === "eval"
			? typeof input.code === "string"
				? input.code
				: ""
			: typeof input.command === "string"
				? input.command
				: "";
	const databaseContext = DATABASE_TOOL.test(toolName) || DATABASE_CLIENT.test(execution);
	if (!databaseContext) return undefined;

	const queries: string[] = [];
	namedStrings(input, SQL_ARGUMENT_KEY, queries);
	return inspectSql([...queries, execution].join("\n"));
}


interface AskOptionContext {
	label: string;
	description?: string;
	preview?: string;
}

interface AskQuestionContext {
	id: string;
	question: string;
	options: AskOptionContext[];
}

interface AskCallContext {
	id: string;
	questions: AskQuestionContext[];
}

interface AskAnswerContext {
	question: AskQuestionContext;
	selectedOptions: string[];
	customInput?: string;
	note?: string;
	timedOut: boolean;
}

function parseAskCall(item: unknown): AskCallContext | undefined {
	if (!item || typeof item !== "object") return undefined;
	const call = item as Record<string, unknown>;
	if (call.type !== "toolCall" || call.name !== "ask" || typeof call.id !== "string") return undefined;
	if (!call.arguments || typeof call.arguments !== "object") return undefined;
	const questions = (call.arguments as Record<string, unknown>).questions;
	if (!Array.isArray(questions)) return undefined;
	const parsedQuestions: AskQuestionContext[] = [];
	for (const rawQuestion of questions) {
		if (!rawQuestion || typeof rawQuestion !== "object") continue;
		const question = rawQuestion as Record<string, unknown>;
		if (typeof question.id !== "string" || typeof question.question !== "string") continue;
		const options: AskOptionContext[] = [];
		if (Array.isArray(question.options)) {
			for (const rawOption of question.options) {
				if (!rawOption || typeof rawOption !== "object") continue;
				const option = rawOption as Record<string, unknown>;
				if (typeof option.label !== "string") continue;
				options.push({
					label: option.label,
					...(typeof option.description === "string" ? { description: option.description } : {}),
					...(typeof option.preview === "string" ? { preview: option.preview } : {}),
				});
			}
		}
		parsedQuestions.push({ id: question.id, question: question.question, options });
	}
	return parsedQuestions.length > 0 ? { id: call.id, questions: parsedQuestions } : undefined;
}

function parseAskAnswers(message: Record<string, unknown>, call: AskCallContext): AskAnswerContext[] {
	if (message.isError === true || !message.details || typeof message.details !== "object") return [];
	const details = message.details as Record<string, unknown>;
	if (details.chatRedirect === true) return [];
	const rawResults = Array.isArray(details.results) ? details.results : [details];
	const answers: AskAnswerContext[] = [];
	for (let index = 0; index < rawResults.length; index++) {
		const rawResult = rawResults[index];
		if (!rawResult || typeof rawResult !== "object") continue;
		const result = rawResult as Record<string, unknown>;
		const question =
			typeof result.id === "string"
				? call.questions.find(candidate => candidate.id === result.id)
				: call.questions.length === 1
					? call.questions[0]
					: call.questions[index];
		if (!question) continue;
		const validOptions = new Set(question.options.map(option => option.label));
		const selectedOptions = Array.isArray(result.selectedOptions)
			? result.selectedOptions.filter(
					(option): option is string => typeof option === "string" && validOptions.has(option),
				)
			: [];
		const customInput = typeof result.customInput === "string" ? result.customInput : undefined;
		const note = typeof result.note === "string" ? result.note : undefined;
		const timedOut = result.timedOut === true;
		if (selectedOptions.length === 0 && customInput === undefined && note === undefined && !timedOut) continue;
		answers.push({ question, selectedOptions, customInput, note, timedOut });
	}
	return answers;
}

function formatAskQuestion(answer: AskAnswerContext): string {
	const selected = new Set(answer.selectedOptions);
	const orderedOptions = [
		...answer.question.options.filter(option => selected.has(option.label)),
		...answer.question.options.filter(option => !selected.has(option.label)),
	];
	const options = orderedOptions.map(option => {
		const marker = selected.has(option.label) ? " [selected]" : "";
		const description = option.description ? ` - ${option.description}` : "";
		const preview = option.preview ? `\n  Preview: ${option.preview}` : "";
		return `- ${option.label}${marker}${description}${preview}`;
	});
	return [`Ask UI question: ${answer.question.question}`, "Options:", ...options].join("\n");
}

function formatAskResponse(answer: AskAnswerContext): string {
	const lines = [answer.timedOut ? "Ask UI auto-selection (not a user choice):" : "Ask UI user response:"];
	if (answer.selectedOptions.length > 0) lines.push(`User selected: ${answer.selectedOptions.join(", ")}`);
	if (answer.customInput !== undefined) lines.push(`User provided custom input: ${answer.customInput}`);
	if (answer.note !== undefined) lines.push(`User added note: ${answer.note}`);
	return lines.join("\n");
}

const APPROVED_PLAN_PROMPT = /^Plan approved\.\n(?:- Context preserved\. Use conversation history when useful; the plan file is the source of truth if it conflicts with earlier exploration\.\n)?\n<instruction>\nYou MUST read `(local:\/\/[^`\r\n]+)` before executing\.\nThe file content is the authoritative plan; visible\/compressed context is secondary\.\nRead failure\? Report the exact path and error instead of guessing\.\nAfter reading, you MUST execute the plan step by step with full tool access\.\nYou MUST verify each step before proceeding to the next\.\n(?:After reading the plan, initialize todo tracking with `todo`\.\nAfter each completed step, immediately update `todo`\.\nIf `todo` fails, fix the payload and retry before continuing\.\n)?<\/instruction>\n\n<critical>\nNEVER stop because inline plan content is compressed, expired, or unrecoverable\. Read `\1`\.\nYou MUST keep going until complete\. This matters\.\n<\/critical>\n?$/;
const APPROVED_PLAN_REFERENCE_PROMPT = /^## Existing Plan\n\nThe approved plan file is at `(local:\/\/[^`\r\n]+)`\.\n\n<instruction>\nIf this plan is relevant to current work and not complete, you MUST continue executing it\.\nIf you do not have the current plan content in visible context, you MUST read `\1`\.\nIf the plan is stale or unrelated, you MUST ignore it\.\nNEVER stop because inline plan content is compressed, expired, or unrecoverable\. Read the file\.\n<\/instruction>\n?$/;

type IndexedApprovedPlanReference = ApprovedPlanReference & { index: number };

function indexedApprovedPlanReferences(entries: readonly unknown[]): IndexedApprovedPlanReference[] {
	const references: IndexedApprovedPlanReference[] = [];
	for (let index = 0; index < entries.length; index++) {
		const entry = entries[index];
		if (!entry || typeof entry !== "object") continue;
		const record = entry as Record<string, unknown>;
		if (typeof record.id !== "string") continue;

		if (record.type === "message" && record.message && typeof record.message === "object") {
			const message = record.message as Record<string, unknown>;
			if (message.role !== "developer" || message.attribution !== "agent" || !Array.isArray(message.content)) {
				continue;
			}
			if (message.content.length !== 1) continue;
			const item = message.content[0];
			if (!item || typeof item !== "object") continue;
			const content = item as Record<string, unknown>;
			if (content.type !== "text" || typeof content.text !== "string") continue;
			const match = content.text.match(APPROVED_PLAN_PROMPT);
			if (match?.[1]) references.push({ markerId: record.id, path: match[1], kind: "approval", index });
			continue;
		}

		if (
			record.type === "custom_message" &&
			record.customType === "plan-mode-reference" &&
			record.attribution === "agent" &&
			typeof record.content === "string"
		) {
			const match = record.content.match(APPROVED_PLAN_REFERENCE_PROMPT);
			if (match?.[1]) references.push({ markerId: record.id, path: match[1], kind: "reference", index });
		}
	}
	return references;
}

export function approvedPlanReference(entries: readonly unknown[]): ApprovedPlanReference | undefined {
	const reference = indexedApprovedPlanReferences(entries).at(-1);
	return reference
		? { markerId: reference.markerId, path: reference.path, kind: reference.kind }
		: undefined;
}

const APPROVAL_REFERENCE_PATTERN = /(?:^|\b)(?:approv(?:e|ed|al)|authoriz(?:e|ed|ation)|plan[- ]batch|lgtm|proceed|go ahead|do it|continue|execute|ship it|let'?s do (?:it|this))(?:\b|$)/i;

type ConversationCandidate = ConversationExcerpt & {
	index: number;
	pairedAssistantIndex?: number;
};

function truncateExcerpt(text: string, limit: number): string {
	if (limit <= 0) return "";
	if (text.length <= limit) return text;
	const marker = "\n...[TRUNCATED]...\n";
	if (limit <= marker.length + 2) return text.slice(-limit);
	const available = limit - marker.length;
	const headLength = Math.ceil(available / 2);
	return `${text.slice(0, headLength)}${marker}${text.slice(-(available - headLength))}`;
}

function plainMessageText(message: Record<string, unknown>): string {
	if (!Array.isArray(message.content)) return "";
	return message.content
		.filter(item => item && typeof item === "object" && (item as Record<string, unknown>).type === "text")
		.map(item => String((item as Record<string, unknown>).text ?? ""))
		.join("\n")
		.trim();
}

export function approvedPlanAmendments(entries: readonly unknown[]): ApprovedPlanAmendment[] {
	const references = indexedApprovedPlanReferences(entries);
	const currentReference = references.at(-1);
	let baselineIndex = currentReference?.index ?? -1;
	if (currentReference?.kind === "reference") {
		for (let index = references.length - 1; index >= 0; index--) {
			const reference = references[index]!;
			if (
				reference.index <= currentReference.index &&
				reference.kind === "approval" &&
				reference.path === currentReference.path
			) {
				baselineIndex = reference.index;
				break;
			}
		}
	}

	const assistantMessages: Array<{ index: number; text: string }> = [];
	const pairs: Array<{ approval: string; content: string; assistantIndex: number }> = [];
	const pairedAssistants = new Set<number>();
	for (let index = baselineIndex + 1; index < entries.length; index++) {
		const entry = entries[index];
		if (!entry || typeof entry !== "object") continue;
		const record = entry as Record<string, unknown>;
		if (record.type !== "message" || !record.message || typeof record.message !== "object") continue;
		const message = record.message as Record<string, unknown>;
		const text = plainMessageText(message);
		if (!text) continue;
		if (message.role === "assistant") {
			assistantMessages.push({ index, text });
			continue;
		}
		if (message.role !== "user" || message.synthetic === true || !APPROVAL_REFERENCE_PATTERN.test(text)) continue;
		const assistant = assistantMessages.at(-1);
		if (!assistant || pairedAssistants.has(assistant.index)) continue;
		pairs.push({ approval: text, content: assistant.text, assistantIndex: assistant.index });
		pairedAssistants.add(assistant.index);
	}

	const amendments: ApprovedPlanAmendment[] = [];
	let remainingCharacters = 6000;
	for (const pair of pairs.reverse()) {
		if (amendments.length >= 4 || remainingCharacters <= 0) break;
		const approval = truncateExcerpt(pair.approval, Math.min(1000, remainingCharacters));
		remainingCharacters -= approval.length;
		const content = truncateExcerpt(pair.content, Math.min(3000, remainingCharacters));
		if (!content) break;
		remainingCharacters -= content.length;
		amendments.push({ approval, content });
	}
	return amendments;
}

export function recentConversation(entries: readonly unknown[]): ConversationExcerpt[] {
	const candidates: ConversationCandidate[] = [];
	const askCalls = new Map<string, AskCallContext>();
	for (let index = 0; index < entries.length; index++) {
		const entry = entries[index];
		if (!entry || typeof entry !== "object") continue;
		const record = entry as Record<string, unknown>;
		if (record.type !== "message" || !record.message || typeof record.message !== "object") continue;
		const message = record.message as Record<string, unknown>;
		if (message.role === "assistant" && Array.isArray(message.content)) {
			for (const item of message.content) {
				const askCall = parseAskCall(item);
				if (askCall) askCalls.set(askCall.id, askCall);
			}
		}
		if (
			message.role === "toolResult" &&
			message.toolName === "ask" &&
			typeof message.toolCallId === "string" &&
			askCalls.has(message.toolCallId)
		) {
			const askCall = askCalls.get(message.toolCallId)!;
			if (askCall.questions.some(question => question.id.startsWith("omp-auto-guard:"))) continue;
			const answers = parseAskAnswers(message, askCall);
			for (let answerIndex = 0; answerIndex < answers.length; answerIndex++) {
				const answer = answers[answerIndex]!;
				const denominator = answers.length * 2 + 1;
				const questionIndex = index + (answerIndex * 2 + 1) / denominator;
				candidates.push({
					index: questionIndex,
					role: "assistant",
					authoritative: false,
					text: formatAskQuestion(answer),
				});
				candidates.push({
					index: index + (answerIndex * 2 + 2) / denominator,
					pairedAssistantIndex: questionIndex,
					role: "user",
					authoritative: !answer.timedOut,
					text: formatAskResponse(answer),
				});
			}
			continue;
		}
		if ((message.role !== "user" && message.role !== "assistant") || !Array.isArray(message.content)) continue;
		const text = message.content
			.filter(item => item && typeof item === "object" && (item as Record<string, unknown>).type === "text")
			.map(item => String((item as Record<string, unknown>).text ?? ""))
			.join("\n")
			.trim();
		if (!text) continue;
		candidates.push({
			index,
			role: message.role,
			authoritative: message.role === "user" && message.synthetic !== true,
			text,
		});
	}

	const selected: ConversationCandidate[] = [];
	const selectedIndices = new Set<number>();
	const addCandidates = (
		source: ConversationCandidate[],
		characterBudget: number,
		messageBudget: number,
	): void => {
		let remainingCharacters = characterBudget;
		let remainingMessages = messageBudget;
		for (const candidate of source) {
			if (remainingCharacters <= 0 || remainingMessages <= 0) break;
			if (selectedIndices.has(candidate.index)) continue;
			const limit = Math.min(3000, remainingCharacters);
			const text = truncateExcerpt(candidate.text, limit);
			selected.push({ ...candidate, text });
			selectedIndices.add(candidate.index);
			remainingCharacters -= text.length;
			remainingMessages--;
		}
	};

	const authoritativeUsers = candidates.filter(candidate => candidate.authoritative).reverse();
	addCandidates(authoritativeUsers, 6000, 8);
	const approvedPlans: ConversationCandidate[] = [];
	for (const userMessage of authoritativeUsers.slice(0, 8)) {
		if (userMessage.pairedAssistantIndex !== undefined) {
			const pairedQuestion = candidates.find(candidate => candidate.index === userMessage.pairedAssistantIndex);
			if (pairedQuestion) approvedPlans.push(pairedQuestion);
			continue;
		}
		if (!APPROVAL_REFERENCE_PATTERN.test(userMessage.text)) continue;
		for (let index = candidates.length - 1; index >= 0; index--) {
			const candidate = candidates[index];
			if (candidate.index >= userMessage.index || candidate.role !== "assistant") continue;
			approvedPlans.push(candidate);
			break;
		}
	}
	const recentNonAuthoritative = candidates.filter(candidate => !candidate.authoritative).reverse();
	addCandidates([...approvedPlans, ...recentNonAuthoritative], 6000, 8);
	return selected
		.sort((left, right) => left.index - right.index)
		.map(({ role, authoritative, text }) => ({ role, authoritative, text }));
}

export function recentTechnicalContext(entries: readonly unknown[]): TechnicalExcerpt[] {
	const selected: Array<TechnicalExcerpt & { index: number }> = [];
	let remainingCharacters = 8000;
	for (let index = entries.length - 1; index >= 0; index--) {
		if (selected.length >= 16 || remainingCharacters <= 0) break;
		const entry = entries[index];
		if (!entry || typeof entry !== "object") continue;
		const record = entry as Record<string, unknown>;
		if (record.type !== "message" || !record.message || typeof record.message !== "object") continue;
		const message = record.message as Record<string, unknown>;
		if (message.role !== "toolResult" || message.toolName === "ask" || typeof message.toolName !== "string") continue;
		const text = plainMessageText(message);
		if (!text) continue;
		const excerpt = truncateExcerpt(String(redactForClassifier(text)), Math.min(500, remainingCharacters));
		selected.push({
			index,
			toolName: message.toolName,
			isError: message.isError === true,
			text: excerpt,
		});
		remainingCharacters -= excerpt.length;
	}
	return selected
		.reverse()
		.map(({ toolName, isError, text }) => ({ toolName, isError, text }));
}

function taggedSection(text: string, tag: string): string | undefined {
	const startMarker = `<${tag}>`;
	const endMarker = `</${tag}>`;
	const start = text.indexOf(startMarker);
	const end = text.lastIndexOf(endMarker);
	if (start < 0 || end < start) return undefined;
	return text.slice(start, end + endMarker.length).trim();
}

export function selectClassifierInstructions(systemPrompt: readonly string[]): string[] {
	const selected: string[] = [];
	for (const block of systemPrompt) {
		const text = block.trim();
		if (!text) continue;

		const stockOmpPrompt =
			text.includes("<system-conventions>") &&
			text.includes("ROLE\n==============") &&
			text.includes("TOOL POLICY\n==============") &&
			!text.includes("<file path=");
		if (stockOmpPrompt) {
			for (const tag of ["generic-rules", "domain-rules"]) {
				const section = taggedSection(text, tag);
				if (section) selected.push(section);
			}
			continue;
		}

		if (/^PROJECT\n=+/i.test(text)) {
			const criticalMarker = "\n<critical>\n- Each response MUST advance the task.";
			const criticalStart = text.indexOf(criticalMarker);
			const criticalEnd = criticalStart < 0 ? -1 : text.indexOf("</critical>", criticalStart);
			if (criticalEnd < 0) {
				selected.push(text);
				continue;
			}
			for (const tag of ["context", "dir-context", "repo-rules"]) {
				const section = taggedSection(text.slice(0, criticalStart), tag);
				if (section) selected.push(section);
			}
			const appendPrompt = text.slice(criticalEnd + "</critical>".length).trim();
			if (appendPrompt) selected.push(appendPrompt);
			continue;
		}

		if (text.startsWith("<active-repo-context>") && text.endsWith("</active-repo-context>")) continue;
		selected.push(text);
	}
	return selected;
}

const READ_ONLY_SERENA_TOOL = /^mcp__serena_(?:initial_instructions|get_symbols_overview|find_symbol|find_referencing_symbols|find_implementations|find_declaration|get_diagnostics_for_file|read_memory)$/;

export function inspectToolCall(toolName: string, input: Record<string, unknown>): GuardVerdict {
	if (toolName === "ask") return verdict("allow", "interactive", "native user prompt");
	if (SAFE_TOOLS.has(toolName)) {
		return inspectSensitiveRead(input) ?? verdict("allow", "read", "read-only tool");
	}
	if (READ_ONLY_SERENA_TOOL.test(toolName)) {
		return verdict("allow", "read", "read-only Serena operation");
	}
	if (toolName === "browser" && input.action === "close") {
		return verdict("allow", "local-cleanup", "closing a browser session");
	}

	if (toolName === "lsp") {
		const action = typeof input.action === "string" ? input.action : "";
		if (READ_ONLY_LSP_ACTIONS.has(action)) return verdict("allow", "read", "read-only LSP action");
	}

	if (toolName === "debug") {
		const action = typeof input.action === "string" ? input.action : "";
		if (READ_ONLY_DEBUG_ACTIONS.has(action)) return verdict("allow", "read", "read-only debugger action");
	}

	if (["bash", "ssh", "eval"].includes(toolName)) {
		const execution =
			toolName === "eval"
				? typeof input.code === "string"
					? input.code
					: ""
				: typeof input.command === "string"
					? input.command
					: "";
		for (const [pattern, reason] of CATASTROPHIC_SHELL_PATTERNS) {
			if (pattern.test(execution)) return verdict("deny", "host", reason);
		}
	}

	const database = inspectDatabaseCall(toolName, input);
	if (database) return database;

	if (toolName === "ssh") {
		return verdict(
			"classify",
			"remote-shell",
			"classify the concrete command effects; bounded non-sensitive remote reads are ordinarily allowed",
		);
	}
	return verdict("classify", "stateful", "stateful or unknown tool requires semantic review");
}

export function redactForClassifier(value: unknown): unknown {
	if (typeof value === "string") {
		return value
			.replace(/\bBearer\s+[^\s,;]+/gi, "Bearer [REDACTED]")
			.replace(
				/(\b(?:authorization|password|passwd|token|api[_-]?key|secret)\b\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,;]+)/gi,
				"$1[REDACTED]",
			)
			.replace(/(https?:\/\/[^:\s/@]+:)[^@\s/]+@/gi, "$1[REDACTED]@");
	}
	if (typeof value === "number" || typeof value === "boolean" || value === null) return value;
	if (Array.isArray(value)) return value.map(redactForClassifier);
	if (value && typeof value === "object") {
		const result = Object.create(null) as Record<string, unknown>;
		for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
			result[key] = REDACTED_KEY.test(key) ? "[REDACTED]" : redactForClassifier(item);
		}
		return result;
	}
	return String(value);
}

export function classifierInputBytes(value: unknown): number {
	return Buffer.byteLength(JSON.stringify(value) ?? "", "utf8");
}

export function parseClassifierVerdict(text: string): ClassifierVerdict | undefined {
	const match = text.match(/\{[\s\S]*\}/);
	if (!match) return undefined;
	try {
		const parsed = JSON.parse(match[0]) as Record<string, unknown>;
		if (!new Set(["allow", "ask", "deny"]).has(String(parsed.decision))) return undefined;
		if (typeof parsed.reason !== "string" || parsed.reason.trim().length === 0) return undefined;
		return {
			decision: parsed.decision as ClassifierVerdict["decision"],
			category: typeof parsed.category === "string" ? parsed.category.slice(0, 64) : "classified",
			reason: parsed.reason.trim().slice(0, 300),
		};
	} catch {
		return undefined;
	}
}
