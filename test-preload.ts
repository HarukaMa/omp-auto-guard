import { mock } from "bun:test";
import * as piAi from "@oh-my-pi/pi-ai";

for (const name of [
	"OMP_AUTO_GUARD_FAST_MODEL",
	"OMP_AUTO_GUARD_STRONG_MODEL",
	"OMP_AUTO_GUARD_FAST_EFFORT",
	"OMP_AUTO_GUARD_STRONG_EFFORT",
	"OMP_AUTO_GUARD_TIMEOUT_MS",
	"OMP_AUTO_GUARD_LOG_PATH",
	"OMP_AUTO_GUARD_LOG_INCLUDE_CONTEXT",
	"OMP_AUTO_GUARD_TIMING",
]) {
	delete process.env[name];
}

type CompleteImplementation = (...args: unknown[]) => unknown;

const defaultComplete: CompleteImplementation = () => {
	throw new Error("classifier should not run in approval workflow tests");
};
let completeImplementation = defaultComplete;

export function setCompleteImplementation(implementation = defaultComplete): void {
	completeImplementation = implementation;
}

mock.module("@oh-my-pi/pi-ai", () => ({
	...piAi,
	complete(...args: unknown[]) {
		return completeImplementation(...args);
	},
}));
