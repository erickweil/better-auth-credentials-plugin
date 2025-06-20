// Adaptado de: https://github.com/better-auth/better-auth/blob/main/packages/better-auth/src/plugins/username/client.ts
import { BetterAuthClientPlugin } from "better-auth";
import type { credentials } from "./index.js";

export const credentialsClient = () => {
	return {
		id: "credentials",
		$InferServerPlugin: {} as ReturnType<typeof credentials>,
	} satisfies BetterAuthClientPlugin;
};