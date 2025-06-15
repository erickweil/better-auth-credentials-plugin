// Adaptado de: https://github.com/better-auth/better-auth/blob/main/packages/better-auth/src/plugins/username/client.ts
import { BetterAuthClientPlugin } from "better-auth";
import type { ldap } from "./index.js";

export const ldapClient = () => {
	return {
		id: "ldap",
		$InferServerPlugin: {} as ReturnType<typeof ldap>,
	} satisfies BetterAuthClientPlugin;
};