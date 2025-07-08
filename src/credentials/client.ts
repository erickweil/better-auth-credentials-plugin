// Adaptado de: https://github.com/better-auth/better-auth/blob/main/packages/better-auth/src/plugins/username/client.ts
import { BetterAuthClientPlugin, User } from "better-auth";
import { default as z, ZodTypeAny } from "zod";

import type { credentials } from "./index.js";
import { defaultCredentialsSchema } from "./schema.js";

export const credentialsClient = <U extends User = User, P extends string = "/sign-in/credentials", Z extends ZodTypeAny = typeof defaultCredentialsSchema>() => {
	return {
		id: "credentials",
		$InferServerPlugin: {} as ReturnType<typeof credentials<U, P, Z>>,
	} satisfies BetterAuthClientPlugin;
};