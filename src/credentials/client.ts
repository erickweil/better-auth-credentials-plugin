// Adaptado de: https://github.com/better-auth/better-auth/blob/main/packages/better-auth/src/plugins/username/client.ts
import { BetterAuthClientPlugin, BetterAuthOptions, User } from "better-auth";
import type { StandardSchemaV1 } from "@standard-schema/spec";

import type { credentials } from "./index.js";
import { defaultCredentialsSchema } from "./schema.js";

export const credentialsClient = <U extends User = User, P extends string = "/sign-in/credentials", Z extends StandardSchemaV1 = typeof defaultCredentialsSchema, O extends (BetterAuthOptions|undefined) = undefined>() => {
	return {
		id: "credentials",
		$InferServerPlugin: {} as ReturnType<typeof credentials<U, P, Z, O>>,
	} satisfies BetterAuthClientPlugin;
};