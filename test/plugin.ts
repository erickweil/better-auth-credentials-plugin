import { betterAuth, BetterAuthClientOptions, BetterAuthOptions } from "better-auth";
import { testUtils } from "better-auth/plugins";
import { bearer } from "better-auth/plugins/bearer";
import { MongoClient } from "mongodb";
import { mongodbAdapter } from "better-auth/adapters/mongodb";

const client = new MongoClient(process.env.DB_URL_AUTH!);
const db = client.db();

export const defaultBetterAuthOptions = {
	database: mongodbAdapter(db),
	plugins: [
		bearer(),
		testUtils({}),
	],
	secret: "better-auth.secret",
	emailAndPassword: {
		enabled: true,
	},
	rateLimit: {
		enabled: false,
	},
	advanced: {
		disableCSRFCheck: true,
		cookies: {},
	},
} satisfies BetterAuthOptions;