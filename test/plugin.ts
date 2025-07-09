import { betterAuth, BetterAuthOptions, BetterAuthPlugin, User } from "better-auth";
import { bearer } from "better-auth/plugins/bearer";
import { getTestInstance } from "@better-auth-kit/tests";
import { CredentialOptions, credentials, credentialsClient } from "../index.js";
import { MongoClient } from "mongodb";
import { mongodbAdapter } from "better-auth/adapters/mongodb";

const client = new MongoClient(process.env.DB_URL_AUTH!);
const db = client.db();

export const defaultBetterAuthOptions: BetterAuthOptions = {
	database: mongodbAdapter(db),
	plugins: [
		bearer()
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
};