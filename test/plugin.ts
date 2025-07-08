import { betterAuth, BetterAuthPlugin, User } from "better-auth";
import { bearer } from "better-auth/plugins/bearer";
import { getTestInstance } from "@better-auth-kit/tests";
import { CredentialOptions, credentials, credentialsClient } from "../index.js";
import { MongoClient } from "mongodb";
import { mongodbAdapter } from "better-auth/adapters/mongodb";

// https://www.better-auth-kit.com/docs/libraries/tests
export const getPluginAuth = <T extends CredentialOptions<User, any, any>>(options: T) => {
	const client = new MongoClient(process.env.DB_URL_AUTH!);
	const db = client.db();

	// Create a better-auth instance
	return betterAuth({
		database: mongodbAdapter(db),
		plugins: [
			bearer(), 
			credentials(options)
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
	});
};