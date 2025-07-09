import { betterAuth, User } from "better-auth";
import { APIError, EndpointContext } from "better-call";
import { mongodbAdapter } from "better-auth/adapters/mongodb";
import { openAPI } from "better-auth/plugins";
import { MongoClient } from "mongodb";
import * as argon2 from "argon2";
import { credentials } from "../../src/credentials/index.js";

// https://www.better-auth.com/docs/adapters/mongo
// For MongoDB, we don't need to generate or migrate the schema.
const client = new MongoClient(process.env.DB_URL_AUTH!);
const db = client.db();

export const auth = betterAuth({
    database: mongodbAdapter(db),
    emailAndPassword: {
        enabled: true,
    },
    plugins: [
        openAPI(),
        credentials({
            autoSignUp: true,
            linkAccountIfExisting: true,
            providerId: "hashing",
            // Credentials login callback, this is called when the user submits the form
            async callback(ctx, parsed) {
                const registerFn = (userData: Partial<User>, newUser: boolean) => {
                    if (parsed.password.length < 12) {
                        throw new APIError("BAD_REQUEST", { code: "WEAK_PASSWORD", message: "Password must be at least 12 characters long." });
                    }
                    if (!userData.name) {
                        userData.name = parsed.email.split("@")[0];
                    }
                    if (!userData.image) {
                        userData.image = newUser ? "http://example.com/new.png" : "http://example.com/linked.png";
                    }
                    return userData;
                };

                return {
                    async onSignIn(userData, user, account) {
                        if (!account) {
                            // Because linkAccountIfExisting is true, this can happen: 
                            // First time sign in using this provider, but on an existing user (created by another provider, email/password, social, etc...)
                            return registerFn(user, false);
                        }

                        // Check password
                        if(!account.password) {
                            // hash the password to prevent timing attacks
                            const hashedPassword = await argon2.hash(parsed.password);
                            throw new Error("Account password not found.");
                        }
                        if (!(await argon2.verify(account.password, parsed.password))) {
                            throw new Error("Password didn't match.");
                        }
                        // Password matches, return user data
                        return userData;
                    },
                    onSignUp(userData) {
                        // Account creation, sign up this provider and user
                        return registerFn(userData, true);
                    },
                    async onLinkAccount(user) {
                        // This callback can't throw errors, because the user already was created
                        return {
                            password: await argon2.hash(parsed.password),
                        };
                    },
                };
            },
        })
    ],
});