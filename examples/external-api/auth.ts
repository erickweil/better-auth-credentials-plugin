import { betterAuth, User } from "better-auth";
import { bearer, customSession, openAPI } from "better-auth/plugins";
import { credentials } from "../../src/credentials/index.js";
import * as z from "zod";

export const myCustomSchema = z.object({
    username: z.string().min(1),
    password: z.string().min(1),
});

export const auth = betterAuth({
    database: undefined, // No database adapter for stateless mode
    emailAndPassword: {
        // Disable email and password authentication
        // Users will both sign-in and sign-up via Credentials plugin
        enabled: false,
    },
    session: {
        expiresIn: 60 * 10, // 10 minutes
        disableSessionRefresh: true,
        cookieCache: {
            enabled: true,
            strategy: "jwt", // can be "jwe", "jwt" or "compact"
        },
    },
    // account: {
    //     storeStateStrategy: "cookie",
    //     storeAccountCookie: true, // Store account data after OAuth flow in a cookie (useful for database-less flows)
    // },
    user: {
        additionalFields: {
            // Add additional fields to the user model
            username: {
                type: "string",
                returned: true,
                required: false
            },
            // In stateless mode, every login is a new user with its own data, so we can store the token here while also allowing multiple sessions per external api user.
            token: {
                type: "string",
                returned: true,
                required: false
            }
        }
    },
    plugins: [
        openAPI(),
        bearer(),
        credentials({
            autoSignUp: true,
            providerId: "external-api",
            path: "/sign-in/external",
            inputSchema: myCustomSchema,
            UserType: {} as User & { username?: string },
            // Credentials login callback, this is called when the user submits the form
            async callback(ctx, parsed) {
                // Make an external API call to authenticate the user
                const { username, password } = parsed;
                const response = await fetch(`http://localhost:${process.env.PORT || 3000}/example/login`, {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                    },
                    body: JSON.stringify({ username, password }),
                });

                if (!response.ok) {
                    throw new Error("Error authenticating:"+ ` ${response.status} ${response.statusText}`);
                }

                const {token, user: apiUser} = await response.json();

                return {
                    // Must return email, because inputSchema doesn't have it
                    email: apiUser.email,
                    // Store the token in the user to use it later for authenticated requests to the external API
                    token: token,

                    // Other user data to update
                    name: apiUser.name,
                    username: apiUser.username,
                };
            },
        })
    ],
});