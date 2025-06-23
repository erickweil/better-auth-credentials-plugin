import { betterAuth, User } from "better-auth";
import { mongodbAdapter } from "better-auth/adapters/mongodb";
import { openAPI } from "better-auth/plugins";
import { MongoClient } from "mongodb";
import { credentials } from "../../src/credentials/index.js";
import { default as z } from "zod";

// https://www.better-auth.com/docs/adapters/mongo
// For MongoDB, we don't need to generate or migrate the schema.
const client = new MongoClient(process.env.DB_URL_AUTH!);
const db = client.db();

export const auth = betterAuth({
    database: mongodbAdapter(db),
    emailAndPassword: {
        // Disable email and password authentication
        // Users will both sign-in and sign-up via Credentials plugin
        enabled: false,
    },
    user: {
        additionalFields: {
            // Add additional fields to the user model
            username: {
                type: "string",
                returned: true,
                required: false,
            },
        }
    },
    plugins: [
        openAPI(),
        credentials({
            autoSignUp: true,
            inputSchema: z.object({
                username: z.string().min(1),
                password: z.string().min(1),
            }),
            // Credentials login callback, this is called when the user submits the form
            async callback(ctx, parsed) {
                // Simulate an external API call to authenticate the user
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

                const apiUser = await response.json();

                return {
                    // Must return email, because inputSchema doesn't have it
                    email: apiUser.email,

                    // Other user data to update
                    name: apiUser.name,
                    username: apiUser.username,
                };
            },
        })
    ],
});