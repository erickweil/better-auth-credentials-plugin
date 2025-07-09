import { betterAuth, User } from "better-auth";
import { mongodbAdapter } from "better-auth/adapters/mongodb";
import { openAPI } from "better-auth/plugins";
import { MongoClient } from "mongodb";
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
            // Credentials login callback, this is called when the user submits the form
            async callback(ctx, parsed) {
                if (parsed.email !== parsed.password) {
                    throw new Error("Authentication failed, please try again.");
                }
                
                return {
                    // Called if this is a existing user sign-in
                    onSignIn(userData, user, account) {
                        console.log("Existing User signed in:", user);

                        return userData;
                    },

                    // Called if this is a new user sign-up (only used if autoSignUp is true)
                    onSignUp(userData) {
                        console.log("New User signed up:", userData.email);

                        return {
                            ...userData,
                            name: parsed.email.split("@")[0]
                        };
                    }
                };
            },
        })
    ],
});