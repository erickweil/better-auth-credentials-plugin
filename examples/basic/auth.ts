import { betterAuth } from "better-auth";
import { mongodbAdapter } from "better-auth/adapters/mongodb";
import { openAPI } from "better-auth/plugins";
import { MongoClient } from "mongodb";
import { credentials } from "../../src/credentials/index.js";

// https://www.better-auth.com/docs/adapters/mongo
// For MongoDB, we don't need to generate or migrate the schema.
const client = new MongoClient(process.env.DB_URL_AUTH!);
const db = client.db();

const usersFakeStore: Record<string, Record<string,string>> = {
    "test1@example.com": {
        name: "Test User 1",
        image: "https://randomuser.me/api/portraits/lego/1.jpg",
        password: "password1"
    },
    "test2@example.com": {
        name: "Test User 2",
        image: "https://randomuser.me/api/portraits/lego/2.jpg",
        password: "password2"
    },
    "test3@example.com": {
        name: "Test User 3",
        image: "https://randomuser.me/api/portraits/lego/3.jpg",
        password: "password3"
    },
};

export const auth = betterAuth({
    database: mongodbAdapter(db),
    emailAndPassword: {
        // Disable email and password authentication
        // Users will both sign-in and sign-up via LDAP
        enabled: false,
    },
    plugins: [
        openAPI(),
        credentials({
            autoSignUp: true,
            // Credentials login callback, this is called when the user submits the form
            async callback(ctx, parsed) {
                // Simulate a user lookup in a fake store
                const foundUser = usersFakeStore[parsed.email];
                if (!foundUser) {
                    throw new Error("User not found");
                }
                // Check if the password matches
                if (foundUser.password !== parsed.password) {
                    throw new Error("Invalid password");
                }
                
                return {
                    // Must return email to find/create the user
                    email: parsed.email,

                    // Called if this is a existing user sign-in
                    onSignIn(userData, user, account) {
                        return userData;
                    },

                    // Called if this is a new user sign-up (only used if autoSignUp is true)
                    onSignUp(userData) {
                        userData.name =  foundUser.name;
                        userData.image = foundUser.image;
                        userData.emailVerified = false;
                        return userData;
                    }
                };
            },
        })
    ],
});