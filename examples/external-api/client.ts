import { User } from "better-auth";
import { createAuthClient } from "better-auth/client";
import { credentialsClient } from "../../src/credentials/client.js";
import { inferAdditionalFields } from "better-auth/client/plugins";
import { auth, myCustomSchema } from "./auth.js";

interface MyUser extends User {
    username?: string;
}

const port = process.env.PORT || 3000;

// Initialize the Better Auth client
export const authClient = createAuthClient({
    // The base URL of your Better Auth API
    baseURL: `http://localhost:${port}`,
    plugins: [
        // Initialize the client plugin with the correct generic types parameters:
        // 0: User -> The type of the user returned by the API
        // 1: "/sign-in/credentials" -> The path for the credentials sign-in endpoint
        // 2: typeof myCustomSchema -> The input schema for the credentials sign-in
        credentialsClient<MyUser, "/sign-in/external", typeof myCustomSchema>(),

        // https://www.better-auth.com/docs/concepts/typescript#inferring-additional-fields-on-client
        // This will infer the additional fields defined in the auth schema
        // and make them available on the client (e.g., `username`).
        inferAdditionalFields<typeof auth>(),
    ],
});

/*
// Example call to the login function
// Look how the client can use both the custom path and schema, as the types are inferred correctly
const { data, error } = await authClient.signIn.external({
    username: "external1",
    password: "password1"
});
*/