// Test to see if this plugin is compatible with username plugin from better-auth
import { getTestInstance } from "better-auth/test";
import { beforeAll, describe, expect, test } from "vitest";
import { defaultBetterAuthOptions } from "../plugin.js";
import { credentials, credentialsClient } from "../../index.js";
import { betterAuth, User } from "better-auth";
import { bearer, username } from "better-auth/plugins";
import { usernameClient } from "better-auth/client/plugins";

describe("Test check to see if username plugin works with credentials", () => {

    const _instance = getTestInstance(
        {
        ...defaultBetterAuthOptions,
        emailAndPassword: {
            enabled: true,
            requireEmailVerification: false
        },
        plugins: [
            bearer(),
            credentials({
                UserType: {} as User & { username?: string },
                autoSignUp: true,
                linkAccountIfExisting: true,
                providerId: "username-credentials",
                callback(ctx, parsed) {
                    if (parsed.email !== parsed.password) {
                        throw new Error("Authentication failed, please try again.");
                    }

                    return {
                        username: parsed.email.split("@")[0]
                    };
                }
            }),
            username()
        ]
    }, { clientOptions: { plugins: [credentialsClient(), usernameClient()] } }
    );

    let client: (Awaited<typeof _instance>)["client"];

    beforeAll(async () => {
        let instance = await _instance;
        client = instance.client;
    });

    test("Test create new user with credentials", async () => {

        // Sign up with credentials
        {
        const {data, error} = await client.signIn.credentials({
            email: "user1@username.com",
            password: "user1@username.com"
        });

        expect(error).toBeNull();
        const user = data?.user;
        const token = data?.token;
        expect(user).toBeTruthy();
        expect(user!.name).toBeUndefined();
        expect(token).toBeTruthy();
        }

        // Sign in again with credentials (because yes)
        {
        const {data, error} = await client.signIn.credentials({
            email: "user1@username.com",
            password: "user1@username.com"
        });
        expect(error).toBeNull(); 
        const user = data?.user;
        const token = data?.token; 
        expect(user).toBeTruthy();
        expect(user!.name).toBeUndefined();
        expect(token).toBeTruthy();      
        }

        // Sign in with username, should give error because it was not created with email provider
        {
        const {data, error} = await client.signIn.username({
            username: "user1",
            password: "user1@username.com"
        });
        console.log(data, error);
        expect(error).toBeTruthy(); 
        expect(data).toBeNull();
        }
    });

    test("Test create new user with username, then link", async () => {
        let token: string | null | undefined;

        // Sign up with email/password
        {
        const {data, error} = await client.signUp.email({
            name: "Test User 2",
            username: "user2",
            email: "user2@username.com",
            password: "12345678",
        });
        expect(error).toBeNull();
        const user = data?.user;
        token = data?.token;
        expect(user).toBeTruthy();
        expect(user!.name).toBe("Test User 2");
        expect(token).toBeTruthy();
        }

        // Sign in with username
        {
        const {data, error} = await client.signIn.username({
            username: "user2",
            password: "12345678"
        });
        expect(error).toBeNull();
        const user = data?.user;
        const token2 = data?.token;
        expect(user).toBeTruthy();
        expect(user!.name).toBe("Test User 2");
        expect(token2).toBeTruthy();
        }

        // Link credentials to existing username account
        {
        const {data, error} = await client.signIn.credentials({
            email: "user2@username.com",
            password: "user2@username.com"
        });
        expect(error).toBeNull();
        const user = data?.user;
        const token2 = data?.token;
        expect(user).toBeTruthy();
        expect(user!.name).toBe("Test User 2");
        expect(token2).toBeTruthy();
        }
    });
});