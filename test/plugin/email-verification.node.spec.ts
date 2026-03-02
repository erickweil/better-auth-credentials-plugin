import { beforeAll, describe, expect, test } from "vitest";
import { defaultBetterAuthOptions } from "../plugin.js";
import { credentials, credentialsClient } from "../../index.js";

import { betterAuth, User } from "better-auth";
import { getTestInstance } from "better-auth/test";
import { bearer } from "better-auth/plugins";

describe("Test using the plugin with email verification ON", () => {

    let lastEmailSent: { user: User; url: string; token: string } | null = null;

    const _instance = getTestInstance(
        {
        ...defaultBetterAuthOptions,
        emailAndPassword: {
            enabled: true,
            requireEmailVerification: true
        },
        emailVerification: {
            sendVerificationEmail: async ({user, url, token}: {user: User; url: string; token: string}) => {
                console.log("Sending verification email to:", user.email);
                // This is just a test, we don't actually send an email
                lastEmailSent = {
                    user,
                    url,
                    token
                };
            },
            onEmailVerification: async (user: User, request?: Request) => {
                console.log("Email verification completed for user:", user.email);
            },
            sendOnSignUp: true,
            autoSignInAfterVerification: true
        },
        plugins: [
            bearer(),
            credentials({
                autoSignUp: true,
                providerId: "email",
                callback(ctx, parsed) {
                    if (parsed.email !== parsed.password) {
                        throw new Error("Authentication failed, please try again.");
                    }

                    return {};
                }
            }),
        ]
    }, { clientOptions: { plugins: [credentialsClient()] } }
    );

    let client: (Awaited<typeof _instance>)["client"];

    beforeAll(async () => {
        let instance = await _instance;
        client = instance.client;
    });

    test("Test new user", async () => {
        // Wrong password on new user
        {
        const {data, error} = await client.signIn.credentials({
            email: "email_user1@example.com",
            password: "wrong-password"
        });

        expect(error).toBeTruthy();
        expect(data).toBeNull();
        expect(error?.status).toBe(401);
        }

        // Sign up, should send verification email
        {
        const {data, error} = await client.signIn.credentials({
            email: "email_user1@example.com",
            password: "email_user1@example.com"
        });

        expect(error).toBeNull();
        const user = data?.user;
        const token = data?.token;
        expect(user).toBeTruthy();
        expect(user!.name).toBeUndefined();
        expect(token).toBeNull(); // Should not be able to sign in yet because email verification is required
        expect(lastEmailSent).toBeTruthy(); // Should have sent a verification email
        }

        // Try to sign in but email verification is required
        {
        const {data, error} = await client.signIn.credentials({
            email: "email_user1@example.com",
            password: "email_user1@example.com"
        });

        expect(error).toBeTruthy();
        expect(data).toBeNull();
        expect(error?.status).toBe(403);
        expect(error?.code).toBe("EMAIL_NOT_VERIFIED");
        }

        // Verify e-mail
        {
        const { data, error} = await client.verifyEmail({
            query: {
                token: lastEmailSent!.token
            }
        });

        expect(error).toBeNull();
        expect(data).toBeTruthy();
        expect(data!.status).toBe(true);
        }

        // Check if now is able to sign in
        {
        const {data, error} = await client.signIn.credentials({
            email: "email_user1@example.com",
            password: "email_user1@example.com"
        });

        expect(error).toBeNull();
        const user = data?.user;
        const token = data?.token;
        expect(user).toBeTruthy();
        expect(user!.name).toBeUndefined();
        expect(user!.emailVerified).toBe(true);
        
        expect(token).toBeTruthy();
        }
    });
});