import { beforeAll, describe, expect, test } from "vitest";
import { defaultBetterAuthOptions } from "../plugin.js";
import { credentials, credentialsClient } from "../../index.js";
import { betterAuth, User } from "better-auth";
import * as z from "zod";
import { bearer, TestHelpers, testUtils } from "better-auth/plugins";

describe("Test using the plugin in the client", () => {
    const schema = z.object({
        _email: z.email(),
        _password: z.string().min(1, "Password is required"),
    });

    const auth = betterAuth({
        ...defaultBetterAuthOptions,
        plugins: [
            bearer(),
		    testUtils({}),
            credentials({
                autoSignUp: true,
                path: "/sign-in/my-login",
                providerId: "my-login",
                inputSchema: schema,            
                callback(ctx, parsed) {
                    if (parsed._email !== parsed._password) {
                        console.error("Authentication failed mismatch for email and password");
                        return null; // It is possible to return null to indicate failure
                    } else {
                        return {
                            email: parsed._email,
                            name: parsed._email.split("@")[0]
                        };
                    }
                }
            }),
        ]
    });

    let instance: TestHelpers;
    beforeAll(async () => {
        const ctx = await auth.$context;
        instance = ctx.test;
    });

    test("Should be able to authenticate", async () => {
        const { user } = await auth.api.signInCredentials({
            body: {
                _email: "plugin_user@example.com",
                _password: "plugin_user@example.com"
            },
        });

        expect(user).toBeDefined();
        expect(user?.email).toBe("plugin_user@example.com");
        expect(user?.name).toBe("plugin_user");
    });

    test("Should'nt authenticate", async () => {
        const response = await auth.api.signInCredentials({
            body: {
                _email: "plugin_user@example.com",
                _password: "wrong-password"
            }, 
            asResponse: true
        });

        expect(response.status).toBe(401);
    });

    test("Should'nt authenticate, existing user different provider", async () => {
        await auth.api.signUpEmail({
            body: {
                name: "plugin_user2",
                email: "plugin_user2@example.com",
                password: "plugin_user2@example.com"
            }
        });

        const response = await auth.api.signInCredentials({
            body: {
                _email: "plugin_user2@example.com",
                _password: "plugin_user2@example.com"
            },
            asResponse: true
        });

        expect(response.status).toBe(401);
    });
});