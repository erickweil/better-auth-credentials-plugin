import { beforeAll, describe, expect, test } from "vitest";
import { betterAuth } from "better-auth";
import { credentials } from "../../index.js";
import { defaultBetterAuthOptions } from "../plugin.js";
import { bearer, TestHelpers, testUtils } from "better-auth/plugins";

describe("Test using credentials plugin with Better Auth stateless mode", () => {
    const memoryStore: Record<string, any> = {};
    const auth = betterAuth({
        ...defaultBetterAuthOptions,
        database: undefined, // No database adapter for stateless mode
        session: {
            cookieCache: {
                enabled: true,
                maxAge: 1, // 60 seconds for testing purposes
                strategy: "jwt", // can be "jwe", "jwt" or "compact"
                refreshCache: false
            },
        },
        account: {
            storeStateStrategy: "cookie",
            storeAccountCookie: true, // Store account data after OAuth flow in a cookie (useful for database-less flows)
        },
        /*secondaryStorage: {
            get: async (key) => {
                return memoryStore[key];
            },
            set: async (key, value, options) => {
                memoryStore[key] = value;
            },
            delete: async (key) => {
                delete memoryStore[key];
            },
        },*/
        plugins: [
		    bearer(),
		    testUtils({}),
            credentials({
                autoSignUp: true,
                providerId: "stateless",
                callback(ctx, parsed) {
                    if (parsed.email !== parsed.password) {
                        return null;
                    }

                    return {
                        email: parsed.email,
                        name: parsed.email.split("@")[0]
                    };
                },
            }),
        ],
    });

    let instance: TestHelpers;
    beforeAll(async () => {
        const ctx = await auth.$context;
        instance = ctx.test;
    });

    test("Should authenticate in stateless mode with credentials plugin", async () => {
        const success = await auth.api.signInCredentials({
            body: {
                email: "stateless@example.com",
                password: "stateless@example.com",
            },
        });

        expect(success.token).toBeTruthy();
        expect(success.user).toBeTruthy();
        expect(success.user.email).toBe("stateless@example.com");
        expect(success.user.name).toBe("stateless");

        const invalid = await auth.api.signInCredentials({
            body: {
                email: "stateless@example.com",
                password: "invalid-password",
            },
            asResponse: true,
        });

        expect(invalid.status).toBe(401);
    });

    test("Should handle cookie cache refresh in stateless mode", async () => {
        // First authentication to get a token
        const response = await auth.api.signInCredentials({
            body: {
                email: "refresh-test@example.com",
                password: "refresh-test@example.com",
            }
        });
        expect(response.token).toBeTruthy();
        expect(response.user).toBeTruthy();

        {
            const headers = await instance.getAuthHeaders({
                userId: response.user.id
            });
            const testSessionFn = async () => {
                // Check if session is still valid
                let session = await auth.api.getSession({
                    headers: headers,
                    returnHeaders: true
                });
                expect(session.response?.session).toBeTruthy();
                return session.response;
            };
            
            const sessionResponse = await testSessionFn();            
        }
    });
});
