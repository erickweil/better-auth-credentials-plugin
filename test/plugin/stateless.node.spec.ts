import { beforeAll, describe, expect, test } from "vitest";
import { betterAuth } from "better-auth";
import { credentials, credentialsClient } from "../../index.js";
import { defaultBetterAuthOptions } from "../plugin.js";
import { bearer, TestHelpers, testUtils } from "better-auth/plugins";
import { getTestInstance } from "better-auth/test";

describe("Test using credentials plugin with Better Auth stateless mode", () => {
    const memoryStore: Record<string, any> = {};
    const _instance = getTestInstance({
        ...defaultBetterAuthOptions,
        database: undefined, // No database adapter for stateless mode
        session: {
            cookieCache: {
                enabled: true,
                maxAge: 60, // 60 seconds for testing purposes
                strategy: "jwt", // can be "jwe", "jwt" or "compact"
                refreshCache: {
                    updateAge: 59 // Refresh when 59 seconds remain (which is after 1 second has passed)
                }
            },
        },
        account: {
            storeStateStrategy: "cookie",
            //storeAccountCookie: true, // Store account data after OAuth flow in a cookie (useful for database-less flows)
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
    }, { clientOptions: { plugins: [credentialsClient()] } }
    );

    let client: (Awaited<typeof _instance>)["client"];
    
    beforeAll(async () => {
        let instance = await _instance;
        client = instance.client;
    });

    test("Should authenticate in stateless mode with credentials plugin", async () => {
        {
        const { data, error } = await client.signIn.credentials({
            email: "stateless@example.com",
            password: "stateless@example.com",
        });

        expect(error).toBeNull();
        expect(data?.token).toBeTruthy();
        expect(data?.user).toBeTruthy();
        expect(data?.user.email).toBe("stateless@example.com");
        expect(data?.user.name).toBe("stateless");
        }

        {
        const { data, error } = await client.signIn.credentials({
            email: "stateless@example.com",
            password: "invalid-password",
        });

        expect(error).toBeTruthy();
        expect(error?.status).toBe(401);
        expect(data).toBeNull();
        }
    });

    test("Simplified flow, no cookies, stateless mode with bearer plugin", async () => {
        // First authentication to get a token
        const { data: authData, error: authError } = await client.signIn.credentials({
            email: "refresh-test@example.com",
            password: "refresh-test@example.com",
        });
        console.log("Authentication data:", authData);
        expect(authError).toBeNull();
        expect(authData?.token).toBeTruthy();
        expect(authData?.user).toBeTruthy();

        // Check if session is still valid
        const { data: sessionData, error: sessionError } = await client.getSession({
            fetchOptions: {
                headers: {
                    Authorization: `Bearer ${authData?.token}`
                }
            }
        });
        console.log("Session data after authentication:", sessionData);
        expect(sessionError).toBeNull();
        expect(sessionData?.session.token).toBe(authData?.token);
        expect(sessionData?.user.id).toBe(authData?.user.id);
    });
});
