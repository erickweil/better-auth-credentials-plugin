import { getTestInstance } from "better-auth/test";
import { beforeAll, describe, expect, test } from "vitest";
import { defaultBetterAuthOptions } from "../plugin.js";
import { credentials, credentialsClient } from "../../index.js";

import { APIError, EndpointContext } from "better-call";
import { betterAuth, User } from "better-auth";
import { bearer } from "better-auth/plugins";

describe("Test using the plugin with custom Account linking attributes", () => {
    const _instance = getTestInstance(
        {
        ...defaultBetterAuthOptions,
        plugins: [
            bearer(),
            credentials({
                autoSignUp: true,
                linkAccountIfExisting: true,
                providerId: "link",
                callback(ctx, parsed) {
                    const registerFn = () => {
                        if(parsed.password.length < 12) {
                            throw new APIError("BAD_REQUEST", { code: "WEAK_PASSWORD", message: "Password must be at least 12 characters long." });
                        }
                    };

                    return {
                        onSignIn(userData, user, account) {
                            if(!account) { 
                                // Account linking, first time sign in this provider on an existing user
                                registerFn();
                                if(!user.image) {
                                    userData.image = "http://example.com/linked.png";
                                }
                                return userData;
                            }

                            // Check password
                            if(parsed.password !== account.password) {
                                throw new Error("Password didn't match.");
                            }
                            return userData;
                        },
                        onSignUp(userData) {
                            // Account creation, sign up this provider and user
                            registerFn();
                            return {
                                ...userData,
                                name: parsed.email.split("@")[0],
                                image: "http://example.com/new.png",
                            };
                        },
                        // This callback can't throw errors, because the user already was created
                        onLinkAccount(user) {
                            // THIS IS JUST FOR TESTING PURPOSES, REAL USE CASES SHOULD STORE HASHED PASSWORDS
                            return {
                                password: parsed.password,
                            };
                        },
                    };
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
        // Weak password on new user
        {
        const {data, error} = await client.signIn.credentials({
            email: "link_user1@example.com",
            password: "12345678"
        });

        expect(error).toBeDefined();
        expect(data).toBeNull();
        expect(error?.status).toBe(401);
        expect(error?.code).toBe("INVALID_CREDENTIALS");
        }

        // Sign up, then repeat for sign in
        for(let i = 0; i < 2; i++) {
            const {data, error} = await client.signIn.credentials({
                email: "link_user1@example.com",
                password: "123456789012"
            });

            expect(error).toBeNull();
            const user = data?.user;
            expect(user).toBeDefined();
            expect(user!.email).toBe("link_user1@example.com");
            expect(user!.name).toBe("link_user1");
            expect(user!.image).toBe("http://example.com/new.png");
        }

        // Wrong password on sign in
        {
        const {data, error} = await client.signIn.credentials({
            email: "link_user1@example.com",
            password: "abcdefgh"
        });

        expect(error).toBeDefined();
        expect(data).toBeNull();
        expect(error?.status).toBe(401);
        }
    });

    test("Test link Account existing user", async () => {
        // new account default credentials provider
        {
        const {data,error} = await client.signUp.email({
            name: "Link User 2",
            email: "link_user2@example.com",
            password: "abcdefgh"
        });

        expect(error).toBeNull();
        expect(data).toBeDefined();
        }

        // Weak password on link user
        {
        const {data, error} = await client.signIn.credentials({
            email: "link_user2@example.com",
            password: "abcdefgh"
        });

        expect(error).toBeDefined();
        expect(data).toBeNull();
        expect(error?.status).toBe(401);
        expect(error?.code).toBe("INVALID_CREDENTIALS");
        }

        // Link account, then repeat for sign in
        for(let i = 0; i < 2; i++) {
            const {data, error} = await client.signIn.credentials({
                email: "link_user2@example.com",
                password: "123456789012"
            });
            
            expect(error).toBeNull();
            const user = data?.user;
            expect(user).toBeDefined();
            expect(user!.email).toBe("link_user2@example.com");
            expect(user!.name).toBe("Link User 2");
            expect(user!.image).toBe("http://example.com/linked.png");
        }


        // Wrong password on sign in
        {
        const {data, error} = await client.signIn.credentials({
            email: "link_user2@example.com",
            password: "abcdefgh"
        });

        expect(error).toBeDefined();
        expect(data).toBeNull();
        expect(error?.status).toBe(401);
        }
    });
});