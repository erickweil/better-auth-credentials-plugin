import { getTestInstance } from "@better-auth-kit/tests";
import { beforeAll, describe, expect, test } from "vitest";
import { defaultBetterAuthOptions } from "../plugin.js";
import { credentials, credentialsClient } from "../../index.js";
import { betterAuth, User } from "better-auth";
import { APIError } from "better-call";
import { bearer } from "better-auth/plugins";
import { testCases } from "../test-helpers.js";
import * as z from "zod";

describe("Test comparison login with email & password vs credentials, should behave similar", () => {

    const _email = "@email.example.com";
    const _cred = "@credential.example.com";

    const _instance = getTestInstance(
        betterAuth({
        ...defaultBetterAuthOptions,
        emailAndPassword: {
            enabled: true
        },
        plugins: [
            bearer(),
            credentials({
                autoSignUp: true,
                providerId: "behaviour",
                inputSchema: z.object({
                    email: z.email().min(1),
                    name: z.string().min(1).optional(),
                    password: z.string().min(1),
                    rememberMe: z.boolean().optional(),
                }),
                callback(ctx, parsed) {
                    return {
                        onSignIn(userData, user, account) {
                            if(!account) return null;

                            if (parsed.password !== account.password) {
                                console.error("Authentication failed mismatch for email and password");
                                return null;
                            }

                            return {};
                        },
                        onSignUp(userData) {
                            if(parsed.password.length < 8) {
                                throw new APIError("BAD_REQUEST", { message: "Password must be at least 8 characters long." });
                            }
                            return {
                                ...userData,
                                name: parsed.name
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
    }), { clientOptions: { plugins: [credentialsClient()] } }
    );

    let client: (Awaited<typeof _instance>)["client"];

    beforeAll(async () => {
        let instance = await _instance;
        client = instance.client;
    });

    testCases("Test cases, comparison of behaviour, signUp cases", [
        { // Fail because password too short
          signUp: true,
          statusEmail: 400, 
          statusCred: 400,
          body: {name: "test1", email: "test1", password: "passw"}, 
          match: {}
        },
        { // Missing name, on newer better-auth versions name is required
          // But on ours credentials plugin we will allow users without name 
          signUp: true,
          statusEmail: 400,
          statusCred: 200,
          body: {email: "test-no-name", password: "password1"}, 
          match: {
            name: undefined,
            email: "test-no-name",
            emailVerified: false
          }
        },
        { 
          signUp: true,
          statusEmail: 200, 
          statusCred: 200,
          body: {name: "test1", email: "test1", password: "password1"}, 
          match: {
            name: "test1",
            email: "test1",
            emailVerified: false
          }
        },
        { 
          signUp: true,
          statusEmail: 200, 
          statusCred: 200,
          body: {name: "test2", email: "TEST2", password: "password2"}, 
          match: {
            name: "test2",
            email: "test2",
            emailVerified: false
          }
        },
        { // Email & password fail because signup duplicated email, credentials fail because password mismatch
          signUp: true,
          statusEmail: 422,
          statusCred: 401,
          body: {name: "test1", email: "TEST1", password: "password2"}, 
          match: {}
        },

        // Sign In cases
        { // Fail because password wrong
          signUp: false,
          statusEmail: 401, 
          statusCred: 401,
          body: {email: "test1", password: "wrong-password"},
          match: {}
        },
        { 
          signUp: false,
          statusEmail: 200, 
          statusCred: 200,
          body: {email: "test1", password: "password1"},
          match: {
            name: "test1",
            email: "test1",
            emailVerified: false
          }
        },
        // Email should be case insensitive
        { 
          signUp: false,
          statusEmail: 200, 
          statusCred: 200,
          body: {email: "test2", password: "password2"},
          match: {
            name: "test2",
            email: "test2",
            emailVerified: false
          }
        },
        { 
          signUp: false,
          statusEmail: 200, 
          statusCred: 200,
          body: {email: "TEST2", password: "password2"},
          match: {
            name: "test2",
            email: "test2",
            emailVerified: false
          }
        },
        
      ], async ({signUp, statusEmail, statusCred, body, match}) => {
        const emailResult = signUp ? 
              await client.signUp.email({...body, email: body.email+_email} as any) 
            : await client.signIn.email({...body, email: body.email+_email} as any);
        const credResult = await client.signIn.credentials({...body, email: body.email+_cred});

        console.log("Email result:", emailResult);
        console.log("Credentials result:", credResult);

        for(let {data, error, status} of [{...emailResult, status: statusEmail}, {...credResult, status: statusCred}]) {
            if(status >= 200 && status < 300) {
                expect(data).toBeTruthy();
                expect(data?.user).toBeTruthy();
                //expect(data?.user).toMatchObject(match);
                for(const key of Object.keys(match)) {
                    if(key === "email") {
                        expect(data?.user.email.startsWith(match.email!)).toBe(true);
                    } else {
                        expect((data as any)?.user[key]).toBe((match as any)[key]);
                    }
                }
                expect(error).toBeNull();
            } else {
                expect(error).toBeTruthy();
                expect(error?.status).toBe(status);
                expect(data).toBeNull();
            }
        }
    });
});