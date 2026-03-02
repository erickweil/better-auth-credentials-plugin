import { getTestInstance } from "better-auth/test";
import { beforeAll, describe, expect, test } from "vitest";
import { defaultBetterAuthOptions } from "../plugin.js";
import { credentials, credentialsClient } from "../../index.js";
import { betterAuth, User } from "better-auth";
import { bearer } from "better-auth/plugins";
import { testCases } from "../test-helpers.js";

describe("Test with sign-up disabled", () => {

    let _instance = getTestInstance(
        {
            ...defaultBetterAuthOptions,
            plugins: [
                bearer(),
                credentials({
                    autoSignUp: false, // Sign-up is disabled
                    providerId: "disabled",
                    callback(ctx, parsed) {
                        return {
                            onSignIn(userData, user, account) {
                                if(!account) return null;

                                if (parsed.password !== account.password) {
                                    console.error("Authentication failed mismatch for email and password");
                                    return null;
                                }

                                return userData;
                            },
                        };
                    }
                }),
            ]
        },
        {
            clientOptions: {
                plugins: [credentialsClient()],
            },
        },
    );
    let instance: Awaited<typeof _instance>;

    beforeAll(async () => {
        instance = await _instance;
        const { client } = instance;

        const users = new Array(10).fill({}).map((_, index) => ({
            name: `Disabled User ${index + 1}`,
            email: `disabled${index + 1}@example.com`,
            password: `password${index + 1}`,
        }));
        // 1. Sign up test users using email and password directly in the database
        for(const user of users) {
            const userCreated = await instance.db.create({
                model: "user",
                data: {
                    name: user.name,
                    email: user.email,
                    emailVerified: false
                }
            });

            await instance.db.create({
                model: "account",
                data: {
                    providerId: "disabled",
                    accountId: user.email,
                    userId: userCreated.id,
                    password: user.password, // Store the password as plain text for testing purposes
                }
            });
        }

        //2. Sign up a user with email and password
        const {data,error} = await client.signUp.email({
            name: "Disabled User Existing",
            email: "disabled_existing@example.com",
            password: "abcdefgh"
        });
    });

    testCases("Test cases sign-up disabled", [
        { 
          status: 401, 
          body: {email: "disabled0@example.com", password: "password0"}, 
          match: {}
        },
        { 
          status: 401, 
          body: {email: "disabled1@example.com", password: "password?"}, 
          match: {}
        },
        { 
          status: 200, 
          body: {email: "disabled1@example.com", password: "password1"}, 
          match: { name: "Disabled User 1" }
        },
        { 
          status: 200, 
          body: {email: "disabled2@example.com", password: "password2"}, 
          match: { name: "Disabled User 2" }
        },      
        
        { 
          status: 401, 
          body: {email: "disabled_existing@example.com", password: "password0"}, 
          match: {}
        },
        { 
          status: 401, 
          body: {email: "disabled_existing@example.com", password: "abcdefgh"}, 
          match: {}
        },
      ], async ({status, body, match}) => {
        const { client } = instance;
        const { data, error } = await client.signIn.credentials(body);

        if(status >= 200 && status < 300) {
            expect(data).toBeTruthy();
            expect(data?.user).toBeTruthy();
            expect(data?.user).toMatchObject(match);
            expect(error).toBeNull();
        } else {
            expect(error).toBeTruthy();
            expect(error?.status).toBe(status);
            expect(data).toBeNull();
        }
    });
});