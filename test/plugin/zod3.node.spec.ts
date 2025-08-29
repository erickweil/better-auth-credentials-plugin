import { getTestInstance } from "@better-auth-kit/tests";
import { beforeAll, describe, expect, test } from "vitest";
import { defaultBetterAuthOptions } from "../plugin.js";
import { credentials, credentialsClient } from "../../index.js";
import { betterAuth, User } from "better-auth";
import { bearer } from "better-auth/plugins";
import { testCases } from "../test-helpers.js";
import * as z3 from "zod/v3";

describe("Should still work with zod v3 also", () => {

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
                providerId: "zodv3",
                inputSchema: z3.object({
                    email: z3.string().email().min(1),
                    name: z3.string().min(1).optional(),
                    senha: z3.string().min(8),
                    rememberMe: z3.boolean().optional(),
                }),
                callback(ctx, parsed) {
                    return {
                        email: parsed.email,
                        name: parsed.name
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
        { // Fail because no body
          body: { }, 
          match: {}
        },
        { // Fail because missing field
          body: {name: "test1", email: "zodtest1"}, 
          match: {}
        },
        { // Fail because password too short
          body: {name: "test1", email: "zodtest1", senha: "passw"}, 
          match: {}
        },
        { // Missing name, works???
          body: {email: "zodtest-no-name", senha: "password1"}, 
          match: {
            name: undefined,
            email: "zodtest-no-name",
            emailVerified: false
          }
        },
        {
          body: {name: "test1", email: "zodtest1", senha: "password1"}, 
          match: {
            name: "test1",
            email: "zodtest1",
            emailVerified: false
          }
        }        
      ], async ({body, match}) => {
        const credResult = await client.signIn.credentials({...body, email: body.email+"@zod.example.com"} as any);

        console.log("Credentials result:", credResult);

        let {data, error} = credResult;

        if(!error) {
            expect(data).toBeTruthy();
            expect(data?.user).toBeTruthy();
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
            expect(data).toBeNull();
            expect(match).toEqual({}); // in case of error, match should be empty
        }
        
    });
});