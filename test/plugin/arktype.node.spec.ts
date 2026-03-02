import { getTestInstance } from "better-auth/test";
import { beforeAll, describe, expect, test } from "vitest";
import { defaultBetterAuthOptions } from "../plugin.js";
import { credentials, credentialsClient } from "../../index.js";
import { bearer } from "better-auth/plugins";
import { testCases } from "../test-helpers.js";
import { type } from "arktype";
import { User } from "better-auth";

describe("Should work with arktype also (Standard Schema)", () => {

    const userArkType = type({
        email: "string.email",
        senha: "string >= 8",
        "name?": "string > 0 | undefined",
        "rememberMe?": "boolean | undefined"
    });

    const _instance = getTestInstance(
        {
        ...defaultBetterAuthOptions,
        emailAndPassword: {
            enabled: true
        },
        plugins: [
            bearer(),
            credentials({
                autoSignUp: true,
                providerId: "arktype",
                inputSchema: userArkType,
                callback(ctx, parsed) {
                    if(parsed.senha !== "password1") {
                        throw new Error("Invalid password");
                    }
                    return {
                        email: parsed.email,
                        name: parsed.name
                    };
                }
            })
        ]
    }, { clientOptions: { plugins: [credentialsClient<User, "/sign-in/credentials", typeof userArkType>()] } }
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
          body: {name: "test1", email: "arktest1"}, 
          match: {}
        },
        { // Fail because password too short
          body: {name: "test1", email: "arktest1", senha: "passw"}, 
          match: {}
        },
        { // Missing name, works???
          body: {email: "arktest-no-name", senha: "password1"}, 
          match: {
            name: undefined,
            email: "arktest-no-name",
            emailVerified: false
          }
        },
        {
          body: {name: "test1", email: "arktest1", senha: "password1"}, 
          match: {
            name: "test1",
            email: "arktest1",
            emailVerified: false
          }
        }        
      ], async ({body, match}) => {
        const credResult = await client.signIn.credentials({...body, email: body.email+"@ark.example.com"} as any);

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