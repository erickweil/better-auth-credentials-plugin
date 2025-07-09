import { getTestInstance } from "@better-auth-kit/tests";
import { beforeAll, describe, expect, test } from "vitest";
import { defaultBetterAuthOptions } from "../plugin.js";
import { credentials, credentialsClient } from "../../index.js";
import { betterAuth, User } from "better-auth";
import z3 from "zod";
import { bearer } from "better-auth/plugins";

describe("Test using the plugin in the client", () => {
    const schema = z3.object({
        _email: z3.string().email(),
        _password: z3.string().min(1, "Password is required"),
    });

    let _instance = getTestInstance(
        betterAuth({
            ...defaultBetterAuthOptions,
            plugins: [
                bearer(),
                credentials({
                    autoSignUp: true,
                    path: "/sign-in/my-login",
                    providerId: "my-login",
                    inputSchema: schema,            
                    callback(ctx, parsed) {
                        if (parsed._email !== parsed._password) {
                            throw new Error("Authentication failed, please try again.");
                        } else {
                            return {
                                email: parsed._email,
                                name: parsed._email.split("@")[0]
                            };
                        }
                    }
                }),
            ]
        }),
        {
            clientOptions: {
                plugins: [credentialsClient<User, "/sign-in/my-login", typeof schema>()],
            },
        },
    );
    let instance: Awaited<typeof _instance>;

    beforeAll(async () => {
         instance = await _instance;
    });

    test("Should be able to authenticate", async () => {
        const { client } = instance;

        const {data, error} = await client.signIn.myLogin({
            _email: "plugin_user@example.com",
            _password: "plugin_user@example.com"
        });
        
        expect(error).toBeNull();
        expect(data).toBeDefined();

        expect(data?.user).toBeDefined();
        expect(data?.user?.email).toBe("plugin_user@example.com");
        expect(data?.user?.name).toBe("plugin_user");
    });

    test("Should'nt authenticate", async () => {
        const { client } = instance;

        const {data, error} = await client.signIn.myLogin({
            _email: "plugin_user@example.com",
            _password: "wrong-password"
        });
        
        expect(error).toBeDefined();
        expect(data).toBeNull();
    });

    test("Should'nt authenticate, existing user different provider", async () => {
        const { client } = instance;

        await client.signUp.email({
            name: "Plugin User 2",
            email: "plugin_user2@example.com",
            password: "plugin_user2@example.com"
        });

        const {data, error} = await client.signIn.myLogin({
            _email: "plugin_user2@example.com",
            _password: "plugin_user2@example.com"
        });
        
        expect(error).toBeDefined();
        expect(data).toBeNull();
    });
});