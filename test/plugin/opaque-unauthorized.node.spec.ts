import { describe, expect, test } from "vitest";
import { betterAuth, email } from "better-auth";
import { APIError } from "@better-auth/core/error";

import { defaultBetterAuthOptions } from "../plugin.js";
import { credentials } from "../../index.js";

describe("Opaque UNAUTHORIZED paths no matter what", () => {
    test("User not found --> INVALID_CREDENTIALS", async () => {
        const auth = betterAuth({
            ...defaultBetterAuthOptions,
            plugins: [credentials({
                autoSignUp: false,
                callback(_ctx, parsed) {
                    return parsed;
                },
            })],
        });

        const response = await auth.api.signInCredentials({
            body: {
                email: "opaque-user-not-found@example.com",
                password: "opaque-user-not-found@example.com",
            },
            asResponse: true,
        });
        const body = await response.json();

        expect(response.status).toBe(401);
        expect(body.code).toBe("INVALID_CREDENTIALS");
    });

    test("Disabled linking on existing user without credentials account--> INVALID_CREDENTIALS", async () => {
        const auth = betterAuth({
            ...defaultBetterAuthOptions,
            plugins: [credentials({
                autoSignUp: true,
                linkAccountIfExisting: false,
                providerId: "opaque-provider",
                callback(_ctx, parsed) {
                    return parsed;
                },
            })],
        });

        await auth.api.signUpEmail({
            body: {
                name: "Opaque Existing",
                email: "opaque-account-not-found@example.com",
                password: "opaque-account-not-found@example.com",
            },
        });

        const response = await auth.api.signInCredentials({
            body: {
                email: "opaque-account-not-found@example.com",
                password: "opaque-account-not-found@example.com",
            },
            asResponse: true,
        });
        const body = await response.json();

        expect(response.status).toBe(401);
        expect(body.code).toBe("INVALID_CREDENTIALS");
    });

    test("Credentials login on Email & Password flow account with same provider id --> INVALID_CREDENTIALS", async () => {
        const auth = betterAuth({
            ...defaultBetterAuthOptions,
            plugins: [credentials({
                autoSignUp: true,
                linkAccountIfExisting: true,
                callback(_ctx, parsed) {
                    return parsed;
                },
            })],
        });

        await auth.api.signUpEmail({
            body: {
                name: "Opaque Credential Account",
                email: "opaque-credential-account@example.com",
                password: "opaque-credential-account@example.com",
            },
        });

        const response = await auth.api.signInCredentials({
            body: {
                email: "opaque-credential-account@example.com",
                password: "opaque-credential-account@example.com",
            },
            asResponse: true,
        });
        const body = await response.json();

        expect(response.status).toBe(401);
        expect(body.code).toBe("INVALID_CREDENTIALS");
    });
});

describe("Errors thrown that you can see if you want", () => {
    test("Thrown APIError on callbacks should propagate as is", async () => {
        const auth = betterAuth({
            ...defaultBetterAuthOptions,
            plugins: [credentials({
                autoSignUp: true,
                callback(ctx, parsed) {
                    if(parsed.password === "return-null-callback") {
                        return null;
                    }
                    if(parsed.password === "throw-api-error-callback") {
                        throw new APIError("FORBIDDEN", {
                            code: "CUSTOM_FORBIDDEN",
                            message: "This is a custom forbidden error",
                        });
                    }
                    return {
                        ...parsed,
                        onSignUp(userData) {
                            if(parsed.password === "return-null-signup") {
                                return null;
                            }
                            if(parsed.password === "throw-api-error-signup") {
                                throw new APIError("FORBIDDEN", {
                                    code: "SIGN_UP_FORBIDDEN",
                                    message: "Sign up is forbidden",
                                });
                            }
                            return userData;
                        },
                        onSignIn(userData, user, account) {
                            if(parsed.password === "return-null-signin") {
                                return null;
                            }
                            if(parsed.password === "throw-api-error-signin") {
                                throw new APIError("FORBIDDEN", {
                                    code: "SIGN_IN_FORBIDDEN",
                                    message: "Sign in is forbidden",
                                });
                            }
                            return userData;
                        },
                        onLinkAccount(user) {
                            if(parsed.password === "throw-api-error-linking") {
                                throw new APIError("FORBIDDEN", {
                                    code: "LINKING_FORBIDDEN",
                                    message: "Linking account is forbidden",
                                });
                            }
                            return {
                                accountId: user.email
                            };
                        },
                    };
                },
            })],
        });

        const testErrorCases = [{
            email: "invalid-email.com",
            password: "",
            expectedCode: "VALIDATION_ERROR",
        }, {
            email: "apierror-callback@example.com",
            password: "throw-api-error-callback",
            expectedCode: "CUSTOM_FORBIDDEN",
        }, {
            email: "apierror-signup@example.com",
            password: "throw-api-error-signup",
            expectedCode: "SIGN_UP_FORBIDDEN",
        }, {
            email: "apierror-signin@example.com",
            password: "throw-api-error-signin",
            expectedCode: "SIGN_IN_FORBIDDEN",
        }, {
            email: "apierror-linking@example.com",
            password: "throw-api-error-linking",
            expectedCode: "LINKING_FORBIDDEN",
        },
        // when returns null fallback to INVALID_CREDENTIALS, and user/account shouldn't be created in the database
           {
            email: "apierror-callback@example.com",
            password: "return-null-callback",
            expectedCode: "INVALID_CREDENTIALS",
        }, {
            email: "apierror-signup@example.com",
            password: "return-null-signup",
            expectedCode: "INVALID_CREDENTIALS",
        }, {
            email: "apierror-signin@example.com",
            password: "return-null-signin",
            expectedCode: "INVALID_CREDENTIALS",
        }];

        {
            const response = await auth.api.signInCredentials({
                body: {
                    email: "apierror-signin@example.com",
                    password: "somepassword123",
                },
                asResponse: true,
            });
            expect(response.status).toBe(200);
        }

        const ctx = await auth.$context;
        for(const testCase of testErrorCases) {
            const response = await auth.api.signInCredentials({
                body: {
                    email: testCase.email,
                    password: testCase.password,
                },
                asResponse: true,
            });
            const body = await response.json();

            expect(response.ok).toBe(false);
            expect(body.code).toBe(testCase.expectedCode);

            if(testCase.email === "apierror-signin@example.com") continue;

            // User & Account shouldn't exist in the database after these errors
            const user = await ctx.internalAdapter.findUserByEmail(testCase.email);
            expect(user).toBeNull();

            const account = await ctx.internalAdapter.findAccount(testCase.email);
            expect(account).toBeNull();

        }
    });


});