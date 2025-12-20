// Adaptado de https://github.com/better-auth/better-auth/blob/main/packages/better-auth/src/plugins/username/index.ts
// e https://github.com/better-auth/better-auth/blob/main/packages/better-auth/src/api/routes/sign-in.ts

import { APIError, EndpointContext } from "better-call";
import { Account, BetterAuthOptions, BetterAuthPlugin, InferUser, User } from "better-auth";
import { createAuthEndpoint, sendVerificationEmailFn } from "better-auth/api";
import { CREDENTIALS_ERROR_CODES as CREDENTIALS_ERROR_CODES } from "./error-codes.js";
import { setSessionCookie } from "better-auth/cookies";
import { defaultCredentialsSchema } from "./schema.js";
import { inferZod34, Zod34Schema } from "../utils/zod.js";
import { parseUserOutput } from "better-auth/db";

type GetBodyParsed<Z> = Z extends Zod34Schema ? inferZod34<Z> : {
    email: string;
    password: string;
    rememberMe?: boolean | undefined;
};
type MaybePromise<T> = T | Promise<T>;

export type CallbackResult<U extends User> = (Partial<U> & {
	onSignUp?: (userData: Partial<U>) => MaybePromise<Partial<U> | null>;
	onSignIn?: (userData: Partial<U>, user: U, account: Account | null) => MaybePromise<Partial<U> | null>;
	onLinkAccount?: (user: U) => MaybePromise<Partial<Account>>;
}) | null | undefined;

export type CredentialOptions<U extends User = User, P extends string = "/sign-in/credentials", Z extends (Zod34Schema|undefined) = undefined> = {	
	/**
	 * Function that receives the credential and password and returns a Promise with the partial user data to be updated.
	 * 
	 * If the user does not exists it will be created if `autoSignUp` is true, in this case a
	 * the returned user data will be used to create the user, otherwise, if the user exists, it will be updated with the returned user data.
	 * 
	 * If a custom inputSchema is set and it hasn't an `email` field, then you should return the `email` field to uniquely identify the user (Better auth can't operate without emails anyway).
	 * 
	 * The `onSignIn` and `onSignUp` callbacks are optional, but if returned they will be called to handle updating the user data differently based if the user is signing in or signing up.
	 * 
	 * The `onLinkAccount` callback is called whenever a Account is created or if the user already exists and an account is linked to the user, use it to store custom data on the Account.
	 */
	callback: (
		ctx: EndpointContext<string, any>, 
		parsed: GetBodyParsed<Z> 
	) => 
		MaybePromise<CallbackResult<U>>;

	/**
	 * Schema for the input data, if not provided it will use the default schema that mirrors default email and password with rememberMe option.
	 * 
	 * (Until version 0.2.2 it had to be a zod/v3 schema, now it works with zod/v4 also)
	 */
	inputSchema?: Z;

	/**
	 * Whether to sign up the user if they successfully authenticate but do not exist locally
	 * @default false
	 */
	autoSignUp?: boolean;

	/**
	 * If is allowed to link an account to an existing user without an Account of this provider (No effect if autoSignUp is false).
	 * 
	 * Basically, if the user already exists, but with another provider (e.g. email and password), if this is true a 
	 * new Account will be created and linked to this user (as if new login method), otherwise it will throw an error.
	 * @default false
	 */
	linkAccountIfExisting?: boolean;

	/**
	 * The Id of the provider to be used for the account created, fallback to "credential", the same used by the email and password flow.
	 * 
	 * Obs: If you are using this plugin with the email and password plugin enabled and did not change the providerId, users that have a password set will not be able to log in with this credentials plugin.
	 * @default "credential"
	 */
	providerId?: string;

	/**
	 * The path for the endpoint
	 * @default "/sign-in/credentials"
	 */
	path?: P;

	/**
	 * This is used to infer the User type to be used, never used otherwise. If not provided it will be the default User type.
	 * 
	 * For example, to add a lastLogin input value: 
	 * @example {} as User & {lastLogin: Date}
	 */
	UserType?: U;
};

/**
 * Customized Credentials plugin for BetterAuth.
 * 
 * The options allow you to customize the input schema, the callback function, and other behaviors.
 * 
 * Summary of the stages of this authentication flow:
 * 1. Validate the input data against `inputSchema`
 * 2. Call the `callback` function
 *   - If the callback throws an error, or doesn't return a object with user data, a generic 401 Unauthorized error is thrown.
 * 3. Find the user by email (given by callback or parsed input), if exists proceed to [SIGN IN], if not [SIGN UP] (only when `autoSignUp` is true).
 * 
 * **[SIGN IN]**
 * 
 * 4. Find the Account with the providerId
 *   - If the account is not found, and `linkAccountIfExisting` or `autoSignUp` is false, login fails with a 401 Unauthorized error.
 * 5. If provided, Call the `onSignIn` callback function, but yet don't update the user data.
 * 6. If no Account was found on step 4. call the `onLinkAccount` callback function to get the account data to be stored, and then create a new Account for the user with the providerId.
 * 7. Update the user with the provided data (Either returned by the auth callback function or the `onSignIn` callback function).
 * 
 * **[SIGN UP]**
 * 
 * 4. If provided, call the `onSignUp` callback function to get the user data to be stored.
 * 5. Create a new User with the provided data (Either returned by the auth callback function or the `onSignUp` callback function).
 * 5. If provided, call the `onLinkAccount` callback function to get the account data to be stored
 * 6. Then create a new Account for the user with the providerId.
 * 
 * **[AUTHENTICATED!]**
 * 
 * 6. Create a new session for the user and set the session cookie.
 * 7. Return the user data and the session token.
 * 
 * @example
 * ```ts
 * credentials({
 *   autoSignUp: true,
 *   callback: async (ctx, parsed) => {
 *     // 1. Verify the credentials
 *
 *     // 2. On success, return the user data
 *     return {
 *       email: parsed.email
 *     };  
 * })
 */
export const credentials = <U extends User = User, P extends string = "/sign-in/credentials", Z extends (Zod34Schema|undefined) = undefined, O extends (BetterAuthOptions|undefined) = undefined>(
	options: CredentialOptions<U, P, Z>, 
	betterAuthOptions?: O | undefined
) => {
	type ReturnUserType = O extends BetterAuthOptions ? InferUser<O> : U; 
	const zodSchema = (options.inputSchema || defaultCredentialsSchema) as Z;

	return {
		id: "credentials",
		options: options,
		endpoints: {
			signInCredentials: createAuthEndpoint(
				// Endpoints are inferred from the server plugin by adding a $InferServerPlugin key to the client plugin.
				// Without this 'as' key the inferred client plugin would not work properly.
				(options.path || "/sign-in/credentials") as P,
				{
					method: "POST",
					body: zodSchema,
					metadata: {
						openapi: {
							summary: "Sign in with Credentials",
							description: "Sign in with credentials using the user's email and password or other configured fields.",
							responses: {
								200: {
									description: "Success",
									content: {
										"application/json": {
											schema: {
												type: "object",
												properties: {
													token: {
														type: "string",
														description:
															"Session token for the authenticated session",
													},
													user: {
														$ref: "#/components/schemas/User",
													},
												},
												required: ["token", "user"],
											},
										},
									},
								},
							},
						},
					},
				},
				async (ctx): Promise<{
					token: string | null;
					user: ReturnUserType;
				}> => {
					// ================== 1. Validate the input data ===================
					// TODO: double check if the body was *really* parsed against the zod schema
					const parsed = ctx.body as GetBodyParsed<Z>;
                    if(!parsed || typeof parsed !== "object") {
                        ctx.context.logger.error("Invalid request body", { credentials });
                        throw new APIError("UNPROCESSABLE_ENTITY", {
                            message: CREDENTIALS_ERROR_CODES.UNEXPECTED_ERROR
                        });
                    }

					// ================== 2. Calling Callback Function ===================
					let callbackResult: CallbackResult<U>;
					try {
						callbackResult = await options.callback(ctx, parsed);

						if (!callbackResult) {
							ctx.context.logger.error("Authentication failed, callback didn't returned user data", { credentials });
							throw new APIError("UNAUTHORIZED", {
								message: CREDENTIALS_ERROR_CODES.INVALID_CREDENTIALS,
							});
						}
					} catch (error) {
						ctx.context.logger.error("Authentication failed", { error, credentials });
					
						throw new APIError("UNAUTHORIZED", {
							message: CREDENTIALS_ERROR_CODES.INVALID_CREDENTIALS,
						});
					}
					let {onSignIn, onSignUp, onLinkAccount, email, ..._userData} = callbackResult;
					let userData: Partial<U> = _userData as Partial<U>;

					// Fallback email from body if not provided in callback result
					if(!email) {
						email = "email" in parsed && typeof parsed.email === "string" ? parsed.email : undefined;
						if(!email) {
							ctx.context.logger.error("Email is required for credentials authentication", { credentials });
							throw new APIError("UNPROCESSABLE_ENTITY", {
								message: CREDENTIALS_ERROR_CODES.UNEXPECTED_ERROR,
								details: "Email is required for credentials authentication",
							});
						}
					}
					email = email.toLowerCase();

					// ================== 3. Find User by email ===================
					let user: U | null = await ctx.context.adapter.findOne<U>({
						model: "user",
						where: [
							{
								field: "email",
								value: email,
							},
						],
					});
					
					// If no user is found and autoSignUp is not enabled, throw an error
					if(!options.autoSignUp && !user) {
						// TODO: timing attack mitigation?
						ctx.context.logger.error("User not found", { credentials });
						throw new APIError("UNAUTHORIZED", {
							message: CREDENTIALS_ERROR_CODES.INVALID_CREDENTIALS,
						});
					}

					// If email verification is required, return early
					if (
						user && !user.emailVerified &&
						ctx.context.options.emailAndPassword?.requireEmailVerification
					) {
						await sendVerificationEmailFn(ctx, user);
						throw new APIError("FORBIDDEN", {
							message: CREDENTIALS_ERROR_CODES.EMAIL_NOT_VERIFIED,
						});
					}

					let account: Account | null = null;
					if(!user) {
						// ===================================================================
						// =                          SIGN UP                                =
						// =      Create a new User and Account, for this provider           =
						// ===================================================================
						// 

						// ================== 4. create new User ====================
						try {
							if(onSignUp && typeof onSignUp === "function") {
								const newData = await onSignUp({email: email, ...userData});
								if(!newData) {
									throw new Error("onSignUp callback returned null, failed sign up");
								}
								userData = newData;
							}

							if(!userData || !email) {
								throw new APIError("UNPROCESSABLE_ENTITY", {
									message: CREDENTIALS_ERROR_CODES.EMAIL_REQUIRED,
									details: "User data must include at least email",
								});
							}

							delete userData.email;
							const { name, ...restUserData } = userData;
							user = await ctx.context.internalAdapter.createUser({
								email: email,
								name: name!, // Yes, the type is wrong, NAME IS OPTIONAL
								emailVerified: false,
								...restUserData,
							}) as U;
						} catch (e) {
							ctx.context.logger.error("Failed to create user", e);
							if (e instanceof APIError) {
								throw e;
							}
							throw new APIError("UNAUTHORIZED", {
								message: CREDENTIALS_ERROR_CODES.INVALID_CREDENTIALS,
							});
						}
						if (!user) {
							throw new APIError("UNPROCESSABLE_ENTITY", {
								message: CREDENTIALS_ERROR_CODES.UNEXPECTED_ERROR,
							});
						}

						// ================== 5. create new Account ====================
						let accountData = {};
						if(onLinkAccount && typeof onLinkAccount === "function") {
							accountData = await onLinkAccount(user);
						}
						account = await ctx.context.internalAdapter.linkAccount(
							{
								userId: user.id,
								providerId: options.providerId || "credential",
								accountId: user.id,
								...accountData
							}
						);

						// If the user is created, we can send the verification email if required
						if (
							!user.emailVerified &&
							(ctx.context.options.emailVerification?.sendOnSignUp ||
							ctx.context.options.emailAndPassword?.requireEmailVerification)
						) {
							await sendVerificationEmailFn(ctx, user);

							// If email verification is required, just return the user without a token and no session is created (this mimics the behavior of the email and password sign-up flow)
							if(ctx.context.options.emailAndPassword?.requireEmailVerification) {
								return ctx.json({
									token: null,
									user: parseUserOutput(
										ctx.context.options,
										user,
									) as ReturnUserType,
								});
							}
						}
					} else {
						// ===================================================================
						// =                          SIGN IN                                =
						// =                  Find/Link Account, for this provider           =
						// ===================================================================
						// 
						
						// =============== 4.  Get the user account with the chosen provider ==============
						account = await ctx.context.adapter.findOne<Account>({
							model: "account",
							where: [
								{
									field: "userId",
									value: user.id,
								},
								{
									field: "providerId",
									value: options.providerId || "credential",
								},
							],
						});

						if((!options.autoSignUp || !options.linkAccountIfExisting) && !account) {
							ctx.context.logger.error("User exists but no account found for this provider", { credentials });
							throw new APIError("UNAUTHORIZED", {
								message: CREDENTIALS_ERROR_CODES.INVALID_CREDENTIALS,
							});
						}

						if(account && account.providerId === "credential" && account.password) {
							ctx.context.logger.error("Shouldn't login with credentials, this user has a account with password", { credentials });
							throw new APIError("UNAUTHORIZED", {
								message: CREDENTIALS_ERROR_CODES.INVALID_CREDENTIALS,
							});
						}
						
						// =============== 5. Update user data ==============
						try {
							if(onSignIn && typeof onSignIn === "function") {
								const newData = await onSignIn({email: email, ...userData}, user, account);
								if(!newData) {
									throw new Error("onSignIn callback returned null, failed on sign in");
								}
								userData = newData;
							}
						} catch (e) {
							ctx.context.logger.error("Failed to update user data on sign in", e);
							if (e instanceof APIError) {
								throw e;
							}
							throw new APIError("UNAUTHORIZED", {
								message: CREDENTIALS_ERROR_CODES.INVALID_CREDENTIALS,
							});
						}

						// Doing the linking after onSignIn callback, so if it fails no account is created
						if(!account) {
							// Create an account for the user if it doesn't exist
							let accountData = {};
							if(onLinkAccount && typeof onLinkAccount === "function") {
								accountData = await onLinkAccount(user);
							}
							account = await ctx.context.internalAdapter.linkAccount(
								{
									userId: user.id,
									providerId: options.providerId || "credential",
									accountId: user.id,
									...accountData
								}
							);
						}
						
						// Update the user with the new data (excluding email)
						if(userData) {
							delete userData.email;
							if(Object.keys(userData).length > 0) {
								user = (await ctx.context.internalAdapter.updateUser(user.id, userData)) as U;
							}
						}
					}
					
					// ===================================================================
					// =                          AUTHENTICATED!                         =
					// =                   Proceed with login flow                       =
					// ===================================================================
					
					const rememberMe = "rememberMe" in parsed ? parsed.rememberMe : false;
					const session = await ctx.context.internalAdapter.createSession(
						user.id,
						rememberMe === false,
					);
					if (!session) {
						ctx.context.logger.error("Failed to create session");
						throw new APIError("BAD_REQUEST", {
							message: CREDENTIALS_ERROR_CODES.UNEXPECTED_ERROR
						});
					}
					await setSessionCookie(
						ctx,
						{ session, user },
						rememberMe === false,
					);

					// =============== Response with user data ==============
					return ctx.json({
						token: session.token,
						user: parseUserOutput(
							ctx.context.options,
							user,
						) as ReturnUserType,
					});
				},
			),
		},
		$ERROR_CODES: CREDENTIALS_ERROR_CODES,
	} satisfies BetterAuthPlugin;
};
