// Adaptado de https://github.com/better-auth/better-auth/blob/main/packages/better-auth/src/plugins/username/index.ts
// e https://github.com/better-auth/better-auth/blob/main/packages/better-auth/src/api/routes/sign-in.ts

import { APIError, EndpointContext } from "better-call";
import { Account, BetterAuthPlugin, User } from "better-auth";
import { createAuthEndpoint, sendVerificationEmailFn } from "better-auth/api";
import { CREDENTIALS_ERROR_CODES as CREDENTIALS_ERROR_CODES } from "./error-codes.js";
import { setSessionCookie } from "better-auth/cookies";
import { default as z, ZodTypeAny } from "zod";

const defaultCredentialsSchema = z.object({
	email: z.string({
		description: "The email of the user",
	}).min(1).email(),
	password: z.string({
		description: "The password of the user",
	}).min(1),
	rememberMe: z.boolean({
		description: "Remember the user session",
	}).optional(),
});
type DefaultCredentialsType = z.infer<typeof defaultCredentialsSchema>;

type GetBodyParsed<Z> = Z extends z.ZodTypeAny ? z.infer<Z> : DefaultCredentialsType;
type MaybePromise<T> = T | Promise<T>;

export type CallbackResult<U extends User> = (Partial<U> & {
	onSignUp?: (userData: Partial<U>) => MaybePromise<Partial<U>>;
	onSignIn?: (userData: Partial<U>, user: U, account: Account) => MaybePromise<Partial<U>>;
}) | null | undefined;

export type CredentialOptions<U extends User = User, Z extends (ZodTypeAny|undefined) = undefined> = {	
	/**
	 * Function that receives the credential and password and returns a Promise with the partial user data to be updated.
	 * 
	 * If the user does not exists it will be created if `autoSignUp` is true, in this case a
	 * the returned user data will be used to create the user, otherwise, if the user exists, it will be updated with the returned user data.
	 * 
	 * If a custom inputSchema is set and it hasn't an `email` field, then you should return the `email` field to uniquely identify the user (Better auth can't operate without emails anyway).
	 * 
	 * The `onSignIn` and `onSignUp` callbacks are optional, but if returned they will be called to handle updating the user data differently based if the user is signing in or signing up.
	 */
	callback: (
		ctx: EndpointContext<string, any>, 
		parsed: GetBodyParsed<Z> 
	) => 
		MaybePromise<CallbackResult<U>>;

	/**
	 * Schema for the input data, if not provided it will use the default schema that mirrors default email and password with rememberMe option.
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
	path?: string;

	/**
	 * This is used to infer the User type to be used, never used otherwise. If not provided it will be the default User type.
	 * 
	 * For example, to add a lastLogin input value: 
	 * @example {} as User & {lastLogin: Date}
	 */
	UserType?: U;
};

export const credentials = <U extends User = User, Z extends (ZodTypeAny|undefined) = undefined>(options: CredentialOptions<U,Z>) => {
	const zodSchema = options.inputSchema || defaultCredentialsSchema;

	return {
		id: "credentials",
		endpoints: {
			signInUsername: createAuthEndpoint(
				options.path || "/sign-in/credentials",
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
				async (ctx) => {
					// The zod schema on body already validated the input
					const parsed = ctx.body as GetBodyParsed<Z>;

					// ================== Authenticate with Credentials ===================
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
					let {onSignIn, onSignUp, email, ..._userData} = callbackResult;
					let userData: Partial<U> = _userData as Partial<U>;

					// Fallback email from body if not provided in callback result
					if(!email) {
						email = "email" in parsed && typeof parsed.email === "string" ? parsed.email : undefined;
						if(!email) {
							ctx.context.logger.error("Email is required for credentials authentication", { credentials });
							throw new APIError("UNAUTHORIZED", {
								message: CREDENTIALS_ERROR_CODES.INVALID_CREDENTIALS,
							});
						}
					}

					// ================== Find User & Account, also Auto-SignUp if enabled ===================
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
						// TODO: timing attack mitigation
						ctx.context.logger.error("User not found", { credentials });
						throw new APIError("UNAUTHORIZED", {
							message: CREDENTIALS_ERROR_CODES.INVALID_CREDENTIALS,
						});
					} 

					let account: Account | null = null;
					if(!user) {
						// Auto-SignUp: Create a new user and account
						try {
							if(onSignUp && typeof onSignUp === "function") {
								userData = await onSignUp({email: email, ...userData});
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
								name: name || email, // Fallback to using email as name if not provided
								...restUserData
							}, ctx);
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
							throw new APIError("BAD_REQUEST", {
								message: CREDENTIALS_ERROR_CODES.UNEXPECTED_ERROR,
							});
						}

						// Create an account for the user
						account = await ctx.context.internalAdapter.linkAccount(
							{
								userId: user.id,
								providerId: options.providerId || "credential",
								accountId: user.id,
							},
							ctx,
						);

						// If the user is created, we can send the verification email if required
						// In this case, just return the user without a token and no session is created (this mimics the behavior of the email and password sign-up flow)
						if (
							!user.emailVerified &&
							(ctx.context.options.emailVerification?.sendOnSignUp ||
							ctx.context.options.emailAndPassword?.requireEmailVerification)
						) {
							await sendVerificationEmailFn(ctx, user);
							return ctx.json({
								token: null,
								user: {
									id: user.id,
									email: user.email,
									name: user.name,
									image: user.image,
									emailVerified: user.emailVerified,
									createdAt: user.createdAt,
									updatedAt: user.updatedAt,
								},
							});
						}
					} else {
						// Sign-in: Get the user account with the chosen provider
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
						if(!options.linkAccountIfExisting) {
							if (!account) {
								ctx.context.logger.error("User exists but no account found for this provider", { credentials });
								throw new APIError("UNAUTHORIZED", {
									message: CREDENTIALS_ERROR_CODES.INVALID_CREDENTIALS,
								});
							}
							// Prevent email & password created users from logging in with this credentials plugin, as they would have a password set
							if (account?.password) {
								ctx.context.logger.error("Shouldn't login with credentials, this user has a account with password", { credentials });
								throw new APIError("UNAUTHORIZED", {
									message: CREDENTIALS_ERROR_CODES.INVALID_CREDENTIALS,
								});
							}
						} else {
							if(!options.autoSignUp && !account) {
								ctx.context.logger.error("Account for this provider not found", { credentials });
								throw new APIError("UNAUTHORIZED", {
									message: CREDENTIALS_ERROR_CODES.INVALID_CREDENTIALS,
								});
							}

							if(!account) {
								// Create an account for the user
								account = await ctx.context.internalAdapter.linkAccount(
									{
										userId: user.id,
										providerId: options.providerId || "credential",
										accountId: user.id,
									},
									ctx,
								);								
							}
						}

						if (
							!user.emailVerified &&
							ctx.context.options.emailAndPassword?.requireEmailVerification
						) {
							await sendVerificationEmailFn(ctx, user);
							throw new APIError("FORBIDDEN", {
								message: CREDENTIALS_ERROR_CODES.EMAIL_NOT_VERIFIED,
							});
						}
						
						try {
							if(onSignIn && typeof onSignIn === "function") {
								userData = await onSignIn({email: email, ...userData}, user, account!);
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
						
						// Update the user with the new data (excluding email)
						if(userData) {
							delete userData.email;
							if(Object.keys(userData).length > 0) {
								user = (await ctx.context.internalAdapter.updateUser(user.id, userData, ctx)) as U;
							}
						}
					}
					
					// ================== Authenticated! Proceed with login flow ===================
					const rememberMe = "rememberMe" in parsed ? parsed.rememberMe : false;
					const session = await ctx.context.internalAdapter.createSession(
						user.id,
						ctx,
						rememberMe === false,
					);
					if (!session) {
						ctx.context.logger.error("Failed to create session");
						throw new APIError("UNAUTHORIZED", {
							message: CREDENTIALS_ERROR_CODES.UNEXPECTED_ERROR
						});
					}
					await setSessionCookie(
						ctx,
						{ session, user },
						rememberMe === false,
					);
					return ctx.json({
						token: session.token,
						user: {
							id: user.id,
							email: user.email,
							name: user.name,
							image: user.image,
							emailVerified: user.emailVerified,
							createdAt: user.createdAt,
							updatedAt: user.updatedAt,
						},
					});
				},
			),
		},
		$ERROR_CODES: CREDENTIALS_ERROR_CODES,
	} satisfies BetterAuthPlugin;
};