// Adaptado de https://github.com/better-auth/better-auth/blob/main/packages/better-auth/src/plugins/username/index.ts
// e https://github.com/better-auth/better-auth/blob/main/packages/better-auth/src/api/routes/sign-in.ts

import { APIError, EndpointContext } from "better-call";
import { Account, BetterAuthPlugin, User } from "better-auth";
import { createAuthEndpoint, sendVerificationEmailFn } from "better-auth/api";
import { CREDENTIALS_ERROR_CODES as CREDENTIALS_ERROR_CODES } from "./error-codes.js";
import { setSessionCookie } from "better-auth/cookies";
import z, { ZodTypeAny } from "zod";

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

export type CredentialOptions<Z extends (ZodTypeAny|undefined) = undefined> = {
	/**
	 * The path for the endpoint
	 * @default "/sign-in/credentials"
	 */
	path?: string;

	/**
	 * Schema for the input data, if not provided it will use the default schema allowing any non-empty string for credential and password
	 */
	inputSchema?: Z;
	
	/**
	 * Function that receives the credential and password and returns a Promise with the user Data, with `email` field to uniquely identify the user (Better auth can't operate without emails anyway).
	 * 
	 * if the user does not exist in the local database they will be created if `autoSignUp` is true, in this case is mandatory
	 * to return a partial user object with the data to be stored in the user object, including at least the `email` and `name` field.
	 * 
	 * If the user exists, the data returned will be merged with the existing user data.
	 */
	callback: (
		ctx: EndpointContext<string, any>, 
		parsed: GetBodyParsed<Z> 
	) => 
		MaybePromise<(Partial<User> & Pick<User, "email">) | null | undefined>;

	/**
	 * Whether to sign up the user if they successfully authenticate but do not exist locally
	 * @default false
	 */
	autoSignUp?: boolean;

	/**
	 * The Id of the provider to be used for the account created, fallback to "credential", the same used by the email and password flow.
	 * @default "credential"
	 */
	providerId?: string;
};

export const credentials = <Z extends (ZodTypeAny|undefined) = undefined>(options: CredentialOptions<Z>) => {
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
					let callbackResult: (Partial<User> & Pick<User, "email">) | null | undefined;
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

					// ================== Find User & Account, also Auto-SignUp if enabled ===================
					let user: User | null = await ctx.context.adapter.findOne<User>({
						model: "user",
						where: [
							{
								field: "email",
								value: callbackResult.email,
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
							const {email, name, ...userData} = callbackResult;
							if(!userData || !email) {
								throw new APIError("UNPROCESSABLE_ENTITY", {
									message: CREDENTIALS_ERROR_CODES.EMAIL_REQUIRED,
									details: "User data must include at least email",
								});
							}
							user = await ctx.context.internalAdapter.createUser({
								email: email,
								name: name || email, // Fallback to using email as name if not provided
								...userData
							}, ctx);
						} catch (e) {
							ctx.context.logger.error("Failed to create user", e);
							if (e instanceof APIError) {
								throw e;
							}
							throw new APIError("UNPROCESSABLE_ENTITY", {
								message: CREDENTIALS_ERROR_CODES.UNEXPECTED_ERROR,
								details: e,
							});
						}
						if (!user) {
							throw new APIError("BAD_REQUEST", {
								message: CREDENTIALS_ERROR_CODES.UNEXPECTED_ERROR,
							});
						}

						// Create an account for the user
						await ctx.context.internalAdapter.linkAccount(
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
						if (!account) {
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

						if (
							!user.emailVerified &&
							ctx.context.options.emailAndPassword?.requireEmailVerification
						) {
							await sendVerificationEmailFn(ctx, user);
							throw new APIError("FORBIDDEN", {
								message: CREDENTIALS_ERROR_CODES.EMAIL_NOT_VERIFIED,
							});
						}
						
						// Update the user with the new data (Both in database and in the user object used to create session)
						await ctx.context.internalAdapter.updateUser(user.id, callbackResult, ctx);
						for(let key of Object.keys(callbackResult)) {
							(user as any)[key] = (callbackResult as any)[key];
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