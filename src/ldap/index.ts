// Adaptado de https://github.com/better-auth/better-auth/blob/main/packages/better-auth/src/plugins/username/index.ts
// e https://github.com/better-auth/better-auth/blob/main/packages/better-auth/src/api/routes/sign-in.ts

import { z } from "zod";
import { APIError, EndpointContext, EndpointOptions } from "better-call";
import { Account, BetterAuthPlugin, InferOptionSchema, User } from "better-auth";
import { createAuthEndpoint, createAuthMiddleware, sendVerificationEmailFn } from "better-auth/api";
import { USERNAME_ERROR_CODES } from "./error-codes.js";
import { ERROR_CODES } from "better-auth/plugins";
import { setSessionCookie } from "better-auth/cookies";
import { authenticateLdap } from "./ldap.js";
import { AuthenticationOptions } from "ldap-authentication";

export type LDAPOptions = {	
	/**
	 * The LDAP configuration to use for authentication, see https://github.com/shaozi/ldap-authentication/ for details
	 * Also you can pass a function that receives the credential and password and returns a Promise with the LDAP result.
	 */
	ldapConfig: Omit<AuthenticationOptions, "username" | "userPassword"> | ((credential: string, password: string) => Promise<any>);

	inputSchema?: z.ZodType<{
		credential: string;
		password: string;
		rememberMe?: boolean;
	}, z.ZodTypeDef, {
		credential: string;
		password: string;
		rememberMe?: boolean;
	}>;

	/**
	 * The attribute to use as the credential, must be a unique field to  identify the user.
	 * Also you can pass a function that receives the credential and returns a Promise with the user object or null if not found.
	 * @default "email"
	 */
	userCredentialAttribute?: string | ((credential: string) => Promise<User | null>);

	/**
	 * Whether to sign up the user if they successfully authenticate on LDAP but do not exist locally
	 * @default false
	 */
	autoSignUp?: boolean;

	/**
	 * Callback when a user is authenticated, with the authenticated user (if not new) and the LDAP result
	 *
	 * If user is null, it means the user does not exist in the local database and will be created if `autoSignUp` is true, in this case is mandatory
	 * to return a partial user object with the data to be stored in the user object, including at least the `email` field.
	 * 
	 * This can be used to store additional information from the LDAP result in the user object
	 * Or to perform additional actions after successful LDAP authentication (if you throw an error here, the user will not be accepted for login)
	 * Example:
	 * ```ts
	 * async (ctx, user, ldapResult) => {
	 *   return { email: ldapResult.email, name: ldapResult.name, image: ldapResult.image };
	 * }
	 * ```
	 */
	onLdapAuthenticated: (ctx: EndpointContext<string, any>, user: User | null, ldapResult: any) => Promise<Partial<User> | void | undefined> | Partial<User> | void | undefined;
};

export const ldap = (options: LDAPOptions) => {
	return {
		id: "ldap",
		endpoints: {
			signInUsername: createAuthEndpoint(
				"/sign-in/ldap",
				{
					method: "POST",
					body: z.object({
						credential: z.string({
							description: "The credential of the user",
						}),
						password: z.string({
							description: "The password of the user",
						}),
						rememberMe: z
							.boolean({
								description: "Remember the user session",
							})
							.optional(),
					}),
					metadata: {
						openapi: {
							summary: "Sign in with LDAP",
							description: "Sign in with LDAP using the user's credential and password",
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
					// ================== Validate Input ===================
					const zodSchema = options.inputSchema || z.object({
						credential: z.string().min(1),
						password: z.string().min(1),
						rememberMe: z.boolean().optional(),
					});
					const parsed = zodSchema.safeParse(ctx.body);
					if (!parsed.success) {
						throw new APIError("UNAUTHORIZED", {
							message: USERNAME_ERROR_CODES.INVALID_USERNAME_OR_PASSWORD,
							details: parsed.error.format(),
						});
					}

					// ================== Authenticate with LDAP credentials ===================
					let ldapResult: unknown;
					try {
						if(typeof options.ldapConfig === "function") {
							ldapResult = await options.ldapConfig(parsed.data.credential, parsed.data.password);
						} else {
							ldapResult = await authenticateLdap(options.ldapConfig, parsed.data.credential, parsed.data.password);
						}

						if (!ldapResult) {
							ctx.context.logger.error("LDAP authentication failed, no result", { ldap });
							throw new APIError("UNAUTHORIZED", {
								message: USERNAME_ERROR_CODES.INVALID_USERNAME_OR_PASSWORD,
							});
						}
					} catch (error) {
						ctx.context.logger.error("LDAP authentication failed", { error, ldap });
					
						throw new APIError("UNAUTHORIZED", {
							message: USERNAME_ERROR_CODES.INVALID_USERNAME_OR_PASSWORD,
						});
					}

					// ================== Find User & Account, also Auto-SignUp if enabled ===================
					let user: User | null = null;
					if(!options.userCredentialAttribute || typeof options.userCredentialAttribute === "string") {
						user = await ctx.context.adapter.findOne<User>({
							model: "user",
							where: [
								{
									field: options.userCredentialAttribute || "email",
									value: parsed.data.credential,
								},
							],
						});
					} else {
						user = await options.userCredentialAttribute(parsed.data.credential);
					}

					// If no user is found and autoSignUp is not enabled, throw an error
					if(!options.autoSignUp && !user) {
						// TODO: timing attack mitigation
						ctx.context.logger.error("User not found", { ldap });
						throw new APIError("UNAUTHORIZED", {
							message: USERNAME_ERROR_CODES.INVALID_USERNAME_OR_PASSWORD,
						});
					} 

					let account: Account | null = null;
					if(!user) {
						// Auto-SignUp: Create a new user and account
						try {
							const {email, name, ...userData} = (await options.onLdapAuthenticated(ctx, null, ldapResult)) || {};
							if(!userData || !email || !name) {
								throw new APIError("UNPROCESSABLE_ENTITY", {
									message: USERNAME_ERROR_CODES.INVALID_USERNAME,
									details: "User data must include at least an email and a name",
								});
							}
							user = await ctx.context.internalAdapter.createUser({
								email: email,
								name: name,
								...userData
							}, ctx);
						} catch (e) {
							ctx.context.logger.error("Failed to create user", e);
							if (e instanceof APIError) {
								throw e;
							}
							throw new APIError("UNPROCESSABLE_ENTITY", {
								message: USERNAME_ERROR_CODES.UNEXPECTED_ERROR,
								details: e,
							});
						}
						if (!user) {
							throw new APIError("BAD_REQUEST", {
								message: USERNAME_ERROR_CODES.UNEXPECTED_ERROR,
							});
						}

						// Create an account for the user
						await ctx.context.internalAdapter.linkAccount(
							{
								userId: user.id,
								providerId: "ldap",
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
						// Sign-in: Get the user account with the ldap provider
						account = await ctx.context.adapter.findOne<Account>({
							model: "account",
							where: [
								{
									field: "userId",
									value: user.id,
								},
								{
									field: "providerId",
									value: "ldap",
								},
							],
						});
						if (!account) {
							throw new APIError("UNAUTHORIZED", {
								message: USERNAME_ERROR_CODES.INVALID_USERNAME_OR_PASSWORD,
							});
						}
						if (account?.password) {
							ctx.context.logger.error("Shouldn't login with ldap, this user has a password", { ldap });
							throw new APIError("UNAUTHORIZED", {
								message: USERNAME_ERROR_CODES.INVALID_USERNAME_OR_PASSWORD,
							});
						}

						if (
							!user.emailVerified &&
							ctx.context.options.emailAndPassword?.requireEmailVerification
						) {
							await sendVerificationEmailFn(ctx, user);
							throw new APIError("FORBIDDEN", {
								message: USERNAME_ERROR_CODES.EMAIL_NOT_VERIFIED,
							});
						}
						
						const userData = await options.onLdapAuthenticated(ctx, user, ldapResult);
						if(userData) {
							// Update the user with the new data
							await ctx.context.internalAdapter.updateUser(user.id, userData, ctx);
							for(let key of Object.keys(userData)) {
								(user as any)[key] = (userData as any)[key];
							}
						}
					}
					
					// ================== Authenticated! Proceed with login flow ===================
					const session = await ctx.context.internalAdapter.createSession(
						user.id,
						ctx,
						parsed.data.rememberMe === false,
					);
					if (!session) {
						ctx.context.logger.error("Failed to create session");
						throw new APIError("UNAUTHORIZED", {
							message: USERNAME_ERROR_CODES.UNEXPECTED_ERROR
						});
					}
					await setSessionCookie(
						ctx,
						{ session, user },
						parsed.data.rememberMe === false,
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
		$ERROR_CODES: USERNAME_ERROR_CODES,
	} satisfies BetterAuthPlugin;
};