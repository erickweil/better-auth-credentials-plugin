// Adaptado de https://github.com/better-auth/better-auth/blob/main/packages/better-auth/src/plugins/username/index.ts

import { z } from "zod";
import { APIError, EndpointContext, EndpointOptions } from "better-call";
import { Account, BetterAuthPlugin, InferOptionSchema, User } from "better-auth";
import { schema } from "./schema.js";
import { createAuthEndpoint, createAuthMiddleware, sendVerificationEmailFn } from "better-auth/api";
import { USERNAME_ERROR_CODES } from "./error-codes.js";
import { ERROR_CODES } from "better-auth/plugins";
import { setSessionCookie } from "better-auth/cookies";
import { mergeSchema } from "better-auth/db";
import { authenticateLdap } from "./ldap.js";

export type LDAPOptions = {
	schema?: InferOptionSchema<typeof schema>;
	/**
	 * A function to validate the username
	 *
	 * By default, the username should only contain alphanumeric characters and underscores
	 */
	usernameValidator?: z.ZodType,

	ldapOptions: {
		/**
		 * The URL of the LDAP server
		 * Example: "ldap://localhost:389" or "ldaps://localhost:636"
		 */
		url: string;

		/**
		 * Force strict DN parsing for client methods
		 * @default true
		 */
		strictDN?: boolean;

		/**
		 * TLS options for the LDAP connection
		 * default {{ 
		 *  minVersion: 'TLSv1.2' 
		 * }}
		 */
		tlsOptions?: Record<string, any>;

		/**
		 * The timeout for the LDAP connection in milliseconds
		 * @default 30000
		 */
		connectTimeout?: number;

		/**
		 * The timeout for the LDAP authentication in milliseconds, 
		 * Should leave undefined, currently a bug if this is set, see https://github.com/ldapts/ldapts/issues/167
		 * @default undefined
		 */
		timeout?: number;
	}

	/**
	 * The DN of the admin user to authenticate with the LDAP server
	 * Example: "cn=admin,dc=example,dc=com"
	 */
	adminDn: string;

	/**
	 * The password of the admin user to authenticate with the LDAP server
	 */
	adminPassword: string;

	/**
	 * The base DN to search for users
	 * Example: "ou=users,dc=example,dc=com"
	 */
	baseDn: string;

	/**
	 * The attribute to use as the username in the LDAP server
	 * Example: "uid" or "cn"
	 * @default "uid"
	 */
	usernameAttribute?: string;

	/**
	 * Callback when a user is authenticated, with the authenticated user and the LDAP result
	 * This can be used to store additional information from the LDAP result in the user object
	 * Or to perform additional actions after successful LDAP authentication (if you throw an error here, the user will not be accepted for login)
	 * Example:
	 * ```ts
	 * async (ctx, user, ldapResult) => {
	 *   // Store additional information from the LDAP result in the user object
	 *   user.ldap = ldapResult;
	 * }
	 * ```
	 */
	onLdapAuthenticated?: (ctx: EndpointContext<string, any>, user: User, ldapResult: any) => Promise<void> | void;
};

const defaultUsernameValidator = z.string().min(3).max(32).regex(
    /^[a-zA-Z0-9_\-]+$/,
    "Username can only contain alphanumeric characters, underscores, and hyphens."
);

export const ldap = (options: LDAPOptions) => {
	return {
		id: "ldap",
		endpoints: {
			signInUsername: createAuthEndpoint(
				"/sign-in/ldap",
				{
					method: "POST",
					body: z.object({
						username: z.string({
							description: "The username of the user",
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
							summary: "Sign in with username",
							description: "Sign in with username",
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
					if (!ctx.body.username || !ctx.body.password) {
						ctx.context.logger.error("Username or password not found");
						throw new APIError("UNAUTHORIZED", {
							message: USERNAME_ERROR_CODES.INVALID_USERNAME_OR_PASSWORD,
						});
					}

					const validator =
						options?.usernameValidator || defaultUsernameValidator;
                    const validatorResult = validator.safeParse(ctx.body.username);
					if (!validatorResult.success) {
						throw new APIError("UNPROCESSABLE_ENTITY", {
							message: validatorResult.error.issues.find(() => true)?.message || USERNAME_ERROR_CODES.INVALID_USERNAME,
						});
					}

					const user = await ctx.context.adapter.findOne<
						User & { username: string }
					>({
						model: "user",
						where: [
							{
								field: "username",
								value: ctx.body.username.toLowerCase(),
							},
						],
					});
					if (!user) {
						ctx.context.logger.error("User not found", { ldap });
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

					const account = await ctx.context.adapter.findOne<Account>({
						model: "account",
						where: [
							{
								field: "userId",
								value: user.id,
							},
							{
								field: "providerId",
								value: "credential",
							},
						],
					});
					if (!account) {
						throw new APIError("UNAUTHORIZED", {
							message: USERNAME_ERROR_CODES.INVALID_USERNAME_OR_PASSWORD,
						});
					}
					const currentPassword = account?.password;
					if (currentPassword) {
						ctx.context.logger.error("Shouldn't login with ldap, this user has a password", { ldap });
						throw new APIError("UNAUTHORIZED", {
							message: USERNAME_ERROR_CODES.INVALID_USERNAME_OR_PASSWORD,
						});
					}

					/*const validPassword = await ctx.context.password.verify({
						hash: currentPassword,
						password: ctx.body.password,
					});*/
					let ldapResult;
					try {
						ldapResult = await authenticateLdap(options, ctx.body.username, ctx.body.password);

						if (!ldapResult) {
							ctx.context.logger.error("LDAP authentication failed, no result", { ldap });
							throw new APIError("UNAUTHORIZED", {
								message: USERNAME_ERROR_CODES.INVALID_USERNAME_OR_PASSWORD,
							});
						}

						if (options.onLdapAuthenticated) {
							await options.onLdapAuthenticated(ctx, user, ldapResult);
						}
					} catch (error) {
						ctx.context.logger.error("LDAP authentication failed", { error, ldap });
					
						throw new APIError("UNAUTHORIZED", {
							message: USERNAME_ERROR_CODES.INVALID_USERNAME_OR_PASSWORD,
						});
					}

					const session = await ctx.context.internalAdapter.createSession(
						user.id,
						ctx,
						ctx.body.rememberMe === false,
					);
					if (!session) {
						return ctx.json(null, {
							status: 500,
							body: {
								message: ERROR_CODES.UNAUTHORIZED_SESSION
							},
						});
					}
					await setSessionCookie(
						ctx,
						{ session, user },
						ctx.body.rememberMe === false,
					);
					return ctx.json({
						token: session.token,
						user: {
							id: user.id,
							email: user.email,
							emailVerified: user.emailVerified,
							username: user.username,
							name: user.name,
							image: user.image,
							createdAt: user.createdAt,
							updatedAt: user.updatedAt,
						},
					});
				},
			),
		},
		schema: mergeSchema(schema, options?.schema),
		hooks: {
			before: [
				{
					matcher(context) {
						return (
							context.path === "/sign-up/email" ||
							context.path === "/update-user"
						);
					},
					handler: createAuthMiddleware(async (ctx) => {
						const username = ctx.body.username;
						if (username !== undefined && typeof username === "string") {

                            const validator =
                                options?.usernameValidator || defaultUsernameValidator;
                            const validatorResult = validator.safeParse(ctx.body.username);
                            if (!validatorResult.success) {
                                throw new APIError("UNPROCESSABLE_ENTITY", {
                                    message: validatorResult.error.issues.find(() => true)?.message || USERNAME_ERROR_CODES.INVALID_USERNAME,
                                });
                            }

							const user = await ctx.context.adapter.findOne<User>({
								model: "user",
								where: [
									{
										field: "username",
										value: username.toLowerCase(),
									},
								],
							});
							if (user) {
								throw new APIError("UNPROCESSABLE_ENTITY", {
									message: USERNAME_ERROR_CODES.USERNAME_IS_ALREADY_TAKEN,
								});
							}
						}
					}),
				},
				/*{
					matcher(context) {
						return (
							context.path === "/sign-up/email" ||
							context.path === "/update-user"
						);
					},
					handler: createAuthMiddleware(async (ctx) => {
						if (!ctx.body.displayUsername && ctx.body.username) {
							ctx.body.displayUsername = ctx.body.username;
						}
					}),
				},*/
			],
		},
		$ERROR_CODES: USERNAME_ERROR_CODES,
	} satisfies BetterAuthPlugin;
};