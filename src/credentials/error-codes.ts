// Adaptado de: https://github.com/better-auth/better-auth/blob/main/packages/better-auth/src/plugins/username/error-codes.ts
export const CREDENTIALS_ERROR_CODES = {
	INVALID_CREDENTIALS: "invalid credentials",
	EMAIL_REQUIRED: "email is required",
	EMAIL_NOT_VERIFIED: "email not verified",
	UNEXPECTED_ERROR: "unexpected error",
	USERNAME_IS_ALREADY_TAKEN: "username is already taken. please try another.",
    USER_NOT_FOUND: "user not found",
    NO_USER_DATA_PROVIDED: "no user data provided by the authentication callback",
    ACCOUNT_NOT_FOUND: "account not found for the given provider",
    ACCOUNT_HAS_PASSWORD: "account has a password set, cannot login with credentials provider",
};