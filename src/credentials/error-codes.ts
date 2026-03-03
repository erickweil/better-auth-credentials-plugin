import { defineErrorCodes } from "better-auth";

// Adaptado de: https://github.com/better-auth/better-auth/blob/main/packages/better-auth/src/plugins/username/error-codes.ts
export const CREDENTIALS_ERROR_CODES = defineErrorCodes({
	UNEXPECTED_ERROR: "unexpected critical error, please check the server logs for more details", // only for errors that shouldn't ever happen on normal operation
	INVALID_CREDENTIALS: "invalid credentials",
	EMAIL_REQUIRED: "email is required when authenticating with credentials provider",
	EMAIL_NOT_VERIFIED: "email not verified",
	USERNAME_IS_ALREADY_TAKEN: "username is already taken. please try another.",
    USER_NOT_FOUND: "user not found",
	FAILED_TO_CREATE_SESSION: "failed to create a new session",
    NO_USER_DATA_PROVIDED: "no user data provided by the authentication callback",
    ACCOUNT_NOT_FOUND: "account not found for the given provider",
    ACCOUNT_HAS_PASSWORD: "account has a password set, cannot login with credentials provider",
});
