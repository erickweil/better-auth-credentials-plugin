import { defineErrorCodes } from "better-auth";

// Adaptado de: https://github.com/better-auth/better-auth/blob/main/packages/better-auth/src/plugins/username/error-codes.ts
export const CREDENTIALS_ERROR_CODES = defineErrorCodes({
	INVALID_CREDENTIALS: "invalid credentials",
	EMAIL_REQUIRED: "email is required",
	EMAIL_NOT_VERIFIED: "email not verified",
	UNEXPECTED_ERROR: "unexpected error",
	USERNAME_IS_ALREADY_TAKEN: "username is already taken. please try another.",
});