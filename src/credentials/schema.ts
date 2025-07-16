import { default as z } from "zod/v3";

export const defaultCredentialsSchema = z.object({
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
export type DefaultCredentialsType = z.infer<typeof defaultCredentialsSchema>;