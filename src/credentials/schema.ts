import z3 from "zod";

export const defaultCredentialsSchema = z3.object({
	email: z3.string({
		description: "The email of the user",
	}).min(1).email(),
	password: z3.string({
		description: "The password of the user",
	}).min(1),
	rememberMe: z3.boolean({
		description: "Remember the user session",
	}).optional(),
});
export type DefaultCredentialsType = z3.infer<typeof defaultCredentialsSchema>;