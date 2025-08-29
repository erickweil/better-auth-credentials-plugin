import * as z from "zod";
import * as z3 from "zod/v3";

import { isZodV4 } from "../utils/zod.js";

//check if zod is v3 or v4
let schema;
if(isZodV4(z.object({ test: z.string() }))) {
    schema = z.object({
        email: z.email().min(1).meta({
            description: "The email of the user",
        }),
        password: z.string().min(1).meta({
            description: "The password of the user",
        }),
        rememberMe: z.boolean().optional().meta({
            description: "Remember the user session",
        }),
    });    
} else {
    console.log("Using Zod v3");
    schema = z3.object({
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
}

export type DefaultCredentialsType = {
    email: string;
    password: string;
    rememberMe?: boolean | undefined;
};
export const defaultCredentialsSchema = schema;