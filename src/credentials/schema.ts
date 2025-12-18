import * as z from "zod";
import * as z4 from "zod/v4";
import * as z3 from "zod/v3";

import { isZodV4 } from "../utils/zod.js";

/** check if default z import from zod is v3 or v4
 * The idea here is, if you are using zod 4.0.0 and above, the schema will be created with zod v4
 * If you are using zod v3.x.x, the schema will be created with zod v3
 * 
 * That hopefully way no mixing of zod versions happen
*/
let schema;
if(isZodV4(z.object({ test: z.string() }))) {
    // Even inside the if, webpack and other bundlers get confused sometimes, so we need to use zod/v4 directly
    schema = z4.object({
        email: z4.email().min(1).meta({
            description: "The email of the user",
        }),
        password: z4.string().min(1).meta({
            description: "The password of the user",
        }),
        rememberMe: z4.boolean().optional().meta({
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