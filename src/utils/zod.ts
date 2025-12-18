import * as z3 from "zod/v3";
import * as z4 from "zod/v4/core";

export type Zod34Schema = z3.ZodTypeAny | z4.$ZodType;

export const isZodV4 = (schema: Zod34Schema) => {
    return "_zod" in schema;
};

export type inferZod34<T extends Zod34Schema> = T extends z3.ZodTypeAny ? z3.infer<T> : T extends z4.$ZodType ? z4.infer<T> : never;