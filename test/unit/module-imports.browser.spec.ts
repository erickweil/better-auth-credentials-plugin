import { describe, expect, it } from "vitest";
import { credentialsClient, defaultCredentialsSchema } from "../../client.js";
import { isZodV4 } from "../../src/utils/zod.js";

describe("Should be able to import on browser", () => {
    it("should import the module without errors", async () => {
        expect(typeof credentialsClient).toBe("function");
        expect(typeof defaultCredentialsSchema).toBe("object");

        expect(isZodV4(defaultCredentialsSchema)).toBe(true);
    });
});