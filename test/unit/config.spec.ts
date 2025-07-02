import { describe, expect, test } from "vitest";
import { credentials } from "../../src/credentials/index.js";
import z3 from "zod";
import { User } from "better-auth";

describe("Test config options calling the plugin", () => {

  test("Minimal config", () => {
    credentials({
      callback(ctx, parsed) {
          return {};
      },
    });
  });

  test("All options", () => {
    credentials({
      autoSignUp: true,
      inputSchema: z3.object({
        credential: z3.string().min(1),
        password: z3.string().min(1),
      }),
      linkAccountIfExisting: false,
      path: "/auth/credentials",
      providerId: "config",
      UserType: {} as User & { a?: boolean },
      callback: (ctx, parsed) => {
        return {
          email: parsed.credential + "@example.com",
          
          onSignIn(userData, user, account) {
            return userData;
          },
          onSignUp(userData) {
            return userData;
          },
        };
      }
    });
  });
});