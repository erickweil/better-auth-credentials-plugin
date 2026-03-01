import { describe, expect, test } from "vitest";
import app from "../../examples/external-api/server.js";
import { testCases } from "../test-helpers.js";
import { authClient } from "../../examples/external-api/client.js";

describe("External API, make request to auth", () => {

  const server = app.listen(3000);

  testCases("success cases", [
    { username: "external1", password: "password1" }, 
    { username: "external2", password: "password2" },
    { username: "external2", password: "password2" }  // Usuário existente
  ], async (testCase) => {
      
    let sessionToken: string | undefined;
    {
      const { data, error } = await authClient.signIn.external({
          username: testCase.username,
          password: testCase.password,
          fetchOptions: {
              onResponse(context) {
                  const cookie = context.response.headers.getSetCookie().filter((c) => c.includes("better-auth.session_token="))[0];
                  if (cookie) {
                      // Extract the session token from the cookie
                      sessionToken = cookie.split("=")[1];
                      sessionToken = sessionToken?.split(";")[0]; // Remove any attributes like `; Path=/; HttpOnly`
                  }
              },
          }
      });
      expect(data).toBeTruthy();
      expect(data?.user).toBeTruthy();
      expect(data?.user.name).toBeTruthy();
      expect((data?.user as any).username).toBeUndefined();
      expect(data?.user.email).toBe(testCase.username+"@example.com");
      expect(error).toBeFalsy();

      expect(sessionToken).toBeTruthy();
      expect(sessionToken).toContain(".");
    }

    {
      const { data, error} = await authClient.getSession({
        fetchOptions: {
          headers: {
            "Authorization": `Bearer ${sessionToken}`
          }
        }
      });
      expect(error).toBeFalsy();
      expect(data).toBeTruthy();

      expect(data?.user).toBeTruthy();
      expect(data?.user.email).toBe(testCase.username+"@example.com");
    }
  });

  testCases("fail cases", [
    { status: 400, email: "", password: "" },
    { status: 400, email: null, password: null },
    { status: 400, email: "invalid", password: "invalid" },
    { status: 400, username: "", password: "" },
    { status: 400, username: null, password: null },
    { status: 400, email: "abcd@example.com", password: "wrongpassword" },
    { status: 401, username: "abcd", password: "wrongpassword" },
    { status: 401, username: "external1", password: "wrongpassword" },
    { status: 401, username: "external2", password: "password3" }
  ], async (testCase) => {    
    const { status, ...body } = testCase;
      const {data, error} = await authClient.signIn.external(body as any);
      console.log(error);
      expect(data).toBeFalsy();
      expect(error).toBeTruthy();
      expect(error?.status).toBe(status);
      expect(error?.message).toBeTruthy();
  });

});