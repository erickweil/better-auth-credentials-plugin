import { describe, expect, test } from "vitest";
import app from "../../examples/external-api/server.js";
import supertest  from "supertest";
import { testCases } from "../test-helpers.js";

describe("External API, make request to auth", () => {

  const server = app.listen(3000);

  const req = supertest(server);

  testCases("success cases", [
    { username: "external1", password: "password1" }, 
    { username: "external2", password: "password2" },
    { username: "external2", password: "password2" }  // Usuário existente
  ], async (testCase) => {   
      let cookies = "";
      { // 1 - Deve fazer login
        const response = await req
            .post("/api/auth/sign-in/credentials")
            .set("Accept", "application/json")
            .send({
                username: testCase.username,
                password: testCase.password
            })
            .expect(200);

        expect(response?.body).toBeTruthy();
        const { user } = response.body;
        expect(user).toBeTruthy();
        expect(user.email).toBe(testCase.username+"@example.com");

        // Verifica se o cookie de sessão foi retornado
        const setCookieHeader = response.headers["set-cookie"];
        expect(setCookieHeader).toBeTruthy();
        cookies = Array.isArray(setCookieHeader) ? setCookieHeader[0] : setCookieHeader;
      }

      { // 2 - /me deve retornar o usuário logado
        const response = await req
            .get("/me")
            .set("Accept", "application/json")
            .set("Cookie", cookies) // Envia o cookie de sessão
            .expect(200);
        expect(response?.body).toBeTruthy();
        const { user, session } = response.body;
        expect(user).toBeTruthy();
        expect(session).toBeTruthy();
        expect(user.username).toBe(testCase.username);
      }
  });

  testCases("fail cases", [
    { status: 400 },
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

    const response = await req
      .post("/api/auth/sign-in/credentials")
      .set("Accept", "application/json")
      .send(body)
      .expect(status);
  });

});