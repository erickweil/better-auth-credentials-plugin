import { describe, expect, test } from "vitest";
import app from "../../examples/basic/server.js";
import supertest  from "supertest";
import { testCases } from "../test-helpers.js";

describe("Fake login, should fail when email and password are different", () => {
  const req = supertest(app);

  testCases("success cases", [
    { email: "basic-user1@example.com", password: "basic-user1@example.com" }, 
    { email: "basic-user2@example.com", password: "basic-user2@example.com" },
    { email: "basic-user2@example.com", password: "basic-user2@example.com" }  // Usuário existente
  ], async (testCase) => {   
      let cookies = "";
      { // 1 - Deve fazer login
        const response = await req
            .post("/api/auth/sign-in/credentials")
            .set("Accept", "application/json")
            .send({
                email: testCase.email,
                password: testCase.password
            })
            .expect(200);

        expect(response?.body).toBeTruthy();
        const { user } = response.body;
        expect(user).toBeTruthy();
        expect(user.email).toBe(testCase.email);

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
        expect(user.email).toBe(testCase.email);
      }
  });

  test("Create normal email & password account", async () => {
    const response = await req
      .post("/api/auth/sign-up/email")
      .set("Accept", "application/json")
      .send({
        name: "new-user",
        email: "new.user@example.com",
        password: "new.user@example.com"
      })
      .expect(200);
  });

  testCases("fail cases", [
    { status: 400 },
    { status: 400, email: "", password: "" },
    { status: 400, email: null, password: null },
    { status: 400, email: "invalid", password: "invalid" },
    { status: 401, email: "abcd@example.com", password: "wrongpassword" },
    { status: 401, email: "basic-user1@example.com", password: "wrongpassword" },
    { status: 401, email: "basic-user1@example.com", password: "basic-user2@example.com" },
    { status: 401, email: "new.user@example.com", password: "new.user@example.com" }, // Deve falhar pois esse usuário foi criado com o método de sign-up normal
  ], async (testCase) => {    
    const { status, ...body } = testCase;

    const response = await req
      .post("/api/auth/sign-in/credentials")
      .set("Accept", "application/json")
      .send(body)
      .expect(status);
  });

});