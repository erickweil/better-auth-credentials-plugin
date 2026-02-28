import { describe, expect, test } from "vitest";
import app from "../../examples/ldap-auth/server.js";
import supertest  from "supertest";
import { testCases } from "../test-helpers.js";

// Check if the LDAP server is running
const isLdapConfigured = process.env.LDAP_URL && process.env.LDAP_BIND_DN && process.env.LDAP_PASSW && process.env.LDAP_BASE_DN && process.env.LDAP_SEARCH_ATTR;

describe.skipIf(!isLdapConfigured)("LDAP, should authenticate users on LDAP server", () => {
  const req = supertest(app);


  test("Create normal email & password account", async () => {
    const response = await req
      .post("/api/auth/sign-up/email")
      .set("Accept", "application/json")
      .send({
        name: "new-ldap-user",
        email: "bender@planetexpress.com",
        password: "bender@planetexpress.com"
      })
      .expect(200);

    expect(response.body).toBeTruthy();
  });

  testCases("success cases", [
    { credential: "fry", password: "fry" },  // Sign-up
    { credential: "professor", password: "professor" }, // Sign-up
    { credential: "professor", password: "professor" }, // Sign-in
    { credential: "bender", password: "bender" }, // Account linking
    { credential: "bender", password: "bender" } // Sign-in
  ], async (testCase) => {   
      let cookies = "";
      { // 1 - Deve fazer login
        const response = await req
            .post("/api/auth/sign-in/credentials")
            .set("Accept", "application/json")
            .send({
                credential: testCase.credential,
                password: testCase.password
            })
            .expect(200);

        expect(response?.body).toBeTruthy();
        const { user } = response.body;
        expect(user).toBeTruthy();
        expect(user.image).toBeTruthy();

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

        const { image, groups, description } = user;
        
        expect(image).toBeTruthy();
        expect(groups).toBeTruthy();
        expect(Array.isArray(groups)).toBeTruthy();
        expect(description).toBeTruthy();

        // Verificar se imagem foi salva
        const imageResponse = await req
            .get(user.image)
            .set("Accept", "image/jpeg")
            .expect(200);
        expect(imageResponse.headers["content-type"]).toBe("image/jpeg");
        expect(imageResponse.body).toBeTruthy();
        
      }

      {
        // 3 verificar Account
        const response = await req
            .get("/api/auth/list-accounts")
            .set("Accept", "application/json")
            .set("Cookie", cookies) // Envia o cookie de sessão
            .expect(200);

        expect(response?.body).toBeTruthy();
        expect(response?.body.length).toBeGreaterThanOrEqual(1);

        const accountLdap = response?.body.find((account: any) => account.providerId === "ldap");
        expect(accountLdap).toBeTruthy();
        expect(accountLdap.providerId).toBe("ldap");
        expect(accountLdap.accountId).toBeTruthy();
      }
  });

  testCases("fail cases", [
    { status: 400 },
    { status: 400, email: "invalid", password: "invalid" },
    { status: 400, credential: "", password: "" },
    { status: 400, credential: null, password: null },
    { status: 401, credential: "abcd", password: "wrongpassword" },
    { status: 401, credential: "fry", password: "wrongpassword" },
    { status: 401, credential: "amy", password: "password3" }
  ], async (testCase) => {    
    const { status, ...body } = testCase;

    const response = await req
      .post("/api/auth/sign-in/credentials")
      .set("Accept", "application/json")
      .send(body)
      .expect(status);
  });

});