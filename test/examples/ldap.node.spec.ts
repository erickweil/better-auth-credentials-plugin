import { describe, expect, test } from "vitest";
import app from "../../examples/ldap-auth/server.js";
import supertest  from "supertest";
import { testCases } from "../test-helpers.js";

describe("LDAP, should authenticate users on LDAP server", () => {
  const req = supertest(app);

  testCases("success cases", [
    { credential: "fry", password: "fry" }, 
    { credential: "professor", password: "professor" },
    { credential: "professor", password: "professor" }  // Usuário existente
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

        const { image, ldap_dn, groups, description } = user;
        
        expect(ldap_dn).toBeUndefined(); // Não deve retornar o DN do usuário (Salvo no banco mas não retorna)
        expect(image).toBeTruthy();
        expect(groups).toBeTruthy();
        expect(description).toBeTruthy();

        // Verificar se imagem foi salva
        const imageResponse = await req
            .get(user.image)
            .set("Accept", "image/jpeg")
            .expect(200);
        expect(imageResponse.headers["content-type"]).toBe("image/jpeg");
        expect(imageResponse.body).toBeTruthy();
      }
  });

  testCases("fail cases", [
    { status: 400 },
    { status: 400, email: "invalid", password: "invalid" },
    { status: 400, credential: "", password: "" },
    { status: 400, credential: null, password: null },
    { status: 401, credential: "abcd", password: "wrongpassword" },
    { status: 401, credential: "fry", password: "wrongpassword" },
    { status: 401, credential: "bender", password: "password3" }
  ], async (testCase) => {    
    const { status, ...body } = testCase;

    const response = await req
      .post("/api/auth/sign-in/credentials")
      .set("Accept", "application/json")
      .send(body)
      .expect(status);
  });

});