import { describe, expect, test, beforeAll } from "vitest";
import app from "../../examples/hashing/server.js"; // Supondo que o segundo exemplo esteja neste caminho
import supertest from "supertest";
import { testCases } from "../test-helpers.js";

describe("Credentials Provider with Hashing and Account Linking", () => {
  const req = supertest(app);
  const existingUser = {
    email: "existing.user@example.com",
    password: "password123", // Senha original do usuário
  };
  const credentialsUser = {
    email: "credentials.user@example.com",
    password: "a-very-secure-password-123",
  };

  // 1. Antes de tudo, crie um usuário padrão (email/senha) para testar a vinculação da conta.
  beforeAll(async () => {
    await req
      .post("/api/auth/sign-up/email")
      .set("Accept", "application/json")
      .send({
        name: "Existing User",
        email: existingUser.email,
        password: existingUser.password,
      })
      .expect(200);
  });

  test("Should sign up a new user via credentials provider", async () => {
    const response = await req
      .post("/api/auth/sign-in/credentials")
      .set("Accept", "application/json")
      .send({
        email: credentialsUser.email,
        password: credentialsUser.password,
      })
      .expect(200);

    const { user } = response.body;
    expect(user).toBeTruthy();
    expect(user.email).toBe(credentialsUser.email);
    expect(user.name).toBe("credentials.user"); // Nome gerado automaticamente
    expect(user.image).toBe("http://example.com/new.png"); // Imagem de novo usuário
  });

  // 3. Testa o login de um usuário que já se registrou através do provedor 'credentials'.
  test("Should sign in an existing credentials user", async () => {
    const response = await req
      .post("/api/auth/sign-in/credentials")
      .set("Accept", "application/json")
      .send({
        email: credentialsUser.email,
        password: credentialsUser.password,
      })
      .expect(200);

    const { user } = response.body;
    expect(user).toBeTruthy();
    expect(user.email).toBe(credentialsUser.email);

    // Verifica se o cookie de sessão foi retornado
    const setCookieHeader = response.headers["set-cookie"];
    expect(setCookieHeader).toBeTruthy();
  });

  // 4. Testa a vinculação do provedor 'credentials' a uma conta que já existia (criada no beforeAll).
  test("Should link credentials provider to an existing account", async () => {
    let cookies = "";
    // Primeiro, faz o login/vinculação
    {
      const response = await req
        .post("/api/auth/sign-in/credentials")
        .set("Accept", "application/json")
        .send({
          email: existingUser.email, // Email do usuário já existente
          password: "new-secure-password-for-linking",
        })
        .expect(200);

      const { user } = response.body;
      expect(user).toBeTruthy();
      expect(user.email).toBe(existingUser.email);
      expect(user.name).toBe("Existing User"); // Deve manter o nome original
      expect(user.image).toBe("http://example.com/linked.png"); // Imagem de conta vinculada

      const setCookieHeader = response.headers["set-cookie"];
      expect(setCookieHeader).toBeTruthy();
      cookies = Array.isArray(setCookieHeader) ? setCookieHeader[0] : setCookieHeader;
    }

    // Em seguida, verifica se a sessão funciona e retorna o usuário correto
    {
      const response = await req
        .get("/me")
        .set("Accept", "application/json")
        .set("Cookie", cookies)
        .expect(200);
      
      const { user, session } = response.body;
      expect(user).toBeTruthy();
      expect(session).toBeTruthy();
      expect(user.email).toBe(existingUser.email);
    }
  });

  // 5. Agrupa todos os casos de falha esperados.
  testCases("fail cases for hashing provider", [
    // Senha fraca
    { status: 401, email: "weak.password@example.com", password: "short" },
    // Senha incorreta para um usuário existente
    { status: 401, email: credentialsUser.email, password: "a-very-secure-but-wrong-password" },
    // Input inválido
    { status: 400, email: "bad@request.com", password: "" },
    { status: 400, email: null, password: "some-password" },
  ], async (testCase) => {
    const { status, ...body } = testCase;

    const response = await req
      .post("/api/auth/sign-in/credentials")
      .set("Accept", "application/json")
      .send(body)
      .expect(status);

      if(status === 400) {
        expect(response.body.code).toBe("VALIDATION_ERROR");
      } else if (status === 401) {
        expect(response.body.code).toBe("INVALID_CREDENTIALS");
      }
  });
});
