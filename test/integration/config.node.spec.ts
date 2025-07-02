import { describe, expect, test } from "vitest";
import { credentials } from "../../src/credentials/index.js";
import z3 from "zod";
import { betterAuth, BetterAuthPlugin, User } from "better-auth";
import { MongoClient } from "mongodb";
import { mongodbAdapter } from "better-auth/adapters/mongodb";
import { getApp } from "../../examples/app.js";
import supertest from "supertest";
import TestAgent from "supertest/lib/agent.js";

describe("Test config options calling the plugin", () => {
  const client = new MongoClient(process.env.DB_URL_AUTH!);
  const db = client.db();

  function buildAppPlugin(plugin: BetterAuthPlugin) {
    const auth = betterAuth({
      database: mongodbAdapter(db),
      emailAndPassword: {
        enabled: true,
      },
      plugins: [
        plugin
      ],
    });

    const app = getApp(auth);
    const req = supertest(app);
    return { app, req };
  }

  test("Minimal config", async () => {
    const { req } = buildAppPlugin(credentials({
      autoSignUp: true,
      callback(ctx, parsed) {
        return {};
      },
    }));

    // Sign up a new user
    const response = await req.post("/api/auth/sign-in/credentials")
    .set("Accept", "application/json")
    .send({
      email: "config_email@example.com",
      password: "password"
    })
    .expect(200);

    expect(response).toBeTruthy();
    expect(response.body).toMatchObject({
      user: {
        name: "config_email@example.com",
        email: "config_email@example.com"
      }
    });
    
    // Shouldn't be able to sign in using user created with email & password
    await req
      .post("/api/auth/sign-up/email")
      .set("Accept", "application/json")
      .send({
        name: "Email Config User",
        email: "config_email2@example.com",
        password: "password"
      })
      .expect(200);

    await req.post("/api/auth/sign-in/credentials")
    .set("Accept", "application/json")
    .send({
      email: "config_email2@example.com",
      password: "password"
    })
    .expect(401);
  });

  test("All options", async () => {
    const { req } = buildAppPlugin(credentials({
      autoSignUp: true,
      inputSchema: z3.object({
        credential: z3.string().min(1),
        password: z3.string().min(1),
      }),
      linkAccountIfExisting: true,
      path: "/my-sign-in",
      providerId: "config",
      UserType: {} as User & { a?: boolean },
      callback: (ctx, parsed) => {
        return {
          email: parsed.credential + "@example.com",

          onSignIn(userData, user, account) {
            userData.name = user.name + "?";
            return userData;
          },
          onSignUp(userData) {
            userData.name = parsed.credential;
            return userData;
          },
        };
      }
    }));

    const response = await req.post("/api/auth/my-sign-in")
    .set("Accept", "application/json")
    .send({
      credential: "config_email2",
      password: "password"
    })
    .expect(200);

    console.log(response.body);
    
    expect(response).toBeTruthy();
    expect(response.body).toMatchObject({
      user: {
        name: "Email Config User?",
        email: "config_email2@example.com"
      }
    });

    const response2 = await req.post("/api/auth/my-sign-in")
    .set("Accept", "application/json")
    .send({
      credential: "config_email3",
      password: "password"
    })
    .expect(200);

    console.log(response2.body);
    
    expect(response2).toBeTruthy();
    expect(response2.body).toMatchObject({
      user: {
        name: "config_email3",
        email: "config_email3@example.com"
      }
    });
  });
});