import { describe, expect, test } from "vitest";
import { credentials } from "../../src/credentials/index.js";
import * as z from "zod";
import { Account, betterAuth, BetterAuthPlugin, User } from "better-auth";
import { MongoClient } from "mongodb";
import { mongodbAdapter } from "better-auth/adapters/mongodb";
import { getApp } from "../../examples/app.js";
import supertest from "supertest";
import TestAgent from "supertest/lib/agent.js";
import { testCases } from "../test-helpers.js";

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

describe("Test minimal config options calling the plugin", () => {
  const { req } = buildAppPlugin(credentials({
    autoSignUp: true,
    callback(ctx, parsed) {
      return {};
    },
  }));

  test("Minimal config", async () => {
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
        email: "config_email@example.com"
      }
    });
    expect(response.body.user.name).toBeUndefined();

    
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
});

describe("Test all config options calling the plugin", () => {
  const { req } = buildAppPlugin(credentials({
    autoSignUp: true,
    inputSchema: z.object({
      credential: z.string().min(1),
      password: z.string().min(1),
    }),
    linkAccountIfExisting: true,
    path: "/my-sign-in",
    providerId: "config",
    callback: (ctx, parsed) => {
      return {
        email: parsed.credential + "@example.com",

        onSignIn(userData, user, account) {
          if(!account) {
            if(parsed.password.length < 6) {
              return null;
            }
          } else {
            if(parsed.password !== account?.password) {
              return null;
            }
          }

          userData.name = user.name + ":" + (account?.scope || "?");
          return userData;
        },
        onSignUp(userData) {
          if(parsed.password.length < 6) {
            return null;
          }

          userData.name = parsed.credential;
          return userData;
        },
        onLinkAccount(user) {
          return {
            scope: "test",
            password: parsed.password
          };
        },
      };
    }
  }));
  
  testCases("Test cases config options", [
    { 
      status: 401, 
      body: {credential: "config_email2", password: "passw"}, 
      match: {}
    }, // Invalid Sign up
    { 
      status: 200, 
      body: {credential: "config_email2", password: "password"}, 
      match: {name: "Email Config User:?"}  
    }, // Sign up
    {
      status: 200, 
      body: {credential: "config_email2", password: "password"}, 
      match: {name: "Email Config User:?:test"}  
    }, // Sign in
    { 
      status: 401, 
      body: {credential: "config_email2", password: "wrong-pass"}, 
      match: {}  
    }, // Mismatch

    { 
      status: 401, 
      body: {credential: "config_email3", password: "passw"}, 
      match: {}
    }, // Invalid Sign up
    { 
      status: 200, 
      body: {credential: "config_email3", password: "password"}, 
      match: {name: "config_email3"}  
    }, // Sign up
    {
      status: 200, 
      body: {credential: "config_email3", password: "password"}, 
      match: {name: "config_email3:test"}  
    }, // Sign in
    { 
      status: 401, 
      body: {credential: "config_email3", password: "wrong-pass"}, 
      match: {}  
    }, // Mismatch
  ], async ({status, body, match}) => {
    const response = await req.post("/api/auth/my-sign-in")
    .set("Accept", "application/json")
    .send(body)
    .expect(status);

    if(status >= 200 && status < 300) {
      const respBody = response.body;
      expect(respBody?.user).toBeTruthy();

      expect(respBody.user).toMatchObject(match);
    }
  });
});