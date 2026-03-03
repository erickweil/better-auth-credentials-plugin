import { describe, expect, test } from "vitest";
import externalApp from "../../examples/external-api/server.js";
import { auth } from "../../examples/external-api/auth.js";
import { testCases } from "../test-helpers.js";
import { authClient } from "../../examples/external-api/client.js";
import { ResponseContext } from "better-auth/client";
import { getApp } from "../../examples/app.js";
import request from "supertest";

describe("External API, make request to auth", () => {
    const externalServer = externalApp.listen(3000);

    const app = getApp(auth);
    const req = request.agent(app);

    const externalReq = request.agent(externalServer);

    testCases("success cases", [
        { username: "external1", password: "password1" },
        { username: "external2", password: "password2" },
        { username: "external2", password: "password2" }  // Usuário existente
    ], async (testCase) => {
        let token;
        {
            const response = await req
                .post("/api/auth/sign-in/external")
                .set("Accept", "application/json")
                .send({
                    username: testCase.username,
                    password: testCase.password
                })
                .expect(200);

            expect(response?.body).toBeTruthy();
            const { user } = response.body;
            expect(user).toBeTruthy();
            expect(user.name).toBeTruthy();
            expect(user.username).toBeTruthy();
            expect(user.email).toBe(testCase.username + "@example.com");
            expect(user.token).toBeTruthy();
            token = user.token;
        }

        {
            const response = await req
                .get("/api/auth/get-session")
                .set("Accept", "application/json")
                .expect(200);

            expect(response?.body).toBeTruthy();
            const { user, session } = response.body;
            expect(user).toBeTruthy();
            expect(user.email).toBe(testCase.username + "@example.com");
            expect(session).toBeTruthy();
            expect(session.token).toBeTruthy();
        }

        {
            const response = await externalReq
                .get("/example/me")
                .set("Accept", "application/json")
                .set("Authorization", `Bearer ${token}`)
                .expect(200);

            expect(response?.body).toBeTruthy();
            const { user } = response.body;
            expect(user).toBeTruthy();
            expect(user.email).toBe(testCase.username + "@example.com");
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
        const { data, error } = await authClient.signIn.external(body as any);
        console.log(error);
        expect(data).toBeFalsy();
        expect(error).toBeTruthy();
        expect(error?.status).toBe(status);
        expect(error?.message).toBeTruthy();
    });

});