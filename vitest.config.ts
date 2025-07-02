// eslint-disable-next-line @typescript-eslint/triple-slash-reference
/// <reference types="vitest/config" />
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test\/**\/*.{test,spec}.{ts,js}"],
    env: {
        // Define environment variables for tests
        NODE_ENV: "test",
        DB_URL_AUTH: "mongodb://127.0.0.1:27017/better-auth-test"
    },
    silent: "passed-only",
    globalSetup: ["test\/setup.ts"],
    projects: [
        {
            extends: true,
            test: {
                exclude: ["**\/*.browser.*"],
                name: "node",
                environment: "node"
            }
        },
        {
            extends: true,
            test: {
                exclude: ["**\/*.node.*"],
                name: "browser",
                environment: "happy-dom"
            }
        }
    ]
  },
});