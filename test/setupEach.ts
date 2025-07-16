import { afterAll, beforeAll } from "vitest";
import { setup, teardown } from "vitest-mongodb";

if(!globalThis.__MONGO_URI__) {
  await setup();
}
process.env.DB_URL_AUTH = globalThis.__MONGO_URI__;

afterAll(async () => {
  await teardown();
});