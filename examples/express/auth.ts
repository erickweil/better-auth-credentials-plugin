import { betterAuth } from "better-auth";
import { mongodbAdapter } from "better-auth/adapters/mongodb";
import { fromNodeHeaders } from "better-auth/node";
import { openAPI } from "better-auth/plugins";
import { Request } from "express";
import { MongoClient } from "mongodb";
import { ldap } from "../../src/ldap/index.js";

// https://www.better-auth.com/docs/adapters/mongo
// For MongoDB, we don't need to generate or migrate the schema.
const client = new MongoClient(process.env.DB_URL_AUTH!);
const db = client.db();

export const auth = betterAuth({
    database: mongodbAdapter(db),
    emailAndPassword: {
        enabled: true,
        requireEmailVerification: false
    },
    plugins: [
        openAPI(),
        ldap({
            adminDn: process.env.LDAP_BIND_DN!,
            adminPassword: process.env.LDAP_PASSW!,
            baseDn: process.env.LDAP_BASE_DN!,
            usernameAttribute: process.env.LDAP_SEARCH_ATTR,
            onLdapAuthenticated(ctx, user, ldapResult) {
                console.log("Usuário autenticado via LDAP:", user, ldapResult);
            },
            ldapOptions: {
                url: process.env.LDAP_URL!
            },
        })
    ],

    user: {
        /*additionalFields: {
            username: {
                type: "string",
                validator: {
                    input: z.string().min(3).max(32).regex(/^[a-zA-Z0-9_\-]+$/, "Nome de usuário inválido"),
                },
                required: false,
                select: true,
                unique: true,
            },
        }*/
    },
});

// https://github.com/Bekacru/t3-app-better-auth/blob/main/src/server/auth.ts
export const getSession = async (req: Request) => {
  return await auth.api.getSession({
    headers: fromNodeHeaders(req.headers)
  })
};