import { betterAuth } from "better-auth";
import { mongodbAdapter } from "better-auth/adapters/mongodb";
import { fromNodeHeaders } from "better-auth/node";
import { openAPI } from "better-auth/plugins";
import { Request } from "express";
import { MongoClient } from "mongodb";
import { credentials } from "../../src/credentials/index.js";
import { authenticate } from "ldap-authentication";
import z from "zod";

// https://www.better-auth.com/docs/adapters/mongo
// For MongoDB, we don't need to generate or migrate the schema.
const client = new MongoClient(process.env.DB_URL_AUTH!);
const db = client.db();

export const auth = betterAuth({
    database: mongodbAdapter(db),
    emailAndPassword: {
        // Disable email and password authentication
        // Users will both sign-in and sign-up via LDAP
        enabled: false,
    },
    plugins: [
        openAPI(),
        credentials({
            autoSignUp: true,
            inputSchema: z.object({
                credential: z.string().min(1),
                password: z.string().min(1)
            }),
            async callback(ctx, parsed) {
                // Login via LDAP and return user data
                const secure = process.env.LDAP_URL!.startsWith("ldaps://");
                const ldapResult = await authenticate({
                    // LDAP client connection options
                    ldapOpts: {
                        url: process.env.LDAP_URL!,
                        connectTimeout: 5000,
                        strictDN: true,
                        ...(secure ? {tlsOptions: { minVersion: "TLSv1.2" }} : {})
                    },
                    adminDn: process.env.LDAP_BIND_DN,
                    adminPassword: process.env.LDAP_PASSW,
                    userSearchBase: process.env.LDAP_BASE_DN,
                    usernameAttribute: process.env.LDAP_SEARCH_ATTR,
                    // https://github.com/shaozi/ldap-authentication/issues/82
                    //attributes: ['jpegPhoto;binary', 'displayName', 'uid', 'mail', 'cn'],

                    username: parsed.credential,
                    userPassword: parsed.password,
                });

                console.log("Auth via LDAP:", ldapResult);
                const uid = ldapResult[process.env.LDAP_SEARCH_ATTR!];
                
                return {
                    name: ldapResult.displayName || uid,
                    email: (Array.isArray(ldapResult.mail) ? ldapResult.mail[0] : ldapResult.mail) || `${uid}@local`
                }
            },
        })
    ],
});

// https://github.com/Bekacru/t3-app-better-auth/blob/main/src/server/auth.ts
export const getSession = async (req: Request) => {
  return await auth.api.getSession({
    headers: fromNodeHeaders(req.headers)
  })
};