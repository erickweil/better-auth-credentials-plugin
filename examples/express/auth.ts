import { z } from "zod";
import { betterAuth } from "better-auth";
import { mongodbAdapter } from "better-auth/adapters/mongodb";
import { fromNodeHeaders } from "better-auth/node";
import { createAuthMiddleware, openAPI } from "better-auth/plugins";
import { Request } from "express";
import { MongoClient } from "mongodb";
import { ldap } from "../../src/ldap/index.js";
import { mkdir, writeFile } from "fs/promises";
import { credentials } from "../../src/credentials/index.js";
import { authenticate } from "ldap-authentication";

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

                    username: parsed.credential,
                    userPassword: parsed.password,
                });

                console.log("Auth via LDAP:", parsed, ldapResult);

                return {
                    name: ldapResult.displayName || ldapResult.uid || ldapResult.cn || "LDAP User",
                    email: (Array.isArray(ldapResult.mail) ? ldapResult.mail[0] : ldapResult.mail) || `${ldapResult[process.env.LDAP_SEARCH_ATTR!]}@local`,
                    //image: imageUrl || undefined
                }
            },
        })
        /*ldap({
            autoSignUp: true,
            userCredentialAttribute: "email",
            ldapConfig: {
                ldapOpts: {
                    url: process.env.LDAP_URL!
                },
                adminDn: process.env.LDAP_BIND_DN,
                adminPassword: process.env.LDAP_PASSW,
                userSearchBase: process.env.LDAP_BASE_DN,
                usernameAttribute: process.env.LDAP_SEARCH_ATTR,
                //attributes: ['jpegPhoto;binary', 'displayName', 'uid', 'mail', 'cn'],
            },
            async onLdapAuthenticated(ctx, user, ldapResult) {
                if(user) {
                    console.log("Existing user via LDAP:", user, ldapResult);
                } else {
                    console.log("New User via LDAP:", ldapResult);
                }

                / *
                // TODO: Handle binary data
                // https://github.com/shaozi/ldap-authentication
                // In version 3, the raw field is no longer used. Instead, append ;binary to the attributes you want to get back as base64-encoded string.
                // https://github.com/shaozi/ldap-authentication/issues/82
                
                let imageUrl;
                let jpegPhoto = ldapResult["jpegPhoto;binary"];
                if(jpegPhoto) {
                    await mkdir("./public/images/users", { recursive: true });
                    await writeFile(`./public/images/users/${ldapResult.uid}.jpg`, jpegPhoto, 'binary');
                    imageUrl = `/images/users/${ldapResult.uid}.jpg`;
                }* /

                return {
                    name: ldapResult.displayName || ldapResult.uid || ldapResult.cn || "LDAP User",
                    email: (Array.isArray(ldapResult.mail) ? ldapResult.mail[0] : ldapResult.mail) || `${ldapResult.uid}@ldap.local`,
                    //image: imageUrl || undefined
                }
            },
        })*/
    ],
});

// https://github.com/Bekacru/t3-app-better-auth/blob/main/src/server/auth.ts
export const getSession = async (req: Request) => {
  return await auth.api.getSession({
    headers: fromNodeHeaders(req.headers)
  })
};