import { betterAuth, User } from "better-auth";
import { mongodbAdapter } from "better-auth/adapters/mongodb";
import { fromNodeHeaders } from "better-auth/node";
import { openAPI } from "better-auth/plugins";
import { Request } from "express";
import { MongoClient } from "mongodb";
import { credentials } from "../../src/credentials/index.js";
import { authenticate } from "ldap-authentication";
import { default as z } from "zod";
import { mkdir, writeFile } from "fs/promises";

// https://www.better-auth.com/docs/adapters/mongo
// For MongoDB, we don't need to generate or migrate the schema.
const client = new MongoClient(process.env.DB_URL_AUTH!);
const db = client.db();

async function saveImageToDisk(id: string, base64Jpeg: string) {
    await mkdir("./public/images/users", { recursive: true });

    const imageUrl = `/public/images/users/${id}.jpg`;
    await writeFile("."+imageUrl, base64Jpeg, "base64");

    return imageUrl;
}

export const auth = betterAuth({
    database: mongodbAdapter(db),
    emailAndPassword: {
        enabled: true,
    },
    user: {
        additionalFields: {
            // Add additional fields to the user model
            ldap_dn: {
                type: "string",
                returned: false,
                required: false,
            },
            description: {
                type: "string",
                returned: true,
                required: false,
            },
            groups: {
                type: "string[]",
                returned: true,
                required: false,
                defaultValue: [],
            }
        }
    },
    plugins: [
        openAPI(),
        credentials({
            // User type to use, this will be used to type the user in the callback
            // This way the zod schema will infer correctly, otherwise you would have to pass both generic types explicitly
            UserType: {} as User & {
                ldap_dn: string,
                description: string,
                groups: string[]
            },
            // Sucessful authenticated users will have a 'ldap' Account linked to them, no matter if they previously exists or not
            autoSignUp: true,
            linkAccountIfExisting: true,
            providerId: "ldap",
            inputSchema: z.object({
                credential: z.string().min(1),
                password: z.string().min(1)
            }),
            // Credentials login callback, this is called when the user submits the form
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
                    explicitBufferAttributes: ["jpegPhoto"],

                    username: parsed.credential,
                    userPassword: parsed.password,
                });
                const uid = ldapResult[process.env.LDAP_SEARCH_ATTR!];
                
                return {
                    // Required to return email to identify the user, as the inputSchema does not have it
                    email: (Array.isArray(ldapResult.mail) ? ldapResult.mail[0] : ldapResult.mail) || `${uid}@local`,

                    // Atributes that will be saved in the user, regardless if is sign-in or sign-up
                    ldap_dn: ldapResult.dn,
                    name: ldapResult.displayName || uid,
                    description: ldapResult.description || "",
                    groups: ldapResult.objectClass && Array.isArray(ldapResult.objectClass) ? ldapResult.objectClass : [],
                    
                    // Callback that is called after sucessful sign-up (New user)
                    async onSignUp(userData) {
                        // Only on sign-up we save the image to disk and save the url in the user data
                        if(ldapResult.jpegPhoto) {
                            userData.image = await saveImageToDisk(ldapResult.uid, ldapResult.jpegPhoto);
                        }

                        return userData;
                    },
                };
            },
        })
    ],
});