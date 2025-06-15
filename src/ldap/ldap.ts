import { authenticate } from "ldap-authentication";
import { LDAPOptions } from "./index.js";

export const authenticateLdap = async (options: LDAPOptions, username: string, password: string) => {
    const ldapOptions = options.ldapOptions;
    const secure = ldapOptions.url.startsWith("ldaps://");
    const result = await authenticate({
        // LDAP client connection options
        ldapOpts: {
            url: ldapOptions.url, // "ldap://localhost:389",
            connectTimeout: ldapOptions.connectTimeout || 5000,
            strictDN: true,
            ...(ldapOptions.timeout ? {timeout: ldapOptions.timeout} : {}),
            ...(secure ? {tlsOptions: ldapOptions.tlsOptions} : { minVersion: "TLSv1.2" }),
        },

        // Admin credentials for binding
        adminDn: options.adminDn,
        adminPassword: options.adminPassword,

        // User search options
        userSearchBase: options.baseDn,
        usernameAttribute: options.usernameAttribute || "uid",
        username: username,
        userPassword: password
    });

    return result;
};