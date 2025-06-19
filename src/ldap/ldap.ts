import { authenticate, AuthenticationOptions } from "ldap-authentication";

export const authenticateLdap = async (options: Omit<AuthenticationOptions, "username" | "userPassword">, credential: string, password: string): Promise<unknown> => {
    const { ldapOpts, ...ldapConfig } = options;
    
    const secure = ldapOpts.url.startsWith("ldaps://");
    const result = await authenticate({
        // LDAP client connection options
        ldapOpts: {
            connectTimeout: 5000,
            strictDN: true,
            ...(secure ? {tlsOptions: ldapOpts.tlsOptions} : { minVersion: "TLSv1.2" }),
            ...ldapOpts
        },
        usernameAttribute: "mail",
        username: credential,
        userPassword: password,
        ...ldapConfig
    });

    return result;
};