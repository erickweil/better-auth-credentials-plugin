# Better Auth Credentials Plugin

[![npm version](https://badge.fury.io/js/better-auth-credentials-plugin.svg)](https://badge.fury.io/js/better-auth-credentials-plugin)

Generic credentials authentication plugin for Better Auth

The plugin itself can be used to authenticate to anything, as are you that handle the logic that verify user input credentials in the callback, and just need to return user data that will be used to create/update the user in the database.

(Early version, experimental, the behaviour WILL CHANGE)

## Features
- Full control over the authentication process
- Auto sign-up (optional) and management of Account linking and session creation
- Similar in behaviour to the default email & password flow, but YOU handle the verification of the credentials and allow automatically sign-up
- Route customization, you can choose the route path and the body parameters (using zod schema that doubles as validation and OpenAPI documentation)
- Supports custom callbacks for sign-in and sign-up events

Examples (All are built using express + MongoDB):
- examples/basic - Basic usage example with a fake user store, showcasing the credentials callback functionality and how to handle user data
- examples/ldap-auth - Uses this plugin to perform LDAP authentication, showing how easy is to use it

Considerations:
- You need to return a `email` field after the authentication, this is used to create/update the user in the database, and also to link the account with the session (email field should be unique).
- It's not intended to use this to re-implement password login, but to be used when you need to integrate with an external system that uses credentials for authentication, like LDAP, or any other system that you can verify the credentials and get user data. If you try to mimic password login by hashing and storing the password, aditional database round-trips will be needed as this plugin will search the user again after you alread did (just use the email & password flow or username plugin don't do this).

**Installation**
https://www.npmjs.com/package/better-auth-credentials-plugin
```bash
npm install better-auth-credentials-plugin
```

## API Details

### Configuration of the plugin

To use this plugin, you need to install it and configure it in your Better Auth application. The plugin provides a way to authenticate users using credentials (like username and password) that can be customized to fit your needs.

Hello world usage example (just to show how to use the plugin):
`auth.ts`
```javascript
import { betterAuth } from "better-auth";
import { credentials } from "better-auth-credentials-plugin";

// ...
export const auth = betterAuth({
    /** ... other configs ... */
    emailAndPassword: {
        // Disable email and password authentication
        enabled: false,
    },
    plugins: [
        credentials({
            autoSignUp: true,
            async callback(ctx, parsed) {
                return {};
            },
        })
    ],
});
```

Doing as above would allow any user sign in with any password, and create new users automatically if they don't exist.

The full set of options for the plugin is as follows:

| Attribute                   | Description                                                                      |
|-----------------------------|----------------------------------------------------------------------------------|
| `callback` *               | This callback is the only required option, here you handle the login logic and return the user data to create a new user or update existing ones |
| `inputSchema`                | Zod schema that defined the body contents of the sign-in route, you can put any schema you like, but if it doesn't have an `email` field, you then need to return the email to use in the callback. Defaults to the same as User & Password flow `{email: string, password: string, rememberMe?: boolean}` |
| `autoSignUp`                | If true will create new Users and Accounts if the don't exist |
| `linkAccountIfExisting`                | If true, will link the Account on existing users created with another login method (Only have effect with autoSignUp true) |
| `providerId`                | Id of the Account provider defaults to `credential` |
| `path`                | Path of the route endpoint, defaults to `/sign-in/credentials` |
| `UserType`                | If you have aditional fields in the User type and want correct typescript types in the callbacks, you can set here it's type, example: `{} as User & {lastLogin: Date}` |

If the callback throws an error or returns a falsy value, auth will fail with generic 401 Invalid Credentials error.

You then must return an object with the following shape:
| Attribute                   | Description                                                                      |
|-----------------------------|----------------------------------------------------------------------------------|
| `...userData`              | User data that will be used to create or update the user in the database, this must contain an `email` field if the inputSchema doesn't have it |
| `onSignIn`                 | Callback that will be called after the user is sucesfully signed in. It receives the user data returned above, User and Account from database as parameters, and you should return the mutated user data to update (The account linking happens after this callback, so it can be null) |
| `onSignUp`                 | Callback that will be called after the user is sucesfully signed up (only if autoSignUp is true). It receives the user data returned above, and you should return the mutated user data with the fields a new user should have |
| `onLinkAccount`            | Callback that will be called when a Account is linked to the user. Can happen in a fresh new user sign up or the first time a existing user signs in with this credentials provider. It receives the User from database as parameter, and you should return additional fields to put in the Account being created |

> All those callbacks can be async if you want.

- If the onSignIn throws an error, auth will fail with generic 401 Invalid Credentials error, you can return a falsy value or an empty object to skip updating the user data in the database.
- If the onSignUp returns a object without email field, falsy value or throws an error, auth will fail with generic 401 Invalid Credentials error.

## Usage examples

### Basic: Accept only equal email and password
Example using the plugin to authenticate users with a simple username and password, where the credentials must be the same as the password. This is just for demonstration purposes, 

[examples/basic](examples/basic)
```javascript
credentials({
    autoSignUp: true,
    // Credentials login callback, this is called when the user submits the form
    async callback(ctx, parsed) {
        // Just for demonstration purposes, half of the time we will fail the authentication
        if (parsed.email !== parsed.password) {
            throw new Error("Authentication failed, please try again.");
        }
        
        return {
            // Called if this is a existing user sign-in
            onSignIn(userData, user, account) {
                console.log("Existing User signed in:", user);

                return userData;
            },

            // Called if this is a new user sign-up (only used if autoSignUp is true)
            onSignUp(userData) {
                console.log("New User signed up:", userData.email);

                return {
                    ...userData,
                    name: parsed.email.split("@")[0]
                };
            }
        };
    },
})
```

### Login on external API
Example using the plugin to authenticate users against an external API, when you want to use the plugin to authenticate users against an external system that uses credentials for authentication, like a custom API or service. For this demonstration, the API has predefined users and returns user data after successful authentication.

[examples/external-api](examples/external-api)
```javascript
credentials({
    autoSignUp: true,
    inputSchema: z.object({
        username: z.string().min(1),
        password: z.string().min(1),
    }),
    // Credentials login callback, this is called when the user submits the form
    async callback(ctx, parsed) {
        // Simulate an external API call to authenticate the user
        const { username, password } = parsed;
        const response = await fetch(`http://localhost:${process.env.PORT || 3000}/example/login`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ username, password }),
        });

        if (!response.ok) {
            throw new Error("Error authenticating:"+ ` ${response.status} ${response.statusText}`);
        }

        const apiUser = await response.json();

        return {
            // Must return email, because inputSchema doesn't have it
            email: apiUser.email,

            // Other user data to update
            name: apiUser.name,
            username: apiUser.username,
        };
    },
    })
```

### LDAP Authentication Example
Example using the plugin to authenticate users against an LDAP server, showcasing how to use the plugin with an external authentication system.

> Uses https://github.com/shaozi/ldap-authentication for LDAP authentication

[examples/ldap-auth](examples/ldap-auth)
```javascript
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
```

## Building and running the example

Requirements:
- Node.js (v18 or later)
- Docker

1. Clone the repository:
```bash
git clone https://github.com/erickweil/better-auth-credentials-plugin.git
cd better-auth-credentials-plugin
```

2. Install dependencies and build the project:
```bash
npm install
npm run build
```

3. Start the MongoDB server and the test LDAP server using Docker:
```bash
docker compose up -d
```

4. Run the example:
```bash
cp .env.example .env
npm run example:ldap
```

5. Open your browser and go to `http://localhost:3000`. You should see the better-auth OpenAPI plugin docs

- Now you can login with the LDAP credentials, go to Credentials -> `/sign-in/credentials` and use the following credentials (username & password must be those values):
```json
{
  "credential": "fry",
  "password": "fry"
}
```
> You can use any value from the default values: https://github.com/rroemhild/docker-test-openldap

Using ldap sign-up should be done automatically after the first sucessful sign-in via LDAP, just like social sign-in, (unless you don't have it enabled it in the configuration)

## Running the tests

```bash
docker compose up -d
npm run test
```

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! But please note that this is an early version and not yet ready for anything. If you have any ideas or improvements, feel free to open an issue or submit a pull request.

## Acknowledgements

This project is inspired by the need for a simple and effective way to integrate LDAP authentication into Better Auth. Special thanks to the Better Auth team for their work on the core library.

Also this project would not be possible if not for shaozi/ldap-authentication package which was used for the LDAP authentication
- https://github.com/shaozi/ldap-authentication