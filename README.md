# Better Auth Credentials Plugin
Generic credentials authentication plugin for Better Auth

The plugin itself can be used to authenticate to anything, as are you that handle the logic that verify user input credentials in the callback, and just need to return user data that will be used to create/update the user in the database.

(Early version, experimental, the behaviour WILL CHANGE)

## Features
- Full control over the authentication process
- Auto sign-up (optional) and management of Account linking and session creation
- Similar in behaviour to the default email & password flow, but YOU handle the verification of the credentials and allow automatically sign-up
- Route customization, you can choose the route path and the body parameters (using zod schema that doubles as validation and OpenAPI documentation)

Examples:
- examples/express - Express.js example configured with MongoDB and uses this plugin to perform LDAP authentication, showing how easy is to use it

Considerations:
- You need to return a `email` field after the authentication, this is used to create/update the user in the database, and also to link the account with the session (email field should be unique).
- It's not intended to use this to re-implement password login, but to be used when you need to integrate with an external system that uses credentials for authentication, like LDAP, or any other system that you can verify the credentials and get user data. If you try to mimic password login by hashing and storing the password, aditional database round-trips will be needed as this plugin will search the user again after you alread did (just use the email & password flow or username plugin don't do this).

## Basic usage

To use this plugin, you need to install it and configure it in your Better Auth application. The plugin provides a way to authenticate users using credentials (like username and password) and can be customized to fit your needs.

**Installation**
```bash
npm install better-auth-credentials-plugin
```
> LOL THIS IS NOT PUBLISHED YET

Hello world usage example (just to show how to use the plugin):
`src/lib/auth.ts`
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
                if(parsed.email === "test@example.com" && parsed.password === "password") {
                    return {
                        name: "Test User",
                        email: "test@example.com",
                    };
                } else {
                    throw new Error("Invalid credentials");
                }
            },
        })
    ],
});
```


## Running the example

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
cp ./examples/express/.env.example ./examples/express/.env
npm run example:express
```
> If on windows, this may not work, you will need to run the example manually:
> ```bash
> cd examples/express
> node ../../dist/examples/express/server.js
> ```

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

(No tests yet)
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