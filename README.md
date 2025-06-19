# About
LDAP authentication plugin for Better Auth

(Early version, experimental, the behaviour WILL CHANGE)

## Running the example

Requirements:
- Node.js (v18 or later)
- Docker

1. Clone the repository:
```bash
git clone git@github.com:erickweil/better-auth-ldap.git
cd better-auth-ldap
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

- Now you can login with the LDAP credentials, go to Ldap -> `/sign-in/ldap` and use the following credentials (username & password must be those values):
```json
{
  "username": "professor",
  "password": "professor"
}
```

Using ldap sign-up should be done automatically after the first sucessful sign-in via LDAP, just like social sign-in, unless you have disabled it in the configuration.

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