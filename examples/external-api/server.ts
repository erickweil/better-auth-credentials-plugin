import "dotenv/config";

import { auth } from "./auth.js";
import { getApp } from "../app.js";

const users = new Array(100).fill({}).map((_, index) => ({
    id: index + 1,
    name: `User ${index + 1}`,
    username: `external${index + 1}`,
    email: `external${index + 1}@example.com`,
    password: `password${index + 1}`,
}));

const tokenExpiryDelay = 10 * 60 * 1000; // 10 min
const app = getApp(auth, (_app) => {
    _app.post("/example/login", async (req, res, next) => {
        const { username, password } = req.body;

        // Simula uma autenticação simples
        const foundUser = users.find(user => user.username === username && user.password === password);
        
        if (!foundUser) {
            res.status(401).json({ message: "Usuário ou senha inválidos" });
            return;
        }

        res.status(200).json({
            token: `${foundUser.id}.${Date.now()+tokenExpiryDelay}`, // Just a dummy token for demonstration
            user: {
                ...foundUser,
                password: undefined,
            }
        });
    });

    _app.get("/example/me", async (req, res, next) => {
        const authHeader = req.headers.authorization;
        if (!authHeader) {
            res.status(401).json({ message: "Token de autenticação ausente" });
            return;
        }

        const [,token] = authHeader.split(" ");
        const [userId, expiryAt] = token.split(".");

        if (Date.now() > parseInt(expiryAt)) {
            res.status(401).json({ message: "Token de autenticação expirado" });
            return;
        }

        const foundUser = users.find(user => ""+user.id === userId);
        if (!foundUser) {
            res.status(401).json({ message: "Token de autenticação inválido" });
            return;
        }

        res.status(200).json({
            user: {
                ...foundUser,
                password: undefined,
            }
        });
    });

    _app.post("/example/refresh", async (req, res, next) => {
        const authHeader = req.headers.authorization;
        if (!authHeader) {
            res.status(401).json({ message: "Token de autenticação ausente" });
            return;
        }

        const [,token] = authHeader.split(" ");
        const [userId, expiryAt] = token.split(".");

        if (Date.now() > parseInt(expiryAt)) {
            res.status(401).json({ message: "Token de autenticação expirado" });
            return;
        }
        
        const foundUser = users.find(user => ""+user.id === userId);
        if (!foundUser) {
            res.status(401).json({ message: "Token de autenticação inválido" });
            return;
        }
        
        // Return a new token with extended expiry
        res.status(200).json({
            token: `${foundUser.id}.${Date.now()+tokenExpiryDelay}`,
            user: {
                ...foundUser,
                password: undefined,
            }
        });
    });
});

export default app;