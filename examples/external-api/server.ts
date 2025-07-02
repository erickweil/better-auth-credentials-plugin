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
            ...foundUser,
            password: undefined,
        });
    });
});

export default app;