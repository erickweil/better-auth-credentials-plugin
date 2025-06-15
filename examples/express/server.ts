import "dotenv/config";

import express, { ErrorRequestHandler } from "express";
import { toNodeHandler } from "better-auth/node";

import { auth, getSession } from "./auth.js";

const app = express();

// https://www.better-auth.com/docs/installation
// Deve ser antes do middleware de parsing do body
app.all("/api/auth/{*any}", toNodeHandler(auth));

app.get("/", (req, res) => {
    res.status(200).redirect("api/auth/reference"); // redirecionando para documentação
});

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.get("/me", async (req, res) => {
    const session = await getSession(req);
    if (!session) {
        res.status(401).json({ message: "Usuário não autenticado" });
        return;
    }
    
    res.status(200).json({
        user: session?.user || null,
        session: session?.session || null
    });
});

app.use((req, res, next) => {
    res.status(404).json({ message: "Rota não encontrada" });
});

// Middleware de tratamento de erros, sempre por último
const errorHandler: ErrorRequestHandler = (err, req, res, next) => {
    console.error("Erro no servidor:", err);
    res.status(err.status || 500).json({ message: err.message || "Erro interno do servidor" });
};
app.use(errorHandler);

const port = process.env.PORT || 3000;
app.listen(port, () => {
	console.log("Servidor está rodando na porta %d", port);
});

export default app;