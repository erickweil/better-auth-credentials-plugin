import express, { ErrorRequestHandler } from "express";
import { fromNodeHeaders, toNodeHandler } from "better-auth/node";
export function getApp(auth: any, callback?: (app: express.Express) => void) {
    const app = express();

    // https://www.better-auth.com/docs/installation
    // Deve ser antes do middleware de parsing do body
    app.all("/api/auth/{*any}", toNodeHandler(auth));

    app.get("/", (req, res) => {
        res.status(200).redirect("api/auth/reference"); // redirecionando para documentação
    });

    // Serve static files from the public directory
    app.use("/public", express.static("public"));

    app.use(express.json());
    app.use(express.urlencoded({ extended: false }));

    app.get("/me", async (req, res) => {
        // https://github.com/Bekacru/t3-app-better-auth/blob/main/src/server/auth.ts
        const session = await auth.api.getSession({
            headers: fromNodeHeaders(req.headers)
        });
        if (!session) {
            res.status(401).json({ message: "Usuário não autenticado" });
            return;
        }
        
        res.status(200).json({
            user: session?.user || null,
            session: session?.session || null
        });
    });

    if (callback) {
        callback(app);
    }

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

    return app;
}