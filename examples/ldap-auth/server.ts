import "dotenv/config";

import { auth } from "./auth.js";
import { getApp } from "../app.js";

const app = getApp(auth);
export default app;