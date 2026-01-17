import express from "express";
import cookieParser from "cookie-parser";
import authRouter from "./routes/auth.routes";
import userRouter from "./routes/user.routes";

const app = express();

//middlewares
app.use(express.json());
app.use(cookieParser());

//routes
app.use("/api/auth", authRouter);
app.use("/api/user", userRouter);



export default app;
