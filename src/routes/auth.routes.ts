import { Router } from "express";
import {
  forgotPasswordHandler,
  loginHandler,
  logoutHandler,
  refreshTokenHandler,
  registerHandler,
  resetPasswordHandler,
  verifyEmailHandler,
} from "../controllers/auth/auth.controller";
import { googleAuthCallbackHandler, googleAuthStartHandler } from "../controllers/auth/google.controller";


const authRouter = Router();

authRouter.post("/register", registerHandler);

authRouter.get("/verify-email", verifyEmailHandler);

authRouter.post("/login", loginHandler);

authRouter.post("/refresh", refreshTokenHandler);

authRouter.post("/logout", logoutHandler);

authRouter.post("/forgot-password", forgotPasswordHandler);


authRouter.post("/reset-password", resetPasswordHandler);

// Google OAuth routes
authRouter.get("/google", googleAuthStartHandler);
authRouter.get("/google/callback", googleAuthCallbackHandler);

export default authRouter;
