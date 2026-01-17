import { Request, Response } from "express";
import { OAuth2Client } from "google-auth-library";
import User from "../../models/user.model";
import crypto from "crypto";
import { hashPassword } from "../../lib/hash";
import { createAccessToken, createRefreshToken } from "../../lib/token";

const getGoogleClient = () => {
  const clientId = process.env.GOOGLE_CLIENT_ID!;
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET!;
  const redirectUri = process.env.GOOGLE_REDIRECT_URI!;

  return new OAuth2Client({
    clientId,
    clientSecret,
    redirectUri,
  });
};

export const googleAuthStartHandler = (req: Request, res: Response) => {
  try {
    const client = getGoogleClient();
    const url = client.generateAuthUrl({
      access_type: "offline",
      prompt: "consent",
      scope: ["profile", "email", "openid"],
    });

    return res.redirect(url);
  } catch (error) {
    return res.status(500).json({ message: "Internal server error" });
  }
};

export const googleAuthCallbackHandler = async (req: Request,res: Response) => {
  // 1. Read authorization code sent by Google
  const code = req.query.code as string;
  if (!code) {
    return res.status(400).json({ message: "Code not provided" });
  }

  try {
    // 2. Create OAuth client
    const client = getGoogleClient();

    // 3. Exchange authorization code for tokens
    const { tokens } = await client.getToken(code);

    // 4. Ensure ID token exists (required for identity verification)
    if (!tokens.id_token) {
      return res.status(400).json({ message: "ID token not provided" });
    }

    // 5. Verify ID token (authenticity + audience)
    const ticket = await client.verifyIdToken({
      idToken: tokens.id_token,
      audience: process.env.GOOGLE_CLIENT_ID!,
    });

    // 6. Extract user information from Google
    const payload = ticket.getPayload();
    const email = payload?.email;
    const emailVerified = payload?.email_verified;

    // 7. Ensure email exists and is verified
    if (!email || !emailVerified) {
      return res.status(400).json({ message: "Email not verified" });
    }

    // 8. Find existing user or create new one
    let user = await User.findOne({ email });

    if (!user) {
      // Generate random password (user logs in via Google)
      const randomPassword = crypto.randomBytes(16).toString("hex");
      const passwordHash = await hashPassword(randomPassword);

      user = await User.create({
        email,
        passwordHash,
        role: "user",
        isEmailVerified: true,
        twoFactorEnabled: false,
      });
    } else if (!user.isEmailVerified) {
      // Ensure email is verified if user existed earlier
      user.isEmailVerified = true;
      await user.save();
    }

    // 9. Create application-specific tokens
    const accessToken = createAccessToken(
      user.id,
      user.role as "user" | "admin",
      user.tokenVersion
    );

    const refreshToken = createRefreshToken(user.id, user.tokenVersion);

    // 10. Store refresh token securely in cookie
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    // 11. Respond with access token and user data
    return res.json({
      message: "Google login successful",
      accessToken,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        isEmailVerified: user.isEmailVerified,
      },
    });
  } catch (error) {
    console.error("Google auth callback error:", error);
    return res.status(500).json({ message: "Google authentication failed" });
  }
};
