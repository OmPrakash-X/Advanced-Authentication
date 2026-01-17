import { Request, Response } from "express";
import { registerSchema, loginSchema } from "./auth.schema";
import User from "../../models/user.model";
import { checkPassword, hashPassword } from "../../lib/hash";
import jwt from "jsonwebtoken";
import sendEmail from "../../lib/mail";
import {
  createAccessToken,
  createRefreshToken,
  verifyRefreshToken,
} from "../../lib/token";
import crypto from "crypto";

function getAppUrl() {
  return process.env.APP_URL || `http://localhost:${process.env.PORT}`;
}

export const registerHandler = async (req: Request, res: Response) => {
  try {
    const result = registerSchema.safeParse(req.body);
    if (!result.success) {
      return res.status(400).json({
        message: "Invalid data",
        errors: result.error.flatten(),
      });
    }

    const { email, password, name } = result.data;

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ message: "User already exists" });
    }

    const passwordHash = await hashPassword(password);

    const newUser = new User({
      email,
      passwordHash,
      name,
    });
    await newUser.save();

    // ✅ Email verification token
    const verificationToken = jwt.sign(
      { sub: newUser.id },
      process.env.JWT_ACCESS_SECRET!,
      { expiresIn: "60m" }
    );

    const verifyUrl = `${getAppUrl()}/api/auth/verify-email?token=${verificationToken}`;

    // ✅ Send verification email
    await sendEmail(
      email,
      "Email Verification",
      `
        <h2>Email Verification</h2>
        <p>Please verify your email by clicking the link below:</p>
        <p>
          <a href="${verifyUrl}" target="_blank">
            Verify Email
          </a>
        </p>
      `
    );

    return res.status(201).json({
      message: "User registered successfully. Please verify your email.",
      user: {
        id: newUser.id,
        name: newUser.name,
        email: newUser.email,
        role: newUser.role,
        isEmailVerified: newUser.isEmailVerified,
      },
    });
  } catch (error) {
    console.error("Registration Error:", error);
    return res.status(500).json({ message: "Internal Server Error" });
  }
};

export const verifyEmailHandler = async (req: Request, res: Response) => {
  const { token } = req.query as { token?: string };

  if (!token) {
    return res.status(400).json({ message: "Verification token is missing" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET!);

    if (typeof decoded !== "object" || !("sub" in decoded)) {
      return res.status(400).json({ message: "Invalid verification token" });
    }

    const userId = decoded.sub as string;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(400).json({ message: "User not found" });
    }

    if (user.isEmailVerified) {
      return res.json({ message: "Email already verified" });
    }

    user.isEmailVerified = true;
    await user.save();

    return res.json({ message: "Email verification successful" });
  } catch (error: any) {
    console.error("Verification Error:", error);
    if (error.name === "TokenExpiredError") {
      return res.status(400).json({ message: "Verification token expired" });
    }
    if (error.name === "JsonWebTokenError") {
      return res.status(400).json({ message: "Invalid verification token" });
    }
    return res.status(500).json({ message: "Internal Server Error" });
  }
};

export const loginHandler = async (req: Request, res: Response) => {
  try {
    const result = loginSchema.safeParse(req.body);
    if (!result.success) {
      return res.status(400).json({
        message: "Invalid data",
        errors: result.error.flatten(),
      });
    }
    const { email, password } = result.data;
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: "Invalid credentials" });
    }
    const isPasswordValid = await checkPassword(password, user.passwordHash);
    if (!isPasswordValid) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    if (!user.isEmailVerified) {
      return res
        .status(403)
        .json({ message: "Please verify your email to login" });
    }

    const accessToken = createAccessToken(
      user.id,
      user.role,
      user.tokenVersion
    );
    const refreshToken = createRefreshToken(user.id, user.tokenVersion);

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });
    return res.status(200).json({
      message: "Login successful",
      accessToken,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        isEmailVerified: user.isEmailVerified,
        twoFactorEnabled: user.twoFactorEnabled,
      },
    });
  } catch (error) {
    console.error("Login Error:", error);
    return res.status(500).json({ message: "Internal Server Error" });
  }
};

export const refreshTokenHandler = async (req: Request, res: Response) => {
  try {
    const token = req.cookies.refreshToken as string | undefined;
    if (!token)
      return res.status(401).json({ message: "Refresh Token Missing" });

    const payload = await verifyRefreshToken(token);

    const user = await User.findById(payload.sub);
    if (!user) return res.status(401).json({ message: "User not found" });
    if (user.tokenVersion !== payload.tokenVersion) {
      return res.status(401).json({ message: "Token has been revoked" });
    }
    const newAccessToken = createAccessToken(
      user.id,
      user.role,
      user.tokenVersion
    );
    const newRefreshToken = createRefreshToken(user.id, user.tokenVersion);

    res.cookie("refreshToken", newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    return res.status(200).json({
      message: "Token refreshed successfully",
      accessToken: newAccessToken,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        isEmailVerified: user.isEmailVerified,
        twoFactorEnabled: user.twoFactorEnabled,
      },
    });
  } catch (error) {
    console.error("Refresh Token Error:", error);
    return res.status(500).json({ message: "Internal Server Error" });
  }
};

export const logoutHandler = async (req: Request, res: Response) => {
  try {
    const token = req.cookies.refreshToken as string | undefined;

    // If no token, still clear cookie
    if (!token) {
      res.clearCookie("refreshToken", { path: "/" });
      return res.status(200).json({ message: "Logged out successfully" });
    }

    // Decode refresh token to get user ID
    const payload = await verifyRefreshToken(token);

    // Revoke all refresh tokens
    await User.findByIdAndUpdate(payload.sub, {
      $inc: { tokenVersion: 1 },
    });

    // Clear cookie
    res.clearCookie("refreshToken", { path: "/" });

    return res.status(200).json({ message: "Logged out successfully" });
  } catch (error) {
    // Even if token is invalid, still clear cookie
    res.clearCookie("refreshToken", { path: "/" });
    return res.status(200).json({ message: "Logged out successfully" });
  }
};

export const forgotPasswordHandler = async (req: Request, res: Response) => {
  try {
    const { email } = req.body as { email?: string };
    if (!email)
      return res.status(400).json({
        message: "Email is required",
      });
    const user = await User.findOne({ email });
    if (!user)
      return res.json({
        message:
          "If an account exist with this email, we have send you a reset link",
      });
    const rawToken = crypto.randomBytes(32).toString("hex");

    const hashedToken = crypto
      .createHash("sha256")
      .update(rawToken)
      .digest("hex");

    user.resetPasswordToken = hashedToken;
    user.resetPasswordExpires = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes
    await user.save();

    const resetUrl = `${getAppUrl()}/api/auth/reset-password?token=${rawToken}`;

    await sendEmail(
      email,
      "Reset Your Password",
      `
  <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px;">
    <h2 style="color: #333;">Password Reset Request</h2>

    <p style="font-size: 14px; color: #555;">
      We received a request to reset your password. Click the button below to set a new password.
    </p>

    <div style="margin: 30px 0; text-align: center;">
      <a
        href="${resetUrl}"
        style="
          background-color: #4f46e5;
          color: #ffffff;
          padding: 12px 24px;
          text-decoration: none;
          border-radius: 6px;
          font-weight: bold;
          display: inline-block;
        "
        target="_blank"
      >
        Reset Password
      </a>
    </div>

    <p style="font-size: 13px; color: #777;">
      This link will expire in <strong>15 minutes</strong>.
      If you didn’t request a password reset, you can safely ignore this email.
    </p>

    <hr style="margin: 30px 0;" />

    <p style="font-size: 12px; color: #999;">
      If the button doesn’t work, copy and paste this link into your browser:
      <br />
      <a href="${resetUrl}" style="color: #4f46e5;">${resetUrl}</a>
    </p>
  </div>
  `
    );

    return res.json({
      message:
        "If an account exist with this email, we have send you a reset link",
    });
  } catch (error) {
    console.log("Forgot password error:", error);
    return res.status(500).json({ message: "Internal Server Error" });
  }
};

export const resetPasswordHandler = async (req: Request, res: Response) => {
  try {
    const { token, password } = req.body as {
      token?: string;
      password?: string;
    };

    if (!token) {
      return res.status(400).json({ message: "Reset token is missing" });
    }

    if (!password || password.length < 8) {
      return res
        .status(400)
        .json({ message: "Password must be at least 8 characters long" });
    }

    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

    const user = await User.findOne({
      resetPasswordToken: hashedToken,
      resetPasswordExpires: { $gt: new Date() },
    });

    if (!user) {
      return res
        .status(400)
        .json({ message: "Invalid or expired reset token" });
    }

    user.passwordHash = await hashPassword(password);
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    user.tokenVersion += 1;

    await user.save();

    return res.status(200).json({
      message: "Password has been reset successfully",
    });
  } catch (error) {
    console.error("Reset Password Error:", error);
    return res.status(500).json({
      message: "Internal Server Error",
    });
  }
};
