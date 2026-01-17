import jwt from "jsonwebtoken";

export const createAccessToken = (
  userId: string,
  role: "user" | "admin",
  tokenVersion: number
) => {
  const payload = { sub: userId, role, tokenVersion };
  return jwt.sign(payload, process.env.JWT_ACCESS_SECRET!, {
    expiresIn: "15m",
  });
};

export const verifyAccessToken = async (token: string) => {
  return jwt.verify(token, process.env.JWT_ACCESS_SECRET!) as {
    sub: string;
    role: "user" | "admin";
    tokenVersion: number;
  };
};


export const createRefreshToken = (userId: string, tokenVersion: number) => {
  const payload = { sub: userId, tokenVersion };
  return jwt.sign(payload, process.env.JWT_ACCESS_SECRET!, {
    expiresIn: "7d",
  });
};

export const verifyRefreshToken = async (token: string) => {
  return jwt.verify(token, process.env.JWT_ACCESS_SECRET!) as {
    sub: string;
    tokenVersion: number;
  };
};
