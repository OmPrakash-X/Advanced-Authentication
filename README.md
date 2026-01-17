# 🔐 Authentication Service

A **production-ready authentication and authorization service** built with **Node.js and TypeScript**, designed for scalability, security, and clean architecture. This project provides complete user authentication flows including OAuth, JWT-based auth, role-based access control, and optional two-factor authentication (2FA).

---

## ✨ Features

* ✅ Email & Password Authentication
* 🔑 JWT Access & Refresh Token Handling
* 🔐 Secure Password Hashing
* 🌐 Google OAuth Authentication
* 🧑‍💼 Role-Based Access Control (RBAC)
* 🔒 Middleware-Based Route Protection
* 📧 Email Utility Support (verification / notifications)
* 🛡️ TOTP-based Two-Factor Authentication (2FA)
* 🧱 Modular & Scalable Folder Structure

---

## 🗂️ Project Structure

```text
Authentication/
├── src/
│   ├── app.ts                # App configuration & middleware setup
│   ├── server.ts             # Server bootstrap
│   ├── configs/
│   │   └── db.ts             # Database connection
│   ├── controllers/
│   │   └── auth/
│   │       ├── auth.controller.ts      # Core auth logic
│   │       ├── auth.schema.ts           # Validation schemas
│   │       └── google.controller.ts     # Google OAuth flow
│   ├── routes/
│   │   ├── auth.routes.ts     # Auth routes
│   │   ├── user.routes.ts     # User routes
│   │   └── admin.routes.ts    # Admin-only routes
│   ├── middlewares/
│   │   ├── requireAuth.ts     # JWT auth middleware
│   │   └── requireRole.ts     # Role-based access middleware
│   ├── models/
│   │   └── user.model.ts      # User schema/model
│   ├── lib/
│   │   ├── hash.ts            # Password hashing utilities
│   │   ├── token.ts           # JWT utilities
│   │   └── mail.ts            # Email utilities
│   ├── scripts/
│   │   └── totp-qr.ts         # TOTP QR generation script
│   └── tsconfig.json
```

---

## ⚙️ Tech Stack

* **Backend:** Node.js, TypeScript
* **Framework:** Express
* **Database:** MongoDB (via Mongoose)
* **Authentication:** JWT, Google OAuth
* **Security:** bcrypt, TOTP (2FA)
* **Validation:** Schema-based validation

---

## 🚀 Getting Started

### 1️⃣ Clone the Repository

```bash
git clone <your-repo-url>
cd Authentication
```

### 2️⃣ Install Dependencies

```bash
npm install
```

### 3️⃣ Environment Variables

Create a `.env` file in the root directory and configure the following:

```env
PORT=5000
MONGO_URI=your_mongodb_connection_string
JWT_SECRET=your_jwt_secret
JWT_REFRESH_SECRET=your_refresh_secret
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
EMAIL_USER=your_email
EMAIL_PASS=your_email_password
```

---

### 4️⃣ Run the Server

```bash
npm run dev
```

The server will start on:

```
http://localhost:5000
```

---

## 🔐 Authentication Flow

1. User registers or logs in via email/password or Google OAuth
2. Passwords are securely hashed before storage
3. JWT access & refresh tokens are issued
4. Protected routes validate JWT using middleware
5. Role-based middleware restricts admin-only routes
6. Optional 2FA adds an extra security layer

---

## 🛡️ Middlewares

* **requireAuth** – Verifies JWT and authenticates requests
* **requireRole** – Ensures user has required role access

---

## 🧪 Scripts

* **TOTP QR Generator**

```bash
npm run totp
```

Generates a QR code for enabling Two-Factor Authentication.

---

## 📌 Use Cases

* SaaS authentication service
* Startup backend boilerplate
* Secure admin/user systems
* Hackathon-ready auth module

---

## 🤝 Contributing

Contributions are welcome! Feel free to open issues or submit pull requests.

---

## 📄 License

This project is licensed under the **MIT License**.

---

### ⭐ If you find this project useful, consider giving it a star!
