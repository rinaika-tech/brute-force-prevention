
require("dotenv").config();

const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

// VALIDASI KONFIGURASI

if (!process.env.SESSION_SECRET || !process.env.ADMIN_PASSWORD) {
    throw new Error(
        "SESSION_SECRET dan ADMIN_PASSWORD wajib diatur di file .env"
    );
}

const username = process.env.ADMIN_USERNAME || "admin";
let adminPasswordHash;

// MIDDLEWARE

app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
    session({
        name: "secure.sid",
        secret: process.env.SESSION_SECRET,
        resave: false,
        saveUninitialized: false,
        cookie: {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "strict",
            maxAge: 30 * 60 * 1000
        }
    })
);

// KONFIGURASI BRUTE FORCE PROTECTION

const loginAttempts = new Map();

const MAX_ATTEMPTS = 5;
const LOCK_TIME = 15 * 60 * 1000;

// Maksimal 10 permintaan login dalam 15 menit per IP
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    standardHeaders: true,
    legacyHeaders: false,

    handler: (req, res) => {
        return res.status(429).json({
            success: false,
            locked: false,
            rateLimited: true,
            message:
                "Terlalu banyak permintaan login. Silakan coba lagi nanti."
        });
    }
});

// Identitas percobaan berdasarkan username dan IP
function getAttemptKey(user, ip) {
    return `${user.toLowerCase()}:${ip}`;
}

// MIDDLEWARE AUTENTIKASI

function requireLogin(req, res, next) {
    if (!req.session.user) {
        return res.redirect("/");
    }

    next();
}

// HALAMAN LOGIN

app.get("/", (req, res) => {
    if (req.session.user) {
        return res.redirect("/dashboard");
    }

    res.sendFile(
        path.join(__dirname, "public", "index.html")
    );
});

// PROSES LOGIN

app.post("/login", loginLimiter, async (req, res) => {
    try {
        const { username: inputUser, password } = req.body;

        // Validasi input
        if (
            typeof inputUser !== "string" ||
            typeof password !== "string" ||
            inputUser.trim() === "" ||
            password === "" ||
            inputUser.length > 100 ||
            password.length > 200
        ) {
            return res.status(400).json({
                success: false,
                locked: false,
                message: "Username dan password wajib diisi."
            });
        }

        const cleanUsername = inputUser.trim();
        const ip = req.ip;
        const key = getAttemptKey(cleanUsername, ip);
        const now = Date.now();

        let attempt = loginAttempts.get(key) || {
            count: 0,
            lockUntil: 0
        };

        // --------------------------------------
        // CEK APAKAH AKUN MASIH TERKUNCI
        // --------------------------------------

        if (attempt.lockUntil > now) {
            const remaining = Math.ceil(
                (attempt.lockUntil - now) / 1000
            );

            const minutes = Math.floor(remaining / 60);
            const seconds = remaining % 60;

            return res.status(429).json({
                success: false,
                locked: true,
                remainingAttempts: 0,
                remainingTime: remaining,
                message:
                    `Akun terkunci. Coba lagi dalam ${minutes} menit ${seconds} detik.`
            });
        }

        // --------------------------------------
        // RESET SETELAH MASA KUNCI BERAKHIR
        // --------------------------------------

        if (attempt.lockUntil > 0 && attempt.lockUntil <= now) {
            attempt = {
                count: 0,
                lockUntil: 0
            };

            loginAttempts.set(key, attempt);
        }

        // --------------------------------------
        // VALIDASI USERNAME DAN PASSWORD
        // --------------------------------------

        const validUsername =
            cleanUsername.toLowerCase() === username.toLowerCase();

        const validPassword = await bcrypt.compare(
            password,
            adminPasswordHash
        );

        // --------------------------------------
        // LOGIN BERHASIL
        // --------------------------------------

        if (validUsername && validPassword) {
            loginAttempts.delete(key);

            return req.session.regenerate((err) => {
                if (err) {
                    console.error("Session error:", err);

                    return res.status(500).json({
                        success: false,
                        message: "Gagal membuat session login."
                    });
                }

                req.session.user = username;

                req.session.save((saveError) => {
                    if (saveError) {
                        console.error("Session save error:", saveError);

                        return res.status(500).json({
                            success: false,
                            message: "Gagal menyimpan session login."
                        });
                    }

                    return res.json({
                        success: true,
                        message: "Login berhasil! Selamat datang."
                    });
                });
            });
        }

        // --------------------------------------
        // LOGIN GAGAL
        // --------------------------------------

        attempt.count++;

        const remainingAttempts =
            MAX_ATTEMPTS - attempt.count;

        // --------------------------------------
        // GAGAL 5 KALI: KUNCI AKUN
        // --------------------------------------

        if (attempt.count >= MAX_ATTEMPTS) {
            attempt.lockUntil = now + LOCK_TIME;

            loginAttempts.set(key, attempt);

            return res.status(429).json({
                success: false,
                locked: true,
                remainingAttempts: 0,
                remainingTime: LOCK_TIME / 1000,
                message:
                    "Anda telah gagal login sebanyak 5 kali. Akun dikunci selama 15 menit."
            });
        }

        // Simpan jumlah kegagalan
        loginAttempts.set(key, attempt);

        // --------------------------------------
        // KIRIM NOTIFIKASI LOGIN GAGAL
        // --------------------------------------

        return res.status(401).json({
            success: false,
            locked: false,
            remainingAttempts: remainingAttempts,
            message:
                `Username atau password salah! Sisa kesempatan login Anda ${remainingAttempts} kali.`
        });

    } catch (error) {
        console.error("Login error:", error);

        return res.status(500).json({
            success: false,
            message: "Terjadi kesalahan pada server."
        });
    }
});

// HALAMAN DASHBOARD

app.get("/dashboard", requireLogin, (req, res) => {
    res.sendFile(
        path.join(__dirname, "dashboard.html")
    );
});

// CEK SESSION

app.get("/api/me", (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({
            loggedIn: false
        });
    }

    res.json({
        loggedIn: true,
        username: req.session.user
    });
});

// LOGOUT

app.post("/logout", (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({
                success: false,
                message: "Logout gagal."
            });
        }

        res.clearCookie("secure.sid");

        res.json({
            success: true,
            message: "Logout berhasil."
        });
    });
});

// FILE PUBLIK: CSS DAN JAVASCRIPT

app.use(express.static(
    path.join(__dirname, "public")
));

// MENJALANKAN SERVER

async function startServer() {
    adminPasswordHash = await bcrypt.hash(
        process.env.ADMIN_PASSWORD,
        12
    );

    app.listen(PORT, () => {
        console.log("------------------------------------");
        console.log(" BRUTE FORCE PREVENTION SYSTEM");
        console.log("------------------------------------");
        console.log(`Server: http://localhost:${PORT}`);
        console.log(`Username admin: ${username}`);
        console.log(`Maximum attempts: ${MAX_ATTEMPTS}`);
        console.log("Lock duration: 15 minutes");
        console.log("Rate limit: 10 requests / 15 minutes");
        console.log("Password hashing: bcrypt");
        console.log("------------------------------------");
        console.log("Server berhasil dijalankan!");
    });
}

startServer().catch((error) => {
    console.error("Gagal menjalankan server:", error);
});
