
const form = document.getElementById("loginForm");
const message = document.getElementById("message");
const button = document.getElementById("loginButton");

form.addEventListener("submit", async (e) => {
    e.preventDefault();

    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;

    button.disabled = true;
    button.textContent = "Memverifikasi...";

    message.style.display = "block";
    message.className = "";
    message.textContent = "Sedang memeriksa akun...";

    let accountLocked = false;

    try {
        const response = await fetch("/login", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                username: username,
                password: password
            })
        });

        const result = await response.json();

        // LOGIN BERHASIL
        if (result.success) {
            message.textContent =
                "✓ Login berhasil! Mengalihkan ke dashboard...";

            message.className = "success";

            setTimeout(() => {
                window.location.href = "/dashboard";
            }, 1000);

            return;
        }

        // AKUN TERKUNCI
        if (result.locked) {
            accountLocked = true;

            message.textContent =
                "🔒 AKUN TERKUNCI! " + result.message;

            message.className = "error";

            return;
        }

        // TERKENA RATE LIMIT
        if (result.rateLimited) {
            message.textContent =
                "⚠️ " + result.message;

            message.className = "error";

            return;
        }

        // USERNAME ATAU PASSWORD SALAH
        if (result.remainingAttempts !== undefined) {
            message.textContent =
                "❌ Username atau password salah! " +
                "Sisa percobaan login: " +
                result.remainingAttempts +
                " kali.";

            message.className = "error";

            return;
        }

        // KESALAHAN LAIN
        message.textContent =
            "⚠️ " + (result.message || "Login gagal.");

        message.className = "error";

    } catch (error) {
        console.error("Kesalahan login:", error);

        message.textContent =
            "Tidak dapat terhubung ke server.";

        message.className = "error";

    } finally {
        if (accountLocked) {
            button.disabled = true;
            button.textContent = "Akun Terkunci";
        } else {
            button.disabled = false;
            button.textContent = "Login Sekarang →";
        }
    }
});
