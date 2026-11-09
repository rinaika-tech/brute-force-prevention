
const usernameElement = document.getElementById("username");
const accountName = document.getElementById("accountName");
const logoutButton = document.getElementById("logoutButton");

// Memeriksa session pengguna
async function checkLogin() {
    try {
        const response = await fetch("/api/me");

        if (!response.ok) {
            window.location.href = "/";
            return;
        }

        const result = await response.json();

        if (result.loggedIn) {
            usernameElement.textContent = result.username;
            accountName.textContent = result.username;
        } else {
            window.location.href = "/";
        }

    } catch (error) {
        window.location.href = "/";
    }
}

// Proses logout
logoutButton.addEventListener("click", async () => {
    logoutButton.disabled = true;
    logoutButton.textContent = "Logging out...";

    try {
        const response = await fetch("/logout", {
            method: "POST"
        });

        if (response.ok) {
            window.location.href = "/";
        } else {
            alert("Logout gagal. Silakan coba lagi.");
            logoutButton.disabled = false;
            logoutButton.textContent = "Logout ↗";
        }

    } catch (error) {
        alert("Tidak dapat terhubung ke server.");
        logoutButton.disabled = false;
        logoutButton.textContent = "Logout ↗";
    }
});

// Jalankan pemeriksaan session
checkLogin();
