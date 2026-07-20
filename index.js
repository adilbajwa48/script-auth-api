const express = require('express');
const app = express();

app.use(express.json());

const ADMIN_SECRET = "Devil7029";
const VALID_PREFIXES = ["Adil", "Bajwa", "Devil", "Hacker", "Pro", "Vip", "Slayer", "Shadow", "King"];

// Root Check (To verify deployment status in browser)
app.get('/', (req, res) => {
    return res.status(200).send("⚡ Devil Script Auth API is Live & Working!");
});

// Verification Endpoint (For GameGuardian)
app.all('/v1/verify-key', (req, res) => {
    const userKey = req.body?.key || req.query?.key;

    if (!userKey) {
        return res.json({ valid: false, status: "UNAUTHORIZED", message: "Key required!" });
    }

    const cleanKey = String(userKey).trim();
    const hasValidPrefix = VALID_PREFIXES.some(prefix => cleanKey.toLowerCase().startsWith(prefix.toLowerCase()));
    const hasNumbers = /\d+$/.test(cleanKey);

    if (hasValidPrefix && hasNumbers) {
        return res.json({ 
            valid: true, 
            status: "AUTHORIZED", 
            message: "Access Granted!" 
        });
    }

    return res.json({ 
        valid: false, 
        status: "UNAUTHORIZED", 
        message: "Invalid Key Format!" 
    });
});

// Sync Endpoint for Discord Bot
app.post('/v1/generate-key', (req, res) => {
    return res.json({ success: true, message: "Key registered!" });
});

// Catch-All 404 Route Fix
app.use((req, res) => {
    res.status(200).json({ valid: false, message: "Route fallback fallback triggered" });
});

module.exports = app;
