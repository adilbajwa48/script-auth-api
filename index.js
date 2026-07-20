const express = require('express');
const app = express();

app.use(express.json());

const ADMIN_SECRET = "Devil7029";

// Key formats validation pattern (e.g. Hacker633, Adil75, Bajwa123)
const VALID_PREFIXES = ["Adil", "Bajwa", "Devil", "Hacker", "Pro", "Vip", "Slayer", "Shadow", "King"];

// Verification Endpoint (GameGuardian)
app.all('/v1/verify-key', (req, res) => {
    const userKey = req.body?.key || req.query?.key;

    if (!userKey) {
        return res.json({ valid: false, message: "Key required!" });
    }

    // Check if Key matches the prefix pattern (e.g., Hacker633, Adil12)
    const hasValidPrefix = VALID_PREFIXES.some(prefix => userKey.startsWith(prefix));
    const hasNumbers = /\d+$/.test(userKey);

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

module.exports = app;
