const express = require('express');
const app = express();

app.use(express.json());

// Testing ke liye temporary keys
const validKeys = {
    "KEY-1234": { hwid: null, discordId: "123456789" }
};

const bannedIPs = [];

// Access check endpoint
app.get('/v1/check-access', (req, res) => {
    const clientIP = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const { key, hwid } = req.query;

    if (bannedIPs.includes(clientIP)) {
        return res.json({ status: "BANNED", message: "Your IP is banned." });
    }

    if (!key || !validKeys[key]) {
        return res.json({ status: "INVALID_KEY", message: "Invalid license key." });
    }

    const keyData = validKeys[key];

    if (keyData.hwid === null) {
        keyData.hwid = hwid;
    } else if (keyData.hwid !== hwid) {
        return res.json({ status: "HWID_MISMATCH", message: "Key locked to another device." });
    }

    return res.json({ 
        status: "AUTHORIZED", 
        message: "Access granted.",
        userIP: clientIP
    });
});

const PORT = process.env.PORT || 3000;
module.exports = app;

