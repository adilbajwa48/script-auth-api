const express = require('express');
const app = express();

app.use(express.json());

const ADMIN_SECRET = "Devil7029";
const keysDatabase = {}; // In-Memory Store

// 1. Verification Endpoint (GG Script & Loader ke liye)
app.all('/v1/verify-key', (req, res) => {
    const userKey = req.body?.key || req.query?.key;
    const userHwid = req.body?.hwid || req.query?.hwid || "N/A";
    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

    if (!userKey || !keysDatabase[userKey]) {
        return res.json({ valid: false, status: "UNAUTHORIZED", message: "Invalid Key!" });
    }

    const keyData = keysDatabase[userKey];

    // Check Ban Status
    if (keyData.isBanned) {
        return res.json({ valid: false, status: "BANNED", message: "Aapka account ban hai!" });
    }

    // Check 24 Hours Expiry
    if (Date.now() > keyData.expiresAt) {
        return res.json({ valid: false, status: "EXPIRED", message: "Key Expired!" });
    }

    // HWID Binding
    if (!keyData.boundHwid && userHwid !== "N/A") {
        keyData.boundHwid = userHwid;
        keyData.boundIp = clientIp;
    } else if (keyData.boundHwid && userHwid !== "N/A" && keyData.boundHwid !== userHwid) {
        return res.json({ valid: false, status: "UNAUTHORIZED", message: "Key kisi aur device par active hai!" });
    }

    keyData.lastSeen = Date.now();
    return res.json({ valid: true, status: "AUTHORIZED", message: "Access Granted!" });
});

// 2. Generate Key Endpoint (Discord Bot ke liye)
app.post('/v1/generate-key', (req, res) => {
    const { discordId, key, expiresAt } = req.body;

    if (!discordId || !key) return res.status(400).json({ error: "Missing fields" });

    keysDatabase[key] = {
        discordId: discordId,
        boundHwid: null,
        boundIp: null,
        isBanned: false,
        createdAt: Date.now(),
        expiresAt: expiresAt || (Date.now() + (24 * 60 * 60 * 1000)),
        lastSeen: null
    };

    return res.json({ success: true, message: "Key created successfully!" });
});

// 3. Admin Ban Endpoint
app.post('/v1/admin/ban', (req, res) => {
    const { adminSecret, key } = req.body;

    if (adminSecret !== ADMIN_SECRET) {
        return res.status(403).json({ error: "Unauthorized!" });
    }

    if (!keysDatabase[key]) return res.status(404).json({ error: "Key not found!" });

    keysDatabase[key].isBanned = true;
    return res.json({ success: true, message: `Key ${key} has been BANNED!` });
});

// 4. Admin Unban Endpoint
app.post('/v1/admin/unban', (req, res) => {
    const { adminSecret, key } = req.body;

    if (adminSecret !== ADMIN_SECRET) {
        return res.status(403).json({ error: "Unauthorized!" });
    }

    if (!keysDatabase[key]) return res.status(404).json({ error: "Key not found!" });

    keysDatabase[key].isBanned = false;
    return res.json({ success: true, message: `Key ${key} has been UNBANNED!` });
});

// 5. Real-Time Admin Stats
app.get('/v1/admin/stats', (req, res) => {
    const { adminSecret } = req.query;

    if (adminSecret !== ADMIN_SECRET) {
        return res.status(403).json({ error: "Unauthorized!" });
    }

    const currentTime = Date.now();
    const activeWindow = 5 * 60 * 1000;

    let totalKeys = 0;
    let bannedKeys = 0;
    let onlineUsersCount = 0;
    const onlineUsersList = [];

    for (const key in keysDatabase) {
        totalKeys++;
        const item = keysDatabase[key];

        if (item.isBanned) bannedKeys++;

        if (item.lastSeen && (currentTime - item.lastSeen <= activeWindow)) {
            onlineUsersCount++;
            onlineUsersList.push({
                key: key,
                discordId: item.discordId,
                ip: item.boundIp || "N/A"
            });
        }
    }

    return res.json({
        totalKeys: totalKeys,
        bannedKeys: bannedKeys,
        onlineUsersCount: onlineUsersCount,
        onlineUsersList: onlineUsersList
    });
});

module.exports = app;
    
