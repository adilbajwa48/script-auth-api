const express = require('express');
const app = express();

app.use(express.json());

// Secret Admin Key (Aapka Admin Password)
const ADMIN_SECRET = "Devil7029";

// In-Memory Database
const keysDatabase = {};

// 1. Script Access Check & Active Status Update
app.get('/v1/check-access', (req, res) => {
    const userKey = req.query.key;
    const userHwid = req.query.hwid;
    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

    if (!keysDatabase[userKey]) {
        return res.json({ status: "UNAUTHORIZED", message: "Invalid Key!" });
    }

    const keyData = keysDatabase[userKey];

    if (keyData.isBanned) {
        return res.json({ status: "BANNED", message: "Aapka account ban hai!" });
    }

    // HWID Binding
    if (!keyData.boundHwid) {
        keyData.boundHwid = userHwid;
        keyData.boundIp = clientIp;
    } else if (keyData.boundHwid !== userHwid) {
        return res.json({ status: "UNAUTHORIZED", message: "Key kisi aur device par active hai!" });
    }

    // Real-Time Activity Update (Last Seen Time update ho gi)
    keyData.lastSeen = Date.now();

    return res.json({ status: "AUTHORIZED", message: "Access Granted!" });
});

// 2. Generate Key Endpoint (Discord Bot)
app.post('/v1/generate-key', (req, res) => {
    const { discordId, key } = req.body;

    if (!discordId || !key) return res.status(400).json({ error: "Missing fields" });

    keysDatabase[key] = {
        discordId: discordId,
        boundHwid: null,
        boundIp: null,
        isBanned: false,
        createdAt: Date.now(),
        lastSeen: null
    };

    return res.json({ success: true, message: "Key created successfully!" });
});

// 3. Admin Ban Endpoint
app.post('/v1/admin/ban', (req, res) => {
    const { adminSecret, key } = req.body;

    if (adminSecret !== ADMIN_SECRET) {
        return res.status(403).json({ error: "Unauthorized! Invalid Admin Secret." });
    }

    if (!keysDatabase[key]) return res.status(404).json({ error: "Key not found!" });

    keysDatabase[key].isBanned = true;
    return res.json({ success: true, message: `Key ${key} has been BANNED!` });
});

// 4. Admin Unban Endpoint
app.post('/v1/admin/unban', (req, res) => {
    const { adminSecret, key } = req.body;

    if (adminSecret !== ADMIN_SECRET) {
        return res.status(403).json({ error: "Unauthorized! Invalid Admin Secret." });
    }

    if (!keysDatabase[key]) return res.status(404).json({ error: "Key not found!" });

    keysDatabase[key].isBanned = false;
    return res.json({ success: true, message: `Key ${key} has been UNBANNED!` });
});

// 5. Real-Time Stats (Online Users + Discord ID + Key Details)
app.get('/v1/admin/stats', (req, res) => {
    const { adminSecret } = req.query;

    if (adminSecret !== ADMIN_SECRET) {
        return res.status(403).json({ error: "Unauthorized!" });
    }

    const currentTime = Date.now();
    const activeWindow = 5 * 60 * 1000; // 5 Minutes Window

    let totalKeys = 0;
    let bannedKeys = 0;
    let onlineUsersCount = 0;
    const onlineUsersList = [];

    for (const key in keysDatabase) {
        totalKeys++;
        const item = keysDatabase[key];

        if (item.isBanned) {
            bannedKeys++;
        }

        // Check agar user ne pichle 5 minutes mein request bheji hai
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
