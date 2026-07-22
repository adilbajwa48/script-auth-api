const express = require('express');
const app = express();

app.use(express.json());

const ADMIN_SECRET = "Devil7029";
const keysDatabase = {};
const bannedIps = new Set(); // Banned IPs ki list

app.all('/v1/verify-key', (req, res) => {
    const userKey = req.body?.key || req.query?.key;
    const userHwid = req.body?.hwid || req.query?.hwid || "N/A";
    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

    // Check if IP is permanently BANNED
    if (bannedIps.has(clientIp)) {
        return res.json({ valid: false, status: "BANNED", message: "Your IP address is permanently banned!" });
    }

    if (!userKey || !keysDatabase[userKey]) {
        return res.json({ valid: false, status: "UNAUTHORIZED", message: "Invalid Key!" });
    }

    const keyData = keysDatabase[userKey];

    if (keyData.isBanned) {
        return res.json({ valid: false, status: "BANNED", message: "Account banned!" });
    }

    if (Date.now() > keyData.expiresAt) {
        return res.json({ valid: false, status: "EXPIRED", message: "Key Expired!" });
    }

    // IP Locking Logic
    if (!keyData.boundIp) {
        keyData.boundIp = clientIp;
        keyData.boundHwid = userHwid;
    } else if (keyData.boundIp !== clientIp) {
        return res.json({ valid: false, status: "UNAUTHORIZED", message: "Key locked to another IP!" });
    }

    keyData.lastSeen = Date.now();
    return res.json({ valid: true, status: "AUTHORIZED", message: "Access Granted!" });
});

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

// BAN IP ENDPOINT
app.post('/v1/admin/ban-ip', (req, res) => {
    const { adminSecret, discordId, ip } = req.body;
    if (adminSecret !== ADMIN_SECRET) return res.status(403).json({ error: "Unauthorized!" });

    let targetIp = ip;

    // Agar IP nahi di lekin Discord ID di hai, to database se uski IP dhoondo
    if (!targetIp && discordId) {
        for (const k in keysDatabase) {
            if (keysDatabase[k].discordId === discordId && keysDatabase[k].boundIp) {
                targetIp = keysDatabase[k].boundIp;
                break;
            }
        }
    }

    if (!targetIp) {
        return res.status(404).json({ error: "User IP not found! User needs to login at least once." });
    }

    bannedIps.add(targetIp);
    return res.json({ success: true, message: `IP ${targetIp} has been BANNED!`, bannedIp: targetIp });
});

// UNBAN IP ENDPOINT
app.post('/v1/admin/unban-ip', (req, res) => {
    const { adminSecret, ip } = req.body;
    if (adminSecret !== ADMIN_SECRET) return res.status(403).json({ error: "Unauthorized!" });

    bannedIps.delete(ip);
    return res.json({ success: true, message: `IP ${ip} has been UNBANNED!` });
});

app.get('/v1/admin/stats', (req, res) => {
    const { adminSecret } = req.query;
    if (adminSecret !== ADMIN_SECRET) return res.status(403).json({ error: "Unauthorized!" });

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
            onlineUsersList.push({ key: key, discordId: item.discordId, ip: item.boundIp || "N/A" });
        }
    }

    return res.json({
        totalKeys: totalKeys,
        bannedKeys: bannedKeys,
        onlineUsersCount: onlineUsersCount,
        onlineUsersList: onlineUsersList,
        bannedIpsCount: bannedIps.size
    });
});

module.exports = app;
            
