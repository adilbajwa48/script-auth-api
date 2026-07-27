const express = require('express');
const { Pool } = require('pg');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const ADMIN_SECRET = "Devil7029";

// Railway Database Connection
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// Database Setup
async function initTables() {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS keys (
                key VARCHAR(100) PRIMARY KEY,
                discord_id VARCHAR(50) NOT NULL,
                bound_ip VARCHAR(50),
                bound_hwid VARCHAR(100),
                is_banned BOOLEAN DEFAULT false,
                expires_at BIGINT NOT NULL,
                created_at BIGINT NOT NULL,
                last_seen BIGINT
            );
            CREATE TABLE IF NOT EXISTS banned_ips (
                ip VARCHAR(50) PRIMARY KEY
            );
        `);
        console.log("✅ Database Ready!");
    } catch (err) {
        console.error("❌ DB Error:", err);
    }
}
initTables();

function getClientIp(req) {
    const forwarded = req.headers['x-forwarded-for'] || req.headers['x-real-ip'];
    if (forwarded) return forwarded.split(',')[0].trim();
    return req.socket?.remoteAddress || req.ip || "0.0.0.0";
}

// 1. CHECK ACTIVE KEY
app.get('/v1/check-key', async (req, res) => {
    const discordId = req.query.discordId ? String(req.query.discordId).trim() : null;
    if (!discordId) return res.status(400).json({ error: "Missing discordId" });

    try {
        const currentTime = Date.now();
        const result = await pool.query(
            `SELECT * FROM keys WHERE discord_id = $1 AND expires_at > $2 AND is_banned = false LIMIT 1`,
            [discordId, currentTime]
        );

        if (result.rows.length > 0) {
            const activeKey = result.rows[0];
            return res.json({
                active: true,
                key: activeKey.key,
                expiresAt: Number(activeKey.expires_at),
                boundIp: activeKey.bound_ip || null
            });
        }
        return res.status(404).json({ active: false, message: "No active key found" });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

// 2. VERIFY KEY
app.all('/v1/verify-key', async (req, res) => {
    const rawKey = req.body?.key || req.query?.key || req.headers['x-key-auth'];
    const rawHwid = req.body?.hwid || req.query?.hwid || "DEFAULT_HWID";

    if (!rawKey) return res.json({ valid: false, status: "UNAUTHORIZED", message: "Invalid Key!" });

    const userKey = String(rawKey).trim();
    const userHwid = String(rawHwid).trim();
    const clientIp = getClientIp(req);

    try {
        const bannedCheck = await pool.query(`SELECT * FROM banned_ips WHERE ip = $1`, [clientIp]);
        if (bannedCheck.rows.length > 0) return res.json({ valid: false, status: "BANNED", message: "IP Banned!" });

        const keyRes = await pool.query(`SELECT * FROM keys WHERE TRIM(key) = $1`, [userKey]);
        if (keyRes.rows.length === 0) return res.json({ valid: false, status: "UNAUTHORIZED", message: "Invalid Key!" });

        const keyData = keyRes.rows[0];
        if (keyData.is_banned) return res.json({ valid: false, status: "BANNED", message: "Account Banned!" });

        const currentTime = Date.now();
        if (currentTime >= Number(keyData.expires_at)) {
            return res.json({ valid: false, status: "EXPIRED", message: "Key Expired!" });
        }

        if (!keyData.bound_hwid || keyData.bound_hwid === "DEFAULT_HWID") {
            await pool.query(
                `UPDATE keys SET bound_ip = $1, bound_hwid = $2, last_seen = $3 WHERE TRIM(key) = $4`,
                [clientIp, userHwid, currentTime, userKey]
            );
        } else if (userHwid !== "DEFAULT_HWID" && keyData.bound_hwid !== userHwid) {
            return res.json({ valid: false, status: "UNAUTHORIZED", message: "Locked to another device!" });
        } else {
            await pool.query(
                `UPDATE keys SET bound_ip = $1, last_seen = $2 WHERE TRIM(key) = $3`,
                [clientIp, currentTime, userKey]
            );
        }

        return res.json({ valid: true, status: "AUTHORIZED", message: "Access Granted!" });
    } catch (err) {
        return res.status(500).json({ error: "Database Server Error" });
    }
});

// 3. GENERATE KEY
app.post('/v1/generate-key', async (req, res) => {
    const { discordId, key, expiresAt } = req.body;
    if (!discordId || !key) return res.status(400).json({ error: "Missing fields" });

    const cleanDiscordId = String(discordId).trim();
    const cleanKey = String(key).trim();
    const now = Date.now();
    let expTime = Number(expiresAt);
    if (!expTime || isNaN(expTime) || expTime <= now) expTime = now + (24 * 60 * 60 * 1000);

    try {
        await pool.query(`DELETE FROM keys WHERE discord_id = $1`, [cleanDiscordId]);
        await pool.query(
            `INSERT INTO keys (key, discord_id, expires_at, created_at) VALUES ($1, $2, $3, $4)`,
            [cleanKey, cleanDiscordId, expTime, now]
        );
        return res.json({ success: true, message: "Key created successfully!" });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

// 4. HEAVY ADMIN PANEL ENDPOINT (ALL DETAILED CATEGORIES)
app.get('/v1/admin/stats', async (req, res) => {
    const { adminSecret } = req.query;
    if (adminSecret !== ADMIN_SECRET) return res.status(403).json({ error: "Unauthorized!" });

    try {
        const currentTime = Date.now();
        const activeWindow = 10 * 60 * 1000; // 10 Min threshold for Online status

        const allKeysResult = await pool.query(`SELECT * FROM keys ORDER BY created_at DESC`);
        const bannedIpsResult = await pool.query(`SELECT * FROM banned_ips`);

        const onlineUsers = [];
        const offlineUsers = [];
        const bannedKeys = [];

        allKeysResult.rows.forEach(row => {
            const userObj = {
                key: row.key,
                discordId: row.discord_id,
                ip: row.bound_ip || "Not Bound Yet",
                hwid: row.bound_hwid || "Not Bound Yet",
                expiresAt: Number(row.expires_at),
                lastSeen: row.last_seen ? Number(row.last_seen) : null,
                isBanned: row.is_banned
            };

            if (row.is_banned) {
                bannedKeys.push(userObj);
            } else if (row.last_seen && (currentTime - Number(row.last_seen)) <= activeWindow) {
                onlineUsers.push(userObj);
            } else {
                offlineUsers.push(userObj);
            }
        });

        return res.json({
            summary: {
                totalKeys: allKeysResult.rows.length,
                onlineCount: onlineUsers.length,
                offlineCount: offlineUsers.length,
                bannedKeysCount: bannedKeys.length,
                bannedIpsCount: bannedIpsResult.rows.length
            },
            onlineUsers: onlineUsers,
            offlineUsers: offlineUsers,
            bannedKeys: bannedKeys,
            bannedIps: bannedIpsResult.rows.map(r => r.ip)
        });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

// BAN & UNBAN ENDPOINTS
app.post('/v1/admin/ban-ip', async (req, res) => {
    const { adminSecret, discordId, ip } = req.body;
    if (adminSecret !== ADMIN_SECRET) return res.status(403).json({ error: "Unauthorized!" });
    let targetIp = ip;
    try {
        if (!targetIp && discordId) {
            const userRes = await pool.query(`SELECT bound_ip FROM keys WHERE discord_id = $1 LIMIT 1`, [String(discordId).trim()]);
            if (userRes.rows.length > 0) targetIp = userRes.rows[0].bound_ip;
        }
        if (!targetIp) return res.status(404).json({ error: "User IP not found!" });
        await pool.query(`INSERT INTO banned_ips (ip) VALUES ($1) ON CONFLICT DO NOTHING`, [targetIp]);
        return res.json({ success: true, message: `IP ${targetIp} BANNED!`, bannedIp: targetIp });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

app.post('/v1/admin/unban-ip', async (req, res) => {
    const { adminSecret, ip } = req.body;
    if (adminSecret !== ADMIN_SECRET) return res.status(403).json({ error: "Unauthorized!" });
    try {
        await pool.query(`DELETE FROM banned_ips WHERE ip = $1`, [ip]);
        return res.json({ success: true, message: `IP ${ip} UNBANNED!` });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

module.exports = app;
