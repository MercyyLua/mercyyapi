const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const crypto = require('crypto');

const DB_PATH = path.join(__dirname, 'keys.db');

class Database {
    constructor() {
        this.db = new sqlite3.Database(DB_PATH, (err) => {
            if (err) {
                console.error('Error opening database:', err);
            } else {
                console.log('Connected to SQLite database');
                this.init();
            }
        });
    }

    init() {
        this.db.serialize(() => {
            this.db.run(`
                CREATE TABLE IF NOT EXISTS keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key TEXT UNIQUE NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    expires_at DATETIME,
                    hwid TEXT,
                    is_active BOOLEAN DEFAULT 1,
                    duration_days INTEGER DEFAULT 30,
                    discord_id TEXT,
                    last_used DATETIME,
                    use_count INTEGER DEFAULT 0
                )
            `);

            this.db.run(`
                CREATE TABLE IF NOT EXISTS announcements (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    message TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    created_by TEXT,
                    is_active BOOLEAN DEFAULT 1
                )
            `);

            this.db.run(`
                CREATE TABLE IF NOT EXISTS admins (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    discord_id TEXT UNIQUE NOT NULL,
                    username TEXT,
                    added_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            `);
        });
    }

    generateKey() {
        const prefix = 'KEY-';
        const randomBytes = crypto.randomBytes(16).toString('hex').toUpperCase();
        return prefix + randomBytes.match(/.{4}/g).join('-');
    }

    createKey(durationDays = 3650, discordId = null) {
        return new Promise((resolve, reject) => {
            const key = this.generateKey();
            const expiresAt = new Date();
            expiresAt.setDate(expiresAt.getDate() + durationDays); // 3650 days = ~10 years (lifetime)

            const sql = `INSERT INTO keys (key, expires_at, duration_days, discord_id) VALUES (?, ?, ?, ?)`;
            
            this.db.run(sql, [key, expiresAt.toISOString(), durationDays, discordId], function(err) {
                if (err) {
                    reject(err);
                } else {
                    resolve({
                        id: this.lastID,
                        key: key,
                        expires_at: expiresAt.toISOString(),
                        duration_days: durationDays
                    });
                }
            });
        });
    }

    getKey(key) {
        return new Promise((resolve, reject) => {
            const sql = `SELECT * FROM keys WHERE key = ?`;
            this.db.get(sql, [key], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });
    }

    validateKey(key, hwid) {
        return new Promise((resolve, reject) => {
            const sql = `SELECT * FROM keys WHERE key = ? AND is_active = 1`;
            this.db.get(sql, [key], (err, row) => {
                if (err) {
                    reject(err);
                    return;
                }

                if (!row) {
                    resolve({ valid: false, message: 'Invalid key' });
                    return;
                }

                if (row.expires_at && new Date(row.expires_at) < new Date()) {
                    resolve({ valid: false, message: 'Key has expired' });
                    return;
                }

                if (row.hwid && row.hwid !== hwid) {
                    resolve({ valid: false, message: 'HWID mismatch - Key is bound to another device' });
                    return;
                }

                if (!row.hwid) {
                    this.bindHwid(key, hwid).catch(console.error);
                }

                this.updateLastUsed(key).catch(console.error);

                resolve({
                    valid: true,
                    message: 'Key is valid',
                    key_data: {
                        key: row.key,
                        created_at: row.created_at,
                        expires_at: row.expires_at,
                        hwid: row.hwid || hwid,
                        use_count: row.use_count + 1
                    }
                });
            });
        });
    }

    bindHwid(key, hwid) {
        return new Promise((resolve, reject) => {
            const sql = `UPDATE keys SET hwid = ? WHERE key = ?`;
            this.db.run(sql, [hwid, key], (err) => {
                if (err) reject(err);
                else resolve();
            });
        });
    }

    updateLastUsed(key) {
        return new Promise((resolve, reject) => {
            const sql = `UPDATE keys SET last_used = CURRENT_TIMESTAMP, use_count = use_count + 1 WHERE key = ?`;
            this.db.run(sql, [key], (err) => {
                if (err) reject(err);
                else resolve();
            });
        });
    }

    revokeKey(key) {
        return new Promise((resolve, reject) => {
            const sql = `UPDATE keys SET is_active = 0 WHERE key = ?`;
            this.db.run(sql, [key], function(err) {
                if (err) reject(err);
                else resolve({ changes: this.changes });
            });
        });
    }

    reactivateKey(key) {
        return new Promise((resolve, reject) => {
            const sql = `UPDATE keys SET is_active = 1 WHERE key = ?`;
            this.db.run(sql, [key], function(err) {
                if (err) reject(err);
                else resolve({ changes: this.changes });
            });
        });
    }

    resetHwid(key) {
        return new Promise((resolve, reject) => {
            const sql = `UPDATE keys SET hwid = NULL WHERE key = ?`;
            this.db.run(sql, [key], function(err) {
                if (err) reject(err);
                else resolve({ changes: this.changes });
            });
        });
    }

    extendKey(key, days) {
        return new Promise((resolve, reject) => {
            const sql = `UPDATE keys SET expires_at = datetime(expires_at, '+${days} days') WHERE key = ?`;
            this.db.run(sql, [key], function(err) {
                if (err) reject(err);
                else resolve({ changes: this.changes });
            });
        });
    }

    getAllKeys() {
        return new Promise((resolve, reject) => {
            const sql = `SELECT * FROM keys ORDER BY created_at DESC`;
            this.db.all(sql, [], (err, rows) => {
                if (err) reject(err);
                else resolve(rows);
            });
        });
    }

    getKeyStats() {
        return new Promise((resolve, reject) => {
            const sql = `
                SELECT 
                    COUNT(*) as total_keys,
                    SUM(CASE WHEN is_active = 1 THEN 1 ELSE 0 END) as active_keys,
                    SUM(CASE WHEN is_active = 0 THEN 1 ELSE 0 END) as revoked_keys,
                    SUM(CASE WHEN expires_at < datetime('now') THEN 1 ELSE 0 END) as expired_keys
                FROM keys
            `;
            this.db.get(sql, [], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });
    }

    createAnnouncement(title, message, createdBy) {
        return new Promise((resolve, reject) => {
            const sql = `INSERT INTO announcements (title, message, created_by) VALUES (?, ?, ?)`;
            this.db.run(sql, [title, message, createdBy], function(err) {
                if (err) reject(err);
                else resolve({ id: this.lastID });
            });
        });
    }

    getAnnouncements(limit = 5) {
        return new Promise((resolve, reject) => {
            const sql = `SELECT * FROM announcements WHERE is_active = 1 ORDER BY created_at DESC LIMIT ?`;
            this.db.all(sql, [limit], (err, rows) => {
                if (err) reject(err);
                else resolve(rows);
            });
        });
    }

    addAdmin(discordId, username) {
        return new Promise((resolve, reject) => {
            const sql = `INSERT OR IGNORE INTO admins (discord_id, username) VALUES (?, ?)`;
            this.db.run(sql, [discordId, username], function(err) {
                if (err) reject(err);
                else resolve({ changes: this.changes });
            });
        });
    }

    isAdmin(discordId) {
        return new Promise((resolve, reject) => {
            const sql = `SELECT * FROM admins WHERE discord_id = ?`;
            this.db.get(sql, [discordId], (err, row) => {
                if (err) reject(err);
                else resolve(!!row);
            });
        });
    }

    close() {
        this.db.close();
    }
}

module.exports = Database;
