const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const Database = require('./database');

const app = express();
const db = new Database();

const API_SECRET = process.env.API_SECRET || crypto.randomBytes(32).toString('hex');
const PORT = process.env.PORT || 3000;

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { success: false, message: 'Too many requests, please try again later' }
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: { success: false, message: 'Too many authentication attempts' }
});

app.use(helmet());
app.use(cors());
app.use(express.json());
app.use('/api/', limiter);
app.use('/api/auth/', authLimiter);

function generateSignature(data, timestamp) {
    return crypto.createHmac('sha256', API_SECRET).update(data + timestamp).digest('hex');
}

function verifySignature(req, res, next) {
    const signature = req.headers['x-api-signature'];
    const timestamp = req.headers['x-api-timestamp'];
    
    if (!signature || !timestamp) {
        return res.status(401).json({ success: false, message: 'Missing signature headers' });
    }

    const expectedSignature = generateSignature(JSON.stringify(req.body), timestamp);
    
    if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSignature))) {
        return res.status(401).json({ success: false, message: 'Invalid signature' });
    }

    next();
}

const botAuth = async (req, res, next) => {
    // Bot auth disabled - all requests allowed
    next();
};

app.post('/api/auth/validate', async (req, res) => {
    try {
        const { key, hwid } = req.body;
        
        if (!key || !hwid) {
            return res.status(400).json({ 
                success: false, 
                message: 'Key and HWID are required' 
            });
        }

        const result = await db.validateKey(key, hwid);
        
        res.json({
            success: result.valid,
            message: result.message,
            ...result
        });
    } catch (error) {
        console.error('Validation error:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

app.get('/api/announcements', async (req, res) => {
    try {
        const announcements = await db.getAnnouncements(5);
        res.json({ success: true, announcements });
    } catch (error) {
        console.error('Announcements error:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

app.post('/api/bot/key/create', botAuth, async (req, res) => {
    try {
        const { durationDays, discordId } = req.body;
        const result = await db.createKey(durationDays || 30, discordId);
        res.json({ success: true, key: result });
    } catch (error) {
        console.error('Create key error:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

app.post('/api/bot/key/revoke', botAuth, async (req, res) => {
    try {
        const { key } = req.body;
        if (!key) {
            return res.status(400).json({ success: false, message: 'Key is required' });
        }
        const result = await db.revokeKey(key);
        res.json({ 
            success: true, 
            message: result.changes > 0 ? 'Key revoked' : 'Key not found' 
        });
    } catch (error) {
        console.error('Revoke key error:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

app.post('/api/bot/key/reset-hwid', botAuth, async (req, res) => {
    try {
        const { key } = req.body;
        if (!key) {
            return res.status(400).json({ success: false, message: 'Key is required' });
        }
        const result = await db.resetHwid(key);
        res.json({ 
            success: true, 
            message: result.changes > 0 ? 'HWID reset' : 'Key not found' 
        });
    } catch (error) {
        console.error('Reset HWID error:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

app.post('/api/bot/key/extend', botAuth, async (req, res) => {
    try {
        const { key, days } = req.body;
        if (!key || !days) {
            return res.status(400).json({ success: false, message: 'Key and days are required' });
        }
        const result = await db.extendKey(key, days);
        res.json({ 
            success: true, 
            message: result.changes > 0 ? `Key extended by ${days} days` : 'Key not found' 
        });
    } catch (error) {
        console.error('Extend key error:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

app.get('/api/bot/key/info/:key', botAuth, async (req, res) => {
    try {
        const key = req.params.key;
        const keyData = await db.getKey(key);
        if (!keyData) {
            return res.status(404).json({ success: false, message: 'Key not found' });
        }
        res.json({ success: true, key: keyData });
    } catch (error) {
        console.error('Key info error:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

app.get('/api/bot/keys', botAuth, async (req, res) => {
    try {
        const keys = await db.getAllKeys();
        res.json({ success: true, keys });
    } catch (error) {
        console.error('Get keys error:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

app.get('/api/bot/stats', botAuth, async (req, res) => {
    try {
        const stats = await db.getKeyStats();
        res.json({ success: true, stats });
    } catch (error) {
        console.error('Stats error:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

app.post('/api/bot/announcement/create', botAuth, async (req, res) => {
    try {
        const { title, message, createdBy } = req.body;
        if (!title || !message) {
            return res.status(400).json({ success: false, message: 'Title and message are required' });
        }
        const result = await db.createAnnouncement(title, message, createdBy);
        res.json({ success: true, id: result.id });
    } catch (error) {
        console.error('Create announcement error:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

app.get('/api/ping', (req, res) => {
    res.json({ success: true, message: 'Pong', timestamp: new Date().toISOString() });
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`API Secret (save this!): ${API_SECRET}`);
});

process.on('SIGINT', () => {
    db.close();
    process.exit(0);
});
