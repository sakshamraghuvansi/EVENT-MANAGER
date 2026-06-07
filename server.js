const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const PORT = 3000;
const JWT_SECRET = 'super-secret-jwt-key-2026-change-in-production-please';

app.use(express.json());
app.use(express.static('public'));

const db = new sqlite3.Database('./events.db');

db.serialize(() => {
    // Users table
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Events table
    db.run(`CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        date_time DATETIME NOT NULL,
        location TEXT NOT NULL,
        category TEXT NOT NULL,
        cover_image_url TEXT,
        organiser_id INTEGER NOT NULL,
        rsvp_count INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (organiser_id) REFERENCES users(id)
    )`);

    // Seed demo data
    db.get("SELECT COUNT(*) as count FROM users", (err, row) => {
        if (row && row.count === 0) {
            const hashed = bcrypt.hashSync('password123', 10);
            db.run("INSERT INTO users (username, email, password) VALUES ('demo', 'demo@example.com', ?)", [hashed], function() {
                const demoId = this.lastID;

                const demoEvents = [
                    {title:"AI & ML Workshop", description:"Hands-on session on building AI models.", date_time:"2026-03-05T14:30:00", location:"Hyderabad International Convention Centre", category:"Tech", cover:"https://picsum.photos/id/1015/800/450"},
                    {title:"Live Jazz Night", description:"Smooth jazz performances by local artists.", date_time:"2026-03-08T19:00:00", location:"The Jazz Lounge, Banjara Hills", category:"Arts", cover:"https://picsum.photos/id/106/800/450"},
                    {title:"Startup Pitch Night", description:"Pitch your idea or watch others.", date_time:"2026-03-12T17:00:00", location:"WeWork, Financial District", category:"Business", cover:"https://picsum.photos/id/201/800/450"},
                    {title:"Youth Football Tournament", description:"Open tournament for under-18 teams.", date_time:"2026-03-15T09:00:00", location:"Gachibowli Stadium", category:"Sports", cover:"https://picsum.photos/id/133/800/450"}
                ];

                demoEvents.forEach(ev => {
                    db.run(`INSERT INTO events (title, description, date_time, location, category, cover_image_url, organiser_id, rsvp_count) 
                            VALUES (?,?,?,?,?,?,?,0)`, [ev.title, ev.description, ev.date_time, ev.location, ev.category, ev.cover, demoId]);
                });
                console.log('✅ Demo data seeded. Login: demo@example.com / password123');
            });
        }
    });
});

// Auth middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({error: 'Access token required'});
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({error: 'Invalid token'});
        req.user = user;
        next();
    });
};

// ====================== ROUTES ======================

app.post('/api/register', async (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password) return res.status(400).json({error: 'All fields required'});

    const hashed = await bcrypt.hash(password, 10);
    db.run('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', [username, email, hashed], function(err) {
        if (err) {
            return res.status(409).json({error: 'Username or email already taken'});
        }
        res.status(201).json({message: 'User registered'});
    });
});

app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
        if (err || !user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({error: 'Invalid credentials'});
        }
        const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ token, username: user.username });
    });
});

app.get('/api/events', (req, res) => {
    const { category, search } = req.query;
    let sql = `SELECT e.*, u.username as organiser 
               FROM events e JOIN users u ON e.organiser_id = u.id 
               WHERE e.date_time > datetime('now')`;
    const params = [];

    if (category && category !== 'All') {
        sql += ' AND e.category = ?';
        params.push(category);
    }
    if (search) {
        sql += ' AND (e.title LIKE ? OR e.description LIKE ?)';
        params.push(`%${search}%`, `%${search}%`);
    }
    sql += ' ORDER BY e.date_time ASC';

    db.all(sql, params, (err, rows) => {
        if (err) return res.status(500).json({error: 'DB error'});
        res.json(rows);
    });
});

app.get('/api/events/:id', (req, res) => {
    db.get(`SELECT e.*, u.username as organiser 
            FROM events e JOIN users u ON e.organiser_id = u.id 
            WHERE e.id = ?`, [req.params.id], (err, row) => {
        if (err || !row) return res.status(404).json({error: 'Event not found'});
        res.json(row);
    });
});

app.post('/api/events', authenticateToken, (req, res) => {
    const { title, description, date_time, location, category, cover_image_url } = req.body;
    if (!title || !description || !date_time || !location || !category) {
        return res.status(400).json({error: 'Missing required fields'});
    }
    db.run(`INSERT INTO events (title, description, date_time, location, category, cover_image_url, organiser_id)
            VALUES (?,?,?,?,?,?,?)`,
        [title, description, date_time, location, category, cover_image_url, req.user.id],
        function(err) {
            if (err) return res.status(500).json({error: 'DB error'});
            res.status(201).json({id: this.lastID});
        });
});

app.delete('/api/events/:id', authenticateToken, (req, res) => {
    db.get('SELECT organiser_id FROM events WHERE id = ?', [req.params.id], (err, event) => {
        if (!event || event.organiser_id !== req.user.id) return res.status(403).json({error: 'Not authorized'});
        
        db.run('DELETE FROM events WHERE id = ?', [req.params.id], (err) => {
            if (err) return res.status(500).json({error: 'DB error'});
            res.json({message: 'Deleted'});
        });
    });
});

app.post('/api/events/:id/rsvp', authenticateToken, (req, res) => {
    db.run('UPDATE events SET rsvp_count = rsvp_count + 1 WHERE id = ?', [req.params.id], function(err) {
        if (err || this.changes === 0) return res.status(404).json({error: 'Event not found'});
        
        db.get('SELECT rsvp_count FROM events WHERE id = ?', [req.params.id], (err, row) => {
            res.json({rsvp_count: row.rsvp_count});
        });
    });
});

app.get('/api/my-events', authenticateToken, (req, res) => {
    db.all('SELECT * FROM events WHERE organiser_id = ? ORDER BY date_time DESC', [req.user.id], (err, rows) => {
        if (err) return res.status(500).json({error: 'DB error'});
        res.json(rows);
    });
});

app.listen(PORT, () => {
    console.log(`🚀 Server ready → http://localhost:${PORT}`);
    console.log(`   Demo login → demo@example.com / password123`);
});