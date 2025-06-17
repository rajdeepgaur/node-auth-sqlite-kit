const express = require('express')
const db = require('./db');
const bcrypt = require('bcrypt');
const path = require('path');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const { authenticateToken, JWT_SECRET } = require('./middleware/auth');


const app = express()
const port = 3000

app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.get('/', (req, res) => {
    res.send('Hello World!')
})

app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'ui', 'register.html'));
});


app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'ui', 'login.html'));
});

app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const hashed = await bcrypt.hash(password, 10);

    db.run(`INSERT INTO users (username, password) VALUES (?, ?)`,
        [username, hashed],
        (err) => {
            if (err) {
                return res.send('User already exists.');
            }
            res.redirect('/login');
        });
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;

    db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
        try {
            if (err || !user) return res.send('Invalid credentials.');

            const match = await bcrypt.compare(password, user.password);
            if (!match) return res.send('Invalid credentials.');

            // Create JWT token
            const token = jwt.sign(
                { id: user.id, username: user.username },
                JWT_SECRET,
                { expiresIn: '1h' } // token is valid for 1 hour
            );

            // Send token as a cookie
            res.cookie('token', token, { httpOnly: true });
            console.log(token);
            res.redirect('/dashboard');
        } catch (e) {
            console.error(e);
            res.status(500).send('Login failed.');

        }

    });
});


app.get('/dashboard', authenticateToken, (req, res) => {
    
    res.sendFile(path.join(__dirname, 'ui', 'dashboard.html'));
});

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})
