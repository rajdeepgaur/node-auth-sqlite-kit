const express = require('express')
const db = require('./db');
const bcrypt = require('bcrypt');
const path = require('path');

const app = express()
const port = 3000

app.use(express.urlencoded({ extended: true }));

let loggedInUser = null;

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
        if (err || !user) return res.send('Invalid credentials.');

        const match = await bcrypt.compare(password, user.password);
        if (match) {
            loggedInUser = user;
            res.redirect('/dashboard');
        } else {
            res.send('Invalid credentials.');
        }
    });
});


app.get('/dashboard', (req, res) => {
    if (!loggedInUser) {
        return res.send('<h2>Access denied</h2><a href="/login">Login</a>');
    }
    res.sendFile(path.join(__dirname, 'ui', 'dashboard.html'));
});

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})
