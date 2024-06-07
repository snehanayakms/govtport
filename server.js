const express = require('express');
const mysql = require('mysql');
const bodyParser = require('body-parser');
const session = require('express-session');
const path = require('path');
const bcrypt = require('bcryptjs'); // Use bcryptjs instead of bcrypt

const app = express();

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// Set up session middleware
app.use(session({
    secret: 'secret',
    resave: false,
    saveUninitialized: true,
}));

// Database connection
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'web_portal'
});

// Connect to MySQL
db.connect((err) => {
    if (err) throw err;
    console.log('MySQL connected');
});

// Handle form submission for registration
app.post('/register', (req, res) => {
    const { name, email, phone, password, gender, state, city } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 10); // Hash the password
    const sql = 'INSERT INTO users (name, email, phone, password, gender, state, city) VALUES (?, ?, ?, ?, ?, ?, ?)';
    db.query(sql, [name, email, phone, hashedPassword, gender, state, city], (err, result) => {
        if (err) throw err;
        console.log('User registered successfully');
        req.session.message = 'Thank you for registering. Please log in.';
        res.redirect('/login');
    });
});

// Serve login page
app.get('/login', (req, res) => {
    const message = req.session.message;
    delete req.session.message;
    res.sendFile(path.join(__dirname, 'public/login.html'));
});

// Handle form submission for login
app.post('/login', (req, res) => {
    const { email, password } = req.body;
    const sql = 'SELECT * FROM users WHERE email = ?';
    db.query(sql, [email], (err, results) => {
        if (err) throw err;
        if (results.length > 0) {
            const user = results[0];
            if (bcrypt.compareSync(password, user.password)) {
                req.session.user = user;
                res.redirect('/dashboard');
            } else {
                req.session.message = 'Invalid email or password.';
                res.redirect('/login');
            }
        } else {
            req.session.message = 'Invalid email or password.';
            res.redirect('/login');
        }
    });
});

// Serve dashboard page
app.get('/dashboard', isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'public/dashboard.html'));
});

// Handle logout
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.log(err);
        }
        res.redirect('/login');
    });
});

// Middleware to check if the user is authenticated
function isAuthenticated(req, res, next) {
    if (req.session && req.session.user) {
        return next();
    } else {
        res.redirect('/login');
    }
}

// Start server
const port = 3000;
app.listen(port, () => console.log(`Server running on port ${port}`));
