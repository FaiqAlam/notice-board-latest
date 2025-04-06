const express = require('express');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const mysql = require('mysql2');
const WebSocket = require('ws');
const bcrypt = require('bcrypt');

const app = express();

// Update server startup:
const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// WebSocket setup
const wss = new WebSocket.Server({ server });
wss.on('connection', (ws) => {
    ws.on('message', (message) => {
        const { type } = JSON.parse(message);
        if (type === 'new_notice') {
            pool.query(
                'SELECT notices.*, users.username FROM notices JOIN users ON notices.author_id = users.id ORDER BY notices.created_at DESC LIMIT 1',
                (error, results) => {
                    if (!error && results.length > 0) {
                        broadcast(JSON.stringify({
                            type: 'new_notice',
                            notice: results[0]
                        }));
                    }
                }
            );
        }
    });
});

// Broadcast function
function broadcast(message) {
    wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(message);
        }
    });
}

// Database connection (new improved version)
const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || 'QWer12.,',
    database: process.env.DB_NAME || 'notice_board',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
  });

// Middleware setup
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));
app.set('view engine', 'ejs');

// Update session configuration:
app.use(session({
    secret: process.env.SESSION_SECRET || 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: { 
      secure: process.env.NODE_ENV === 'production'
    }
  }));

// Passport setup
app.use(passport.initialize());
app.use(passport.session());

// Middleware to pass user to all templates
app.use((req, res, next) => {
    res.locals.user = req.user;
    next();
});

// Passport configuration
passport.use(new LocalStrategy(
    (username, password, done) => {
        pool.query(
            'SELECT * FROM users WHERE username = ?',
            [username],
            (error, results) => {
                if (error) return done(error);
                if (!results.length) return done(null, false, { message: 'Incorrect username' });

                const user = results[0];
                bcrypt.compare(password, user.password, (err, result) => {
                    if (err) return done(err);
                    if (result) return done(null, user);
                    return done(null, false, { message: 'Incorrect password' });
                });
            }
        );
    }
));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => {
    pool.query('SELECT * FROM users WHERE id = ?', [id], (error, results) => {
        done(error, results[0]);
    });
});

// Role-based middleware
const isAdmin = (req, res, next) => {
    if (req.isAuthenticated() && req.user.role === 'admin') return next();
    res.redirect('/login/admin');
  };

const isTeacher = (req, res, next) => {
    if (req.isAuthenticated() && req.user.role === 'teacher') return next();
    res.redirect('/login/teacher');
  };

const isStudent = (req, res, next) => {
    if (req.isAuthenticated() && req.user.role === 'student' && req.user.approved) return next();
    res.redirect('/login/student');
};

// Routes

// Home route
app.get('/', (req, res) => {
    if (req.user) {
        // User is logged in - show notices
        pool.query(
            `SELECT notices.*, users.username 
             FROM notices 
             JOIN users ON notices.author_id = users.id 
             ORDER BY notices.created_at DESC`,
            (error, notices) => {
                if (error) throw error;
                res.render('index', { 
                    user: req.user,
                    notices: notices
                });
            }
        );
    } else {
        // User not logged in - show hero section
        res.render('index', { 
            user: null,
            notices: []
        });
    }
});

// Login GET route (with role)
app.get('/login/:role', (req, res) => {
    res.render('login', { 
        role: req.params.role,
        successMessage: req.query.success || null,
        errorMessage: null
    });
});

// Login POST route
app.post('/login', (req, res, next) => {
    passport.authenticate('local', (err, user, info) => {
        if (err) return next(err);
        if (!user || !user.approved) {
            return res.render('login', { 
                role: req.body.role,
                successMessage: null,
                errorMessage: info ? info.message : 'You are not approved yet.'
            });
        }
        req.logIn(user, (err) => {
            if (err) return next(err);
            return res.redirect('/');
        });
    })(req, res, next);
});

// Logout route
app.get('/logout', (req, res) => {
    req.logout(() => {});
    res.redirect('/');
});

// Registration routes
app.get('/register', (req, res) => {
    res.render('register', { errorMessage: null });
});

app.post('/register', async (req, res) => {
    const { username, password, role } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        
        pool.query(
            'INSERT INTO users (username, password, role, approved) VALUES (?, ?, ?, ?)',
            [username, hashedPassword, role, role === 'student'],
            (error) => {
                if (error) {
                    console.error(error);
                    return res.render('register', { 
                        errorMessage: 'Registration failed. Username may be taken.' 
                    });
                }
                res.redirect(role === 'student' ? '/login/student' : '/login/teacher');
            }
        );
    } catch (error) {
        console.error(error);
        res.render('register', { 
            errorMessage: 'An error occurred during registration' 
        });
    }
});

// Admin Dashboard Route
app.get('/admin', isAdmin, (req, res) => {
    pool.query(
        'SELECT * FROM users WHERE approved = FALSE',
        (error, results) => {
            if (error) {
                console.error('Error fetching pending users:', error);
                return res.render('admin-dashboard', {
                    user: req.user,
                    pendingUsers: [],
                    errorMessage: 'Error fetching pending users from database.'
                });
            }
            res.render('admin-dashboard', {
                user: req.user,
                pendingUsers: results || [],
                errorMessage: null
            });
        }
    );
});

// Approve User Route
app.post('/admin/approve/:id', isAdmin, (req, res) => {
    pool.query(
        'UPDATE users SET approved = TRUE WHERE id = ?',
        [req.params.id],
        (error) => {
            if (error) throw error;
            res.redirect('/admin');
        }
    );
});

// Delete Notice Route
app.post('/notices/delete/:id', isAdmin, (req, res) => {
    pool.query(
        'DELETE FROM notices WHERE id = ?',
        [req.params.id],
        (error) => {
            if (error) throw error;
            res.redirect('/');
        }
    );
});

// Notice creation routes
app.get('/notices/new', isTeacher, (req, res) => {
    res.render('new-notice');
});

app.post('/notices', isTeacher, (req, res) => {
    const { title, content, category } = req.body;
    pool.query(
        'INSERT INTO notices (title, content, author_id, category) VALUES (?, ?, ?, ?)',
        [title, content, req.user.id, category],
        (error) => {
            if (error) throw error;
            res.redirect('/');
        }
    );
});
