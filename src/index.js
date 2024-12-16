const { query } = require('./database');
const config = require("./functions/env.js");

const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const path = require('path');
const fs = require("node:fs");
const MySQLStore = require('express-mysql-session')(session);
const extra = require('./functions/extra');

const app = express();

const options = {
	host: config.HOST,
	port: config.PORT,
	user: config.USER,
	password: config.PASSWORD,
    clearExpired: true,
    createDatabaseTable: true,
	database: config.DATABASE,
    schema: {
		tableName: 'sessions',
		columnNames: {
			session_id: 'session_id',
			expires: 'expires',
			data: 'data'
		}
	}
};

const sessionStore = new MySQLStore(options);

const sessionMiddleware = session({
    secret: config.SECRET,
    resave: false,
    store: sessionStore,
    saveUninitialized: false,
    cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 }
});

app.use(sessionMiddleware);
app.use(express.static(path.join(__dirname, '/public')));
app.set('views', path.join(__dirname, '/views'));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.set('trust proxy', 1) // enables reverse proxy support, allowing express to use the X-Forwarded-* headers to determine the connection properties (e.g. if the connection is secure or not)

// -- ROUTES --
require("./functions/routes.js")(app, session);
// -- ROUTES --

app.get('/', (req, res) => {
    res.render('index', {
        title: 'PasteLitter',
        path: req.path,
        user: (req.session.user ? req.session.user : null)
    });
})

const cache = {
    totalUsers: null,
    totalPastes: null,
    totalLogs: null,
    cacheTime: null
};

app.get('/admin', async (req, res) => {
    if (req.session.user && (req.session.user.rank === 'admin' || req.session.user.rank === 'owner')) {
        const cacheTime = 10 * 60 * 1000;
        if (!cache.totalUsers || !cache.totalPastes || !cache.totalLogs || Date.now() - cache.cacheTime > cacheTime) {
            const data = await Promise.all([
                query('SELECT * FROM users'),
                query('SELECT * FROM pastes'),
                query('SELECT * FROM logs')
            ]);
            cache.totalUsers = data[0].length || 0;
            cache.totalPastes = data[1].length || 0;
            cache.totalLogs = data[2].length || 0;
            cache.cacheTime = Date.now();
        }
        res.render('admin/admin-home', {
            title: 'PasteLitter - Admin Panel',
            path: req.path,
            user: (req.session.user ? req.session.user : null),
            totalUsers: cache.totalUsers,
            totalPastes: cache.totalPastes,
            totalLogs: cache.totalLogs
        });
    } else {
        res.redirect('/unauthorized');
    }
})


// admin/users
app.get('/admin/users', async (req, res) => {
    if (req.session.user && (req.session.user.rank === 'admin' || req.session.user.rank === 'owner')) {
        const users = await query('SELECT * FROM users');
        res.render('admin/admin-users', {
            title: 'PasteLitter - Admin Panel',
            path: req.path,
            user: (req.session.user ? req.session.user : null),
            users
        });
    } else {
        res.redirect('/unauthorized');
    }
})

// admin/pastes
app.get('/admin/pastes', (req, res) => {
    if (req.session.user && (req.session.user.rank === 'admin' || req.session.user.rank === 'owner')) {
        res.render('admin/admin-pastes', {
            title: 'PasteLitter - Admin Panel',
            path: req.path,
            user: (req.session.user ? req.session.user : null)
        });
    } else {
        res.redirect('/unauthorized');
    }
})

// admin/logs

app.get('/admin/logs', (req, res) => {
    if (req.session.user && (req.session.user.rank === 'admin' || req.session.user.rank === 'owner')) {
        res.render('admin/admin-logs', {
            title: 'PasteLitter - Admin Panel',
            path: req.path,
            user: (req.session.user ? req.session.user : null)
        });
    } else {
        res.redirect('/unauthorized');
    }
})

// user profile

app.get('/profile/:id', async (req, res) => {
    const user = await query('SELECT * FROM users WHERE id = ?', [req.params.id]);
    res.render('profile', {
        title: `PasteLitter - ${user[0].username}\'s Profile`,
        path: req.path,
        user: (req.session.user ? req.session.user : null),
        profile: user[0]
    });
})

app.get('/unauthorized', (req, res) => {
    res.render('errors/401', {
        user: (req.session.user ? req.session.user : null),
        path: req.path
    })    
})

app.get('/auth/register', (req, res) => {
    if (req.session.user) {
        return res.redirect('/');
    }
    res.render('register', {
        title: 'PasteLitter - Register',
        path: req.path,
        user: null,
        recaptcha_enabled: config.RE_CAPTCHA_ENABLED === 'false' ? false : true,
        recaptcha_site_key: config.RE_CAPTCHA_KEY
    });
});

app.get('/auth/login', (req, res) => {
    if (req.session.user) {
        return res.redirect('/');
    }
    res.render('login', {
        title: 'PasteLitter - Login',
        path: req.path,
        user: null,
        recaptcha_enabled: config.RE_CAPTCHA_ENABLED === 'false' ? false : true,
        recaptcha_site_key: config.RE_CAPTCHA_KEY
    });
});


// -- ERROR HANDLERS --

app.use((req, res) => {
    res.status(404).render('errors/404', {
        user: (req.session.user ? req.session.user : null),
        path: req.path
    });
})

app.use((err, req, res, next) => {
    console.error(err);
    res.status(500).render('errors/500', {
        user: (req.session.user ? req.session.user : null),
        path: req.path,
    });
})


// -- ERROR HANDLERS --

app.listen(config.SITEPORT, () => {
    sessionStore.onReady().then(() => {
        console.log(`[+] listening on ${config.SITEURL}`);
    })
});

module.exports = app;