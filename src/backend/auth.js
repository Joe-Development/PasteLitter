const rateLimit = require('express-rate-limit');
const { comparePassword, hashPassword, logAction, generatePfp } = require('../functions/extra');
const { query } = require('../database');

const limiter = rateLimit({
    windowMs: 60 * 1000,
    max: 10,
    message: {
        message: 'Too many login attempts. Please try again later.',
    },
});

module.exports = function (app, session) {
    app.use('/auth', limiter);

    app.post('/auth/login', async (req, res) => {
        const { username, password } = req.body;


        if (username.length < 3 || password.length < 4 || username.length > 32 || password.length > 32) {
            res.status(400).send({
                message: 'Username and password must be between 3 and 32 characters',
            });
            return;
        }

        const user = await query('SELECT * FROM users WHERE username = ?', [username]);
        if (user.length === 0) {
            res.status(401).send({
                message: 'Invalid username or password',
            });
            return;
        }

        if (user[0].banned) {
            res.status(401).send({
                message: 'Your account has been banned',
            });
            logAction(user[0].username, 'Attempted to login with <b style="color: red;">Banned</b> account');
            return;
        }

        const htmlRegex = /<(script|img|iframe|object|embed|form|input|textarea|a|style|link|meta|base|body|html|head|title|frame|frameset|svg)[^>]*?(on[a-z]+\s*?=\s*?['"][^'"]*?['"]|javascript\s*?:\s*?[^'"]+|[^\w\s-]|<|>|&|%3C|%3E|%3Cscript|%3E|%3Csvg|%3Ca|%3D|%3Cimg)[^>]*?>|<.*?javascript\s*?:[^>]*>/i;

        if (htmlRegex.test(username) || htmlRegex.test(password)) {
            res.status(400).send({
                message: 'Invalid characters in input',
            });
            return;
        }
        

        const match = await comparePassword(password, user[0].password);
        if (!match) {
            res.status(401).send({
                message: 'Invalid username or password',
            });
            return;
        }
        req.session.user = {
            id: user[0].id,
            username: user[0].username,
            rank: user[0].rank,
            email: user[0].email,
            avatar: user[0].avatar
        };

        logAction(user[0].username, 'Logged in');
        res.redirect('/');
    });


    app.post('/auth/register', async (req, res) => {
        const { username, password, email } = req.body;

        if (username.length > 32 || password.length > 32) {
            res.status(400).send({
                message: 'Username and password must be less than 32 characters',
            });
            return;
        }

        const user = await query('SELECT * FROM users WHERE username = ?', [username]);
        if (user.length > 0) {
            res.status(400).send({
                message: 'Username already exists',
            });
            return;
        }

        const emailRegex = /^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$/;
        if (email && !emailRegex.test(email)) {
            res.status(400).send({
                message: 'Invalid email',
            });
            return;
        }

        const htmlRegex = /<(script|img|iframe|object|embed|form|input|textarea|a|style|link|meta|base|body|html|head|title|frame|frameset|svg)[^>]*?(on[a-z]+\s*?=\s*?['"][^'"]*?['"]|javascript\s*?:\s*?[^'"]+|[^\w\s-]|<|>|&|%3C|%3E|%3Cscript|%3E|%3Csvg|%3Ca|%3D|%3Cimg)[^>]*?>|<.*?javascript\s*?:[^>]*>/i;
        if (htmlRegex.test(username) || htmlRegex.test(password) || htmlRegex.test(email)) {
            res.status(400).send({
                message: 'Invalid characters in input',
            });
            return;
        }

        if (email) {
            const userByEmail = await query('SELECT * FROM users WHERE email = ?', [email]);
            if (userByEmail.length > 0) {
                res.status(400).send({
                    message: 'Email already exists',
                });
                return;
            }
        }
        const avatar = await generatePfp(username);
        const hashedPassword = await hashPassword(password);
        await query('INSERT INTO users (username, password, email, avatar) VALUES (?, ?, ?, ?)', [username, hashedPassword, email || 'anonymous@litter.com', avatar]);
        res.status(200).send({
            message: 'User registered successfully',
        })
    });


    app.get('/auth/logout', async (req, res) => {
        logAction(req.session.user.username, 'Logged out');
        req.session.destroy();
        res.redirect('/');
    });
};
