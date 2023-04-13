import express from 'express';
import path from 'path';
import bcrypt from 'bcrypt';
import session from 'express-session';
import passport from 'passport';
import passportLocal from 'passport-local';

const app = express();

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}))

app.use(express.json());
app.use(express.urlencoded({extended: true}))
app.use(passport.initialize());
app.use(passport.session());

passport.use(new passportLocal.Strategy({
    usernameField: 'email'
}, async (email, password, done) => {
    const user = users.find((user) => user.email === email)

    if (user === undefined) {
        return done(null, null, {message: "Incorrect email."});
    }

    if (await bcrypt.compare(password, user.password)) {
        return done(null, user);
    }

    done(null, null, {message: 'Incorrect password.'});
}));

// used to serialize the user for the session
passport.serializeUser((user, done) => {
    done(null, user.id);
});

// used to deserialize the user
passport.deserializeUser((id, done) => {
    done(null, users.find((user) => user.id === id));
})

app.get('/register', checkAuthenticated, (req, res) => {
    res.sendFile(path.resolve('views/register.html'));
});

app.get('/login', checkAuthenticated, (req, res) => {
    res.sendFile(path.resolve('views/login.html'));
});

let users = [];

app.post('/register', async (req, res) => {
    const {name, email, password} = req.body;
    const hashedPwd = await bcrypt.hash(password, 10);

    users.push({
        id: `${Date.now()}_${Math.random()}`,
        name,
        email,
        password: hashedPwd,
    });

    res.redirect('/login');
});

app.post('/login', passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login',
}))

app.get('/', checkNotAuthenticated, (req, res) => {
    res.sendFile(path.resolve('views/index.html'));
});

app.get('/logout', (req, res, next) => {
    req.logout(function (err) {
        if (err) {
            return next(err);
        }
        res.redirect('/login');
    });
});

function checkNotAuthenticated(req, res, next) {
    if (req.isAuthenticated() === false) {
        return res.redirect('/login');
    }

    next();
}

function checkAuthenticated(req, res, next) {
    if (req.isAuthenticated() === true) {
        return res.redirect('/');
    }

    next();
}

const PORT = process.env.APP_PORT || 3001;

app.listen(PORT, () => {
    console.log(`Listen to port ${PORT}`)
});