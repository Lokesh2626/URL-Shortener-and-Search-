if (process.env.NODE_ENV !== 'production') {
  require('dotenv').config();
}

const express = require('express');
const mongoose = require('mongoose');
const ShortUrl = require('./models/shortUrl');
const app = express();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const flash = require('express-flash');
const session = require('express-session');
const methodOverride = require('method-override');
const User = require('./models/user');
const initializePassport = require('./passport-config');

mongoose.connect('mongodb://127.0.0.1/urlShortener', {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: false }));
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false
}));
app.use(flash());
app.use(passport.initialize());
app.use(passport.session());
app.use(methodOverride('_method'));
function generateToken(user) {
  const payload = { id: user.id };
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });
}

initializePassport(
  passport,
  async (email) => {
    try {
      const user = await User.findOne({ email: email });
      return user;
    } catch (error) {
      console.error(error);
      return null;
    }
  },
  async (id) => {
    try {
      const user = await User.findById(id);
      return user;
    } catch (error) {
      console.error(error);
      return null;
    }
  }
);

app.get('/', checkAuthenticated, async (req, res) => {
  try {
    let query = {};
    if (req.query.search) {
      const searchRegex = new RegExp(req.query.search, 'i');
      query = {
        $or: [
          { full: searchRegex },
          { short: searchRegex },
          { notes: searchRegex }
        ]
      };
    }
    const shortUrls = await ShortUrl.find(query);
    res.render('index', { shortUrls: shortUrls });
  } catch (error) {
    console.error(error);
    res.sendStatus(500);
  }
});

app.get('/register', checkNotAuthenticated, (req, res) => {
  res.render('register.ejs');
});

app.post('/register', checkNotAuthenticated, async (req, res) => {
  try {
    const { email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      email: email,
      password: hashedPassword
    });
    await user.save();
    res.redirect('/login');
  } catch (error) {
    console.error(error);
    res.redirect('/register');
  }
});

app.delete('/logout', (req, res, next) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    res.redirect('/login');
  });
});

function checkAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/login');
}

function checkNotAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return res.redirect('/');
  }
  next();
}

app.post('/login', checkNotAuthenticated, (req, res, next) => {
  passport.authenticate('local', { session: false }, (err, user, info) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: 'Internal Server Error' });
    }
    if (!user) {
      console.log('Authentication failed:', info.message);
      if (info.message === 'User not Registered!') {
        return res.status(401).json({ message: 'User not registered' });
      }
      if (info.message === 'Incorrect Password!') {
        return res.status(401).json({ message: 'Incorrect password' });
      }
      return res.status(401).json({ message: 'Incorrect email or password' });
    }
    req.logIn(user, (err) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ message: 'Internal Server Error' });
      }
      const token = generateToken(user);
      res.json({ token });
    });
  })(req, res, next);
});

app.get('/login', checkNotAuthenticated, (req, res) => {
  res.render('login.ejs');
});

app.post('/shortUrls', async (req, res) => {
  const { fullUrl, noteUrl } = req.body;
  try {
    const shortUrl = await ShortUrl.create({ full: fullUrl, notes: noteUrl });
    res.redirect('/');
  } catch (error) {
    console.error(error);
    res.sendStatus(500);
  }
});

app.get('/:shortUrl', async (req, res) => {
  const shortUrl = await ShortUrl.findOne({ short: req.params.shortUrl });
  if (shortUrl == null) return res.sendStatus(404);
  shortUrl.clicks++;
  shortUrl.save();
  res.redirect(shortUrl.full);
});

app.listen(process.env.PORT || 5000);