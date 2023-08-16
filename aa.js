//jshint esversion:6
// require for dotenv
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");

// mongoose package
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");

// GoogleStrategy
const GoogleStrategy = require('passport-google-oauth20').Strategy;

// findorcreate
const findOrCreate = require('mongoose-findorcreate');

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({
  extended: true
}));

// favicon
app.use('/favicon.ico', express.static('public/images/favicon.ico'));

// establish a session
app.use(session({
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: false
}));

// initialize passport and use it to set up a session
app.use(passport.initialize());
app.use(passport.session());

// connect to mongoose db
mongoose.connect("mongodb://127.0.0.1:27017/userDB", {useNewUrlParser: true});
// addresses deprication warning: collection.ensureIndex is deprecated
mongoose.set('useCreateIndex', true);

// create new mongoose schema
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String
});

// add passport-local-mongoose into mongoose schema as a plugin
userSchema.plugin(passportLocalMongoose);

// add mongoose-findorcreate as a plugin
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

// Configuration of passport-local-mongoose
// CHANGE: USE "createStrategy" INSTEAD OF "authenticate"
passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

// Google Strategy Configuration added after serialization
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "https://boiling-tundra-41595.herokuapp.com/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    // log the user profile
    // console.log(profile);

    User.findOrCreate({
      googleId: profile.id,
      username: profile.name.givenName
    }, function(err, user) {
      return cb(err, user);
    });
  }
));

// render home
app.get("/", function(req, res) {
  res.render("home");
});

// initiate Google authentication
app.get("/auth/google",
  passport.authenticate('google', {
    scope: ["profile"]
  }));

// authorized redirect URI
app.get("/auth/google/secrets",
  passport.authenticate('google', {
    failureRedirect: "/login"
  }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  });

// render login
app.get("/login", function(req, res) {
  res.render("login");
});

// render register
app.get("/register", function(req, res) {
  res.render("register");
});

// secrets route
app.get("/secrets", function(req, res) {

  // check if user is authenticated
  // if (req.isAuthenticated()) {
  //   res.render("secrets");
  // } else {
  //   res.redirect("/login");
  // }

  User.find({"secret": {$ne: null}}, function(err, foundUsers){
    if(err){
      console.log();
    } else {
      if(foundUsers){
        res.render("secrets", {userswithSecrets: foundUsers});
      }
    }
  });
});

// get request for submitting a secrets
app.get("/submit", function(req, res) {

  // check if user is authenticated
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

// post request to submit secret
app.post("/submit", function(req, res) {
  const submittedSecret = req.body.secret;

  // log user id
  // console.log(req.user.id);

  User.findById(req.user.id, function(err, foundUser){
    if(err) {
      console.log(err);
    } else {
      if(foundUser){
        foundUser.secret = submittedSecret;
        foundUser.save(function(){
          res.redirect("/secrets");
        });
      }
    }
  });
});


// get method for logout
app.get("/logout", function(req, res) {
  req.logout();
  res.redirect("/");
});


// post method to register new users
app.post("/register", function(req, res) {

  // passport-local-mongoose
  User.register({
    username: req.body.username
  }, req.body.password, function(err, user) {
    if (err) {
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, function() {
        res.redirect("/secrets");
      });
    }
  });
});


// post method to check credentials of existing users
app.post("/login", function(req, res) {

  // create new user
  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  // passport login authentication
  req.login(user, function(err) {
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function() {
        res.redirect("/secrets");
      });
    }
  });

});

// Heroku deployment
let port = process.env.PORT;
if (port == null || port == "") {
  port = 3000;
}

app.listen(port, function() {
  console.log("Server started successfully.");
});