import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import session from "express-session";
import connectPgSimple from "connect-pg-simple";
import env from "dotenv";

env.config();
const app = express();
const port = process.env.PORT || 5500;
const saltRounds = 10;

const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
  ssl: {
    rejectUnauthorized: false
  }
});

db.on("error", (err) => {
  console.error("Unexpected error on idle client", err);
});

db.connect()
  .then(() => console.log("Connected to DB"))
  .catch((err) => {
    console.error("Failed to connect to DB:", err);
    process.exit(1);
  });

const pgSession = connectPgSimple(session);

app.use(
  session({
    store: new pgSession({
      pool: db,
      tableName: "session"
    }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: false,
      maxAge: 1000 * 60 * 60 * 24
    }
  })
);

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.set("view engine", "ejs");

app.use(passport.initialize());
app.use(passport.session());

app.get("/", (req, res) => {
  try {
    res.render("home.ejs");
  } catch (err) {
    console.error("Error rendering home:", err);
    res.status(500).send("Internal Server Error");
  }
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/logout", (req, res, next) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.get("/secrets", async (req, res) => {
  if (req.isAuthenticated()) {
    try {
      const result = await db.query("SELECT secret FROM users WHERE id = $1", [req.user.id]);
      const userSecret = result.rows[0]?.secret || "";
      res.render("secrets.ejs", { secret: userSecret });
    } catch (err) {
      console.error("Error loading secret:", err);
      res.render("secrets.ejs", { secret: "Error loading secret." });
    }
  } else {
    res.redirect("/login");
  }
});

app.post("/submit", async (req, res) => {
  const userSecret = req.body.secret;
  try {
    await db.query("UPDATE users SET secret = $1 WHERE id = $2", [userSecret, req.user.id]);
    res.redirect("/secrets");
  } catch (err) {
    console.error("Error saving secret:", err);
    res.redirect("/secrets");
  }
});

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"]
  })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    successRedirect: "/secrets",
    failureRedirect: "/login"
  })
);

app.get("/submit", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("submit.ejs");
  } else {
    res.redirect("/login");
  }
});

app.post("/login", (req, res, next) => {
  passport.authenticate("local", (err, user, info) => {
    if (err) {
      console.error("Auth error:", err);
      return next(err);
    }
    if (!user) {
      return res.redirect("/login");
    }
    req.login(user, (err) => {
      if (err) {
        console.error("Login error:", err);
        return next(err);
      }
      return res.redirect("/secrets");
    });
  })(req, res, next);
});

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT id FROM users WHERE email = $1", [email]);

    if (checkResult.rows.length > 0) {
      res.redirect("/login");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
          res.redirect("/register");
        } else {
          const result = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id, email, password",
            [email, hash]
          );
          const user = result.rows[0];
          req.login(user, (err) => {
            if (err) {
              console.error(err);
              return res.redirect("/login");
            }
            res.redirect("/secrets");
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
    res.redirect("/register");
  }
});

passport.use(
  "local",
  new Strategy(async function verify(username, password, cb) {
    try {
      const result = await db.query("SELECT id, email, password FROM users WHERE email = $1", [username]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.password;
        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if (err) {
            console.error("Error comparing passwords:", err);
            return cb(err);
          } else {
            if (valid) {
              return cb(null, user);
            } else {
              return cb(null, false);
            }
          }
        });
      } else {
        return cb(null, false);
      }
    } catch (err) {
      console.log(err);
      return cb(err);
    }
  })
);

passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        const result = await db.query("SELECT id, email FROM users WHERE email = $1", [profile.email]);
        if (result.rows.length === 0) {
          const newUser = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id, email",
            [profile.email, "google"]
          );
          return cb(null, newUser.rows[0]);
        } else {
          return cb(null, result.rows[0]);
        }
      } catch (err) {
        return cb(err);
      }
    }
  )
);

passport.serializeUser((user, cb) => {
  cb(null, user.id);
});

passport.deserializeUser(async (id, cb) => {
  try {
    const result = await db.query("SELECT id, email, secret FROM users WHERE id = $1", [id]);
    if (result.rows.length > 0) {
      cb(null, result.rows[0]);
    } else {
      cb(null, false);
    }
  } catch (err) {
    cb(err);
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
