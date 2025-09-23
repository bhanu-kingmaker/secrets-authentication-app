import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import session from "express-session";
import connectPgSimple from "connect-pg-simple";
import dotenv from "dotenv";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5500;
const saltRounds = 10;

// --- PostgreSQL Pool for Sessions & Users ---
const pgPool = new pg.Pool({
  connectionString: process.env.DATABASE_URL, // Neon URL
  ssl: { rejectUnauthorized: false },
});

// --- Session Store ---
const PgSession = connectPgSimple(session);
app.use(
  session({
    store: new PgSession({ pool: pgPool, tableName: "session" }),
    secret: process.env.SESSION_SECRET || "SUPERSECRET",
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 1000 * 60 * 60 * 24 }, // 1 day
  })
);

// --- Middleware ---
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(passport.initialize());
app.use(passport.session());

// --- PostgreSQL Client for User Data ---
const db = new pg.Client({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});
db.connect();

// --- Routes ---
app.get("/", (req, res) => res.render("home.ejs"));
app.get("/login", (req, res) => res.render("login.ejs"));
app.get("/register", (req, res) => res.render("register.ejs"));

app.get("/logout", (req, res, next) => {
  req.logout((err) => {
    if (err) return next(err);
    res.redirect("/");
  });
});

app.get("/secrets", async (req, res) => {
  if (req.isAuthenticated()) {
    try {
      const result = await db.query("SELECT secret FROM users WHERE email=$1", [
        req.user.email,
      ]);
      const secret = result.rows[0]?.secret || "Don't tell anyone Bhanupranay is a good boy";
      res.render("secrets.ejs", { secret });
    } catch (err) {
      console.log(err);
      res.redirect("/");
    }
  } else {
    res.redirect("/login");
  }
});

app.get("/submit", (req, res) => {
  if (req.isAuthenticated()) res.render("submit.ejs");
  else res.redirect("/login");
});

app.post("/submit", async (req, res) => {
  if (!req.isAuthenticated()) return res.redirect("/login");
  const submittedSecret = req.body.secret;
  try {
    await db.query("UPDATE users SET secret=$1 WHERE email=$2", [
      submittedSecret,
      req.user.email,
    ]);
    res.redirect("/secrets");
  } catch (err) {
    console.log(err);
    res.redirect("/submit");
  }
});

// --- Auth Routes ---
app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));
app.get(
  "/auth/google/secrets",
  passport.authenticate("google", { successRedirect: "/secrets", failureRedirect: "/login" })
);

// --- Local Auth ---
passport.use(
  "local",
  new Strategy(async function verify(username, password, cb) {
    try {
      const result = await db.query("SELECT * FROM users WHERE email=$1", [username]);
      if (!result.rows.length) return cb("User not found");

      const user = result.rows[0];
      bcrypt.compare(password, user.password, (err, valid) => {
        if (err) return cb(err);
        return cb(null, valid ? user : false);
      });
    } catch (err) {
      cb(err);
    }
  })
);

app.post(
  "/login",
  passport.authenticate("local", { successRedirect: "/secrets", failureRedirect: "/login" })
);

app.post("/register", async (req, res) => {
  const { username: email, password } = req.body;
  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email=$1", [email]);
    if (checkResult.rows.length) return res.redirect("/login");

    const hash = await bcrypt.hash(password, saltRounds);
    const result = await db.query(
      "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
      [email, hash]
    );
    const user = result.rows[0];
    req.login(user, (err) => (err ? console.log(err) : res.redirect("/secrets")));
  } catch (err) {
    console.log(err);
    res.redirect("/register");
  }
});

// --- Google OAuth ---
passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        const result = await db.query("SELECT * FROM users WHERE email=$1", [profile.email]);
        if (!result.rows.length) {
          const newUser = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
            [profile.email, "google"]
          );
          return cb(null, newUser.rows[0]);
        } else return cb(null, result.rows[0]);
      } catch (err) {
        return cb(err);
      }
    }
  )
);

// --- Passport Serialize/Deserialize ---
passport.serializeUser((user, cb) => cb(null, user));
passport.deserializeUser((user, cb) => cb(null, user));

// --- Start Server ---
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
