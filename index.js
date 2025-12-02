// Load environment variables from .env file into memory
require('dotenv').config();

const express = require("express");
const session = require("express-session");
const path = require("path");
const multer = require("multer");
const bodyParser = require("body-parser");

const app = express();
app.set("view engine", "ejs");

console.log("Starting server setup...");

// Root directory for static images
const uploadRoot = path.join(__dirname, "images");
const uploadDir = path.join(uploadRoot, "uploads");

// Configure Multer for file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        console.log("Uploading file to:", uploadDir);
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        console.log("Original filename:", file.originalname);
        cb(null, file.originalname);
    }
});
const upload = multer({ storage });

app.use("/images", express.static(uploadRoot));
app.use(express.static(path.join(__dirname, "public")));

const port = process.env.PORT || 3001;

// Session setup
app.use(session({
    secret: process.env.SESSION_SECRET || 'fallback-secret-key',
    resave: false,
    saveUninitialized: false,
}));

// CSP middleware
app.use((req, res, next) => {
    console.log("Applying Content-Security-Policy headers...");
    res.setHeader(
        'Content-Security-Policy',
        "default-src 'self' http://localhost:* ws://localhost:* wss://localhost:*; " +
        "connect-src 'self' http://localhost:* ws://localhost:* wss://localhost:*; " +
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; " +
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; " +
        "img-src 'self' data: https:; " +
        "font-src 'self' https://cdn.jsdelivr.net;"
    );
    next();
});

// PostgreSQL connection via Knex
const knex = require("knex")({
    client: "pg",
    connection: {
        host : process.env.RDS_HOSTNAME || "localhost",
        user : process.env.RDS_USERNAME || "postgres",
        password : process.env.RDS_PASSWORD || "admin",
        database : process.env.RDS_DB_NAME || "assignment 3",
        port : process.env.RDS_PORT || 5432,
        ssl: process.env.DB_SSL ? {rejectUnauthorized: false}: false
    }
});

app.use(express.urlencoded({extended: true}));

// Global authentication middleware
app.use((req, res, next) => {
    console.log("Auth middleware: checking path:", req.path);
    if (req.path === '/' || req.path === '/login' || req.path === '/logout') {
        return next();
    }

    if (req.session.isLoggedIn) {
        console.log("User is logged in:", req.session.username);
        next();
    } else {
        console.log("User is NOT logged in, redirecting to login...");
        res.render("login", { error_message: "Please log in to access this page" });
    }
});

// Routes
app.get("/login", (req, res) => {
    console.log("GET /login");
    if (req.session.isLoggedIn) {
        console.log("Already logged in, redirecting to index");
        res.render("index");
    } else {
        res.render("login", { error_message: "" });
    }
});

app.post("/login", (req, res) => {
    const sName = req.body.username;
    const sPassword = req.body.password;
    console.log("Post Login");

    knex
        .select("id", "username", "password", "level") 
        .from("users")
        .where("username", sName)
        .andWhere("password", sPassword)
        .then(users => {
            if (users.length > 0) {
                const user = users[0];

                req.session.isLoggedIn = true;
                req.session.username = user.username;
                req.session.userid = user.id;

                // Map DB level -> role string
                // assume: 'M' = manager, anything else = user
                req.session.role = user.level === "M" ? "manager" : "user";

                console.log("Login successful, role =", req.session.role);
                res.redirect("/homepage");
            } else {
                res.render("login", { error_message: "Invalid login" });
            }
        })
        .catch(err => {
            console.error("Login error:", err);
            res.render("login", { error_message: "Invalid login" });
        });
});

app.get("/", (req, res) => {
    console.log("GET /");
    res.render("index")
});

app.get("/homepage", (req, res) => {
    if (!req.session.isLoggedIn) {
        return res.redirect("/login");
    }

    res.render("homepage", {
        username: req.session.username,
        role: req.session.role
    });
});

app.get("/events", (req, res) => {
    if (!req.session.isLoggedIn) {
        return res.redirect("/login");
    }

    // Temporary placeholder until DB is connected
    const events = [];

    res.render("events", {
        username: req.session.username,
        permissions: req.session.permissions,
        events: events
    });
});

app.get("/postsurveys", (req, res) => {
    if (!req.session.isLoggedIn) {
        return res.redirect("/login");
    }

    // Placeholder until DB added
    const surveys = [];

    const isManager = req.session.role === "manager" || req.session.role === "Manager";

    res.render("postsurveys", {
        username: req.session.username,
        role: req.session.role,
        isManager: isManager,
        surveys: surveys
    });
});

app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
});