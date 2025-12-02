// Load environment variables from .env file into memory
require('dotenv').config();

const bcrypt = require("bcrypt");
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
        database : process.env.RDS_DB_NAME || "ellarises",
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
        console.log("Participant is logged in:", req.session.username);
        next();
    } else {
        console.log("Participant is NOT logged in, redirecting to login...");
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

app.post("/login", async (req, res) => {
    try {
        const sEmail = req.body.email;
        const enteredPassword = req.body.password;

        // 1. Get participant by email
        const participants = await knex("participants")
            .select("participant_id", "participant_email", "password", "participant_role")
            .where("participant_email", sEmail);

        if (participants.length === 0) {
            return res.render("login", { error_message: "Invalid login" });
        }

        const user = participants[0];

        // 2. Compare entered password with stored hash
        const isValid = await bcrypt.compare(enteredPassword, user.password);

        if (!isValid) {
            return res.render("login", { error_message: "Invalid login" });
        }

        // 3. Create session
        req.session.isLoggedIn = true;
        req.session.email = sEmail;
        req.session.participant_id = user.participant_id;
        req.session.participant_role = user.participant_role;

        console.log("Login successful");
        res.redirect("/homepage");

    } catch (err) {
        console.error("Login error:", err);
        res.render("login", { error_message: "Invalid login" });
    }
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
        username: req.session.email,
        
        participant_role: req.session.participant_role 
    });
});

app.get("/events", async (req, res) => {
    if (!req.session.isLoggedIn) {
        return res.redirect("/login");
    }

    try {
        // Fetch data ONLY from event_templates to avoid duplicates
        const events = await knex("event_templates")
            .select(
                // Select and alias fields to match the names expected by events.ejs
                "event_template_id AS eventid",
                "event_name AS eventname",
                "event_type AS eventtype",
                "event_description AS eventdescription",
                "event_default_capacity AS eventdefaultcapacity",
                "event_recurrence_pattern AS eventrecurrencepattern"
            )
            .orderBy("event_name", "asc");

        // 2. Render the template with the fetched data
        res.render("events", {
            username: req.session.email,
            participant_role: req.session.participant_role, 
            events: events
        });

    } catch (err) {
        console.error("Error loading events:", err);
        // Render the page with an empty array if the query fails, to prevent a crash
        res.render("events", {
            username: req.session.email,
            participant_role: req.session.participant_role,
            events: [],
            error_message: "Error loading events from the database."
        });
    }
});

app.get("/postsurveys", async (req, res) => {
    if (!req.session.isLoggedIn) {
        return res.redirect("/login");
    }

    try {
        // Query ONLY the surveys table for the requested 9 columns
        const surveys = await knex("surveys")
            .select(
                "survey_id AS surveyid",
                knex.raw("TO_CHAR(survey_submission_date, 'YYYY-MM-DD') AS submission_date"),
                "survey_satisfaction_score AS satisfaction",
                "survey_usefulness_score AS usefulness",
                "survey_instructor_score AS instructor_rating",
                "survey_recommendation_score AS recommendation",
                "survey_overall_score AS rating", 
                "survey_nps_bucket AS nps",
                
                "survey_comments AS comments"
            )
            .orderBy("survey_id", "asc");

        // Determine if manager using the correct session variable
        const isManager = req.session.participant_role === "manager" || req.session.participant_role === "Manager";

        // Render the template with the fetched data and correct role variable
        res.render("postsurveys", {
            username: req.session.email,
            participant_role: req.session.participant_role,
            isManager: isManager,
            surveys: surveys,
            error_message: null
        });

    } catch (err) {
        console.error("Error loading surveys:", err);
        // Ensure the page still renders on error
        res.render("postsurveys", {
            username: req.session.email,
            participant_role: req.session.participant_role,
            isManager: false,
            surveys: [],
            error_message: "Error loading surveys from the database."
        });
    }
});



// DONATIONS PAGE
app.get("/donations", async (req, res) => {
    try {
        const donations = await knex("donations as d")
            .join("participants as p", "d.participant_id", "p.id")
            .select(
                "d.id",
                "d.donation_date",
                "d.donation_amount",
                "p.first_name",
                "p.last_name"
            )
            .orderBy("d.donation_date", "desc");

        res.render("donations", {
            donations,
            role: req.session.permissions,
            error_message: null
        });

    } catch (err) {
        console.error(err);
        res.render("donations", {
            donations: [],
            role: req.session.permissions,
            error_message: "Error loading donations"
        });
    }
});


// PARTICIPANTS PAGE
app.get("/participants", async (req, res) => {
    try {
        const participants = await knex("participants").select("*");

        res.render("participants", {
            participants,
            role: req.session.permissions,
            error_message: null
        });

    } catch (err) {
        console.error(err);
        res.render("participants", {
            participants: [],
            role: req.session.permissions,
            error_message: "Error loading participants"
        });
    }
});


app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
});