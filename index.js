// Group 2-11

// Ella Rises app server: Express + EJS with sessions, CSP, and a Postgres (Knex) connection.
// Handles login/register/logout and access based on roles(admin/manager)


// Load environment variables from .env file into memory
require('dotenv').config();

const express = require("express");
const session = require("express-session");
const path = require("path");
const bodyParser = require("body-parser");

const bcrypt = require("bcrypt");
const app = express();
app.set("view engine", "ejs");

console.log("Starting server setup...");

app.use(express.static(path.join(__dirname, "public")));

const port = process.env.PORT || 3001;

// Session setup
app.use(session({
    secret: process.env.SESSION_SECRET || 'fallback-secret-key',
    resave: false,
    saveUninitialized: false,
}));

// Expose auth info to all views
app.use((req, res, next) => {
    res.locals.isLoggedIn = !!req.session.isLoggedIn;
    res.locals.currentRole = req.session.role || "";
    res.locals.currentUser = req.session.username || req.session.email || "";
    next();
});

// CSP middleware
app.use((req, res, next) => {
    console.log("Applying Content-Security-Policy headers...");
    res.setHeader(
        'Content-Security-Policy',
        "default-src 'self' http://localhost:* ws://localhost:* wss://localhost:*; " +
        "script-src 'self' 'unsafe-inline'; " +
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
        "img-src 'self' data: https:; " + // 'https:' allows images from any HTTPS source
        "font-src 'self' https://fonts.gstatic.com; " +
        "frame-src https://www.youtube.com https://www.youtube-nocookie.com;"
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

// Helpers
const requireLogin = (req, res, next) => {
    if (!req.session.isLoggedIn) {
        return res.redirect("/login");
    }
    next();
};

const requireAdmin = (req, res, next) => {
    if (!req.session.isLoggedIn) {
        return res.redirect("/login");
    }
    const role = (req.session.role || "").toLowerCase();
    if (role !== "admin" && role !== "manager") {
        return res.status(403).send("Forbidden");
    }
    next();
};
// Alias for older references
const requireManager = requireAdmin;

// Normalize phone numbers to a consistent (XXX)XXX-XXXX format, with optional country code prefix.
const normalizePhoneNumber = (raw, { required = false } = {}) => {
    const input = (raw || "").trim();
    if (!input) {
        return required ? { error: "Phone number is required." } : { value: null };
    }

    // Keep only digits so international numbers like +44 20 7946 0958 are accepted.
    const digits = input.replace(/\D/g, "");
    if (digits.length < 10) {
        return { error: "Phone number must include at least 10 digits." };
    }

    const national = digits.slice(-10);
    const country = digits.slice(0, -10);
    const formattedLocal = `(${national.slice(0,3)})${national.slice(3,6)}-${national.slice(6)}`;
    const formatted = country ? `+${country} ${formattedLocal}` : formattedLocal;

    return { value: formatted };
};

// Global authentication middleware
app.use((req, res, next) => {
    console.log("Auth middleware: checking path:", req.path);
    if (req.path === '/teapot' ||
        req.path === '/' ||
        req.path === '/login' ||
        req.path === '/logout' ||
        req.path === '/register' ||
        (req.method === 'GET' && req.path === '/donations')
    ) {
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

//--------------------------------------------------------------------------------------------
// ROUTES

// Login
app.get("/login", (req, res) => {
    console.log("GET /login");
    if (req.session.isLoggedIn) {
        console.log("Already logged in, redirecting to home");
        return res.redirect("/");
    } else {
        res.render("login", { error_message: "" });
    }
});

// Register
app.get("/register", (req, res) => {
    // check for login
    if (req.session.isLoggedIn) {
        return res.redirect("/");
    }
    res.render("register", { error_message: "" });
});

// Sends register info to get checked if exists
app.post("/register", async (req, res) => {
    const {
        participant_email,
        password,
        participant_first_name,
        participant_last_name,
        participant_dob,
        participant_phone,
        participant_city,
        participant_state,
        participant_zip,
        participant_school_or_employer,
        participant_field_of_interest
    } = req.body;

    try {
        const phoneResult = normalizePhoneNumber(participant_phone, { required: true });
        if (phoneResult.error) {
            return res.render("register", { error_message: phoneResult.error });
        }

        // Check if user already exists
        const existingUser = await knex("participants")
            .where({ participant_email: participant_email })
            .first();

        if (existingUser) {
            return res.render("register", { error_message: "An account with that email already exists." });
        }

        const hashed = await bcrypt.hash(password, 10);
        // Insert participant as the auth user record
        const [created] = await knex("participants")
            .insert({
                participant_email: participant_email,
                participant_first_name,
                participant_last_name,
                password: hashed,
                participant_role: "participant",
                participant_dob: participant_dob || null,
                participant_phone: phoneResult.value,
                participant_city,
                participant_state,
                participant_zip,
                participant_school_or_employer,
                participant_field_of_interest
            })
            .returning(["participant_id", "participant_email", "participant_role", "participant_first_name", "participant_last_name"]);

        req.session.isLoggedIn = true;
        req.session.participant_id = created.participant_id;
        req.session.email = created.participant_email;
        req.session.role = "participant";
        req.session.username = `${created.participant_first_name} ${created.participant_last_name}`.trim();

        res.redirect("/");
    } catch (err) {
        console.error("Register error:", err);
        res.render("register", { error_message: "Registration failed" });
    }
});

// Logout route
app.get("/logout", (req, res) => {
    req.session.destroy(() => {
        // directs back to login
        res.redirect("/login");
    });
});

// Login route
app.post("/login", (req, res) => {
    let sEmail = req.body.email;
    let sPassword = req.body.password;
    // Teapot error check
    if (sEmail.trim() === "Yeet!"){
        // shows teapot page
        return res.redirect("/teapot");
    }
    console.log('Post Login')
    knex("participants")
        // searching database to pull info
        // SQL Query
        .select("participant_id","participant_email","password","participant_role","participant_first_name","participant_last_name")
        .where("participant_email", sEmail)
        .then(async participants => {
            if (participants.length === 0) {
                return res.render("login", { error_message: "Invalid login" });
            }
            const user = participants[0];
            const isValid = await bcrypt.compare(sPassword, user.password);
            if (!isValid) {
                return res.render("login", { error_message: "Invalid login" });
            }
            const normalizedRole = (user.participant_role || "").toLowerCase() === "manager" ? "admin" : (user.participant_role || "");
            req.session.isLoggedIn = true;
            req.session.participant_id = user.participant_id;
            req.session.email = user.participant_email;
            req.session.role = normalizedRole || "participant";
            req.session.username = `${user.participant_first_name} ${user.participant_last_name}`;
            const nextPath = req.session.redirectAfterLogin || "/homepage";
            delete req.session.redirectAfterLogin;
            res.redirect(nextPath);
        })
        .catch(err => {
            console.error("Login error:", err);
            res.render("login", { error_message: "Invalid login"});
        });
});

// Initail page route
app.get("/", (req, res) => {
    console.log("GET /");
    res.render("index") // first page
});

// Dashboard route
app.get("/dashboard", async (req, res) => {
    if (!req.session.isLoggedIn) {
        return res.redirect("/login");
    }
    // shows the tableau
    res.render("dashboard", {
        username: req.session.username,
        role: req.session.role
    });
});

// Homepage (logged-in landing)
app.get("/homepage", async (req, res) => {
    if (!req.session.isLoggedIn) {
        return res.redirect("/login");
    }
    try {
        const participantId = req.session.participant_id;
        let tasks = [];
        let weekEvents = [];
        const registrations = participantId
            ? await knex("registrations").where("participant_id", participantId).select("event_occurrence_id", "registration_status")
            : [];
        const registeredEventIds = registrations.map(r => r.event_occurrence_id);
        const registrationStatusByEvent = registrations.reduce((acc, r) => {
            acc[r.event_occurrence_id] = r.registration_status;
            return acc;
        }, {});
        const completedSurveyIds = participantId
            ? await knex("surveys").where("participant_id", participantId).pluck("event_occurrence_id")
            : [];

        if (participantId) {
            tasks = await knex("registrations as r")
                .leftJoin("event_occurrences as eo", "r.event_occurrence_id", "eo.event_occurrence_id")
                .leftJoin("event_templates as et", "eo.event_template_id", "et.event_template_id")
                .leftJoin("surveys as s", function() {
                    this.on("s.event_occurrence_id", "eo.event_occurrence_id")
                        .andOn("s.participant_id", "r.participant_id");
                })
                .select(
                    "r.registration_id as registration_id",
                    "r.registration_status",
                    "eo.event_occurrence_id as id",
                    "et.event_name as name",
                    "eo.event_date_time_start as start",
                    "et.event_type as type"
                )
                .where("r.participant_id", participantId)
                .whereNot("r.registration_status", "no-show")
                .whereNull("s.survey_id")
                .andWhere("eo.event_date_time_start", "<", knex.fn.now())
                .orderBy("eo.event_date_time_start", "asc");
        }

        // Week at a glance (current week)
        const today = new Date();
        today.setHours(0,0,0,0);
        const startOfWeek = new Date(today);
        startOfWeek.setDate(today.getDate() - today.getDay()); // Sunday start
        const endOfWeek = new Date(startOfWeek);
        endOfWeek.setDate(startOfWeek.getDate() + 7);
        const startOfWeekStr = startOfWeek.toISOString().slice(0,10);

        weekEvents = await knex("event_occurrences as eo")
            .leftJoin("event_templates as et", "eo.event_template_id", "et.event_template_id")
            .select(
                "eo.event_occurrence_id as id",
                "et.event_name as name",
                "eo.event_date_time_start as start",
                "et.event_type as type",
                "et.event_description as description",
                "et.event_default_capacity as capacity"
            )
            .whereBetween("eo.event_date_time_start", [startOfWeek.toISOString(), endOfWeek.toISOString()])
            .orderBy("eo.event_date_time_start", "asc");

        // shows homepage with related info
        res.render("homepage", {
            username: req.session.username,
            role: req.session.role,
            tasks,
            weekEvents,
            registeredEventIds,
            registrationStatusByEvent,
            completedSurveyIds,
            startOfWeek: startOfWeekStr,
            error_message: ""
        });
    } catch (err) {
        console.error("Error loading homepage:", err);
        res.render("homepage", {
            username: req.session.username,
            role: req.session.role,
            tasks: [],
            weekEvents: [],
            registeredEventIds: [],
            registrationStatusByEvent: {},
            completedSurveyIds: [],
            startOfWeek: "",
            error_message: "Unable to load tasks right now."
        });
    }
});

// Calender route
app.get("/calendar", async (req, res) => {
    // check if logged in
    if (!req.session.isLoggedIn) {
        return res.redirect("/login");
    }
    const participantId = req.session.participant_id;
    try {
        const registeredEventIds = participantId
            ? await knex("registrations").where("participant_id", participantId).pluck("event_occurrence_id")
            : [];
        const completedSurveyIds = participantId
            ? await knex("surveys").where("participant_id", participantId).pluck("event_occurrence_id")
            : [];

        const events = await knex("event_occurrences as eo")
            .leftJoin("event_templates as et", "eo.event_template_id", "et.event_template_id")
            .select(
                "eo.event_occurrence_id as id",
                "et.event_name as name",
                "eo.event_date_time_start as start",
                "et.event_type as type",
                "et.event_description as description",
                "et.event_default_capacity as capacity"
            )
            .orderBy("eo.event_date_time_start", "asc");

        const eventTemplates = await knex("event_templates")
            .select("event_template_id as id", "event_name as name")
            .orderBy("event_name", "asc");

        // show calender
        res.render("calendar", {
            username: req.session.username,
            role: req.session.role,
            events,
            eventTemplates,
            registeredEventIds,
            completedSurveyIds
        });
    } catch (err) {
        console.error("Error loading events for calendar:", err);
        res.render("calendar", {
            username: req.session.username,
            role: req.session.role,
            events: [],
            eventTemplates: [],
            registeredEventIds: [],
            completedSurveyIds: []
        });
    }
});

// Event registration page
app.get("/events/register/:id", async (req, res) => {
    if (!req.session.isLoggedIn) {
        return res.redirect("/login");
    }
    const id = req.params.id;
    const month = req.query.month || "";
    const from = req.query.from || "";
    const anchor = req.query.anchor || "";
    const backLink = req.query.back ||
        (from === "homepage"
            ? `/homepage${anchor ? '#' + anchor : ''}`
            : (month ? `/calendar?month=${month}` : "/calendar"));
    try {
        const event = await knex("event_occurrences as eo")
            .leftJoin("event_templates as et", "eo.event_template_id", "et.event_template_id")
            .select(
                "eo.event_occurrence_id as id",
                "et.event_name as name",
                "eo.event_date_time_start as start",
                "et.event_type as type",
                "et.event_description as description",
                "et.event_default_capacity as capacity"
            )
            .where("eo.event_occurrence_id", id)
            .first();

        if (!event) return res.redirect("/homepage");

        res.render("registerEvent", {
            event,
            success_message: "",
            error_message: "",
            month,
            from,
            anchor,
            backLink
        });
    } catch (err) {
        console.error("Error loading event for registration:", err);
        res.redirect("/homepage");
    }
});

// Register for an event
app.post("/events/register/:id", async (req, res) => {
    if (!req.session.isLoggedIn) {
        return res.redirect("/login");
    } // info sent to server
    const id = req.params.id;
    const participantId = req.session.participant_id;
    const month = req.body.month || "";
    const from = req.body.from || "";
    const anchor = req.body.anchor || "";
    const backLink = req.body.backLink ||
        (from === "homepage"
            ? `/homepage${anchor ? '#' + anchor : ''}`
            : (month ? `/calendar?month=${month}` : "/calendar"));

    try {
        console.log("POST /events/register", { id, month, from, anchor, participantId });
        const event = await knex("event_occurrences as eo")
            .leftJoin("event_templates as et", "eo.event_template_id", "et.event_template_id")
            .select(
                "eo.event_occurrence_id as id",
                "et.event_name as name",
                "eo.event_date_time_start as start",
                "et.event_type as type",
                "et.event_description as description",
                "et.event_default_capacity as capacity"
            )
            .where("eo.event_occurrence_id", id)
            .first();

        if (!event) return res.redirect("/homepage");

        if (!participantId) {
            return res.render("registerEvent", {
                event,
                success_message: "",
                error_message: "You must be logged in as a participant to register.",
                month,
                from,
                anchor
            });
        }

        // Avoid duplicate registrations
        const existing = await knex("registrations")
            .where({
                participant_id: participantId,
                event_occurrence_id: id
            })
            .first();

        if (!existing) {
            await knex("registrations").insert({
                participant_id: participantId,
                event_occurrence_id: id,
                registration_status: "registered",
                registration_attended_flag: false,
                registration_check_in_time: null,
                registration_created_at: new Date().toISOString()
            });
        }

        // Redirect back to origin like survey flow
        if (from === "homepage") {
            return res.redirect(backLink || "/homepage");
        }
        const monthQuery = month ? `?month=${month}` : "";
        return res.redirect(`/calendar${monthQuery}`);
    } catch (err) {
        console.error("Error registering for event:", err);
        res.render("registerEvent", {
            event: null,
            success_message: "",
            error_message: "Unable to register right now. Please try again.",
            month,
            from,
            anchor,
            backLink
        });
    }
});

// Create event occurrence from calendar (admin only)
app.post("/calendar/occurrences", requireManager, async (req, res) => {
    const { date, templateId, startTime, endTime } = req.body;
    if (!date || !templateId || !startTime || !endTime) {
        return res.status(400).send("Missing date, template, or times");
    }
    const start = new Date(`${date}T${startTime}`);
    const end = new Date(`${date}T${endTime}`);
    if (isNaN(start) || isNaN(end) || end <= start) {
        return res.status(400).send("Invalid start/end time");
    }
    try {
        await knex("event_occurrences").insert({
            event_template_id: templateId,
            event_date_time_start: start.toISOString(),
            event_date_time_end: end.toISOString(),
            event_location: "",
            event_registration_deadline: start.toISOString()
        });
        res.redirect("/calendar");
    } catch (err) {
        console.error("Error creating event occurrence:", err);
        res.status(500).send("Failed to create occurrence");
    }
});

// Delete event occurrence by ID (admin only)
app.delete("/calendar/occurrences/:id", requireManager, async (req, res) => {
    const id = req.params.id;
    try {
        await knex("event_occurrences").where("event_occurrence_id", id).del();
        res.status(204).send();
    } catch (err) {
        console.error("Error deleting event occurrence:", err);
        res.status(500).send("Failed to delete occurrence");
    }
});

// Take survey - form
app.get("/surveys/take", requireLogin, async (req, res) => {
    const eventId = req.query.eventId;
    if (!eventId) return res.redirect("/calendar");
    const anchor = req.query.anchor || "";
    try {
        const event = await knex("event_occurrences as eo")
            .leftJoin("event_templates as et", "eo.event_template_id", "et.event_template_id")
            .select(
                "eo.event_occurrence_id as id",
                "et.event_name as name",
                "eo.event_date_time_start as start",
                "et.event_type as type"
            )
            .where("eo.event_occurrence_id", eventId)
            .first();
        // if there is no event, redirect to calendar
        if (!event) return res.redirect("/calendar");

        const calendarMonth = event.start ? (() => {
            const d = new Date(event.start);
            if (isNaN(d)) return "";
            return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-01`;
        })() : "";

        res.render("takeSurvey", {
            error_message: "",
            success_message: "",
            event,
            from: req.query.from || "",
            calendarMonth,
            anchor
        });
    } catch (err) {
        console.error("Error loading survey form:", err);
        res.redirect("/calendar");
    }
});

// Take survey - submit
app.post("/surveys/take", requireLogin, async (req, res) => {
    const eventId = req.body.eventId;
    const participantId = req.session.participant_id;
    if (!eventId || !participantId) return res.redirect("/calendar");

    const {
        satisfaction_score,
        usefulness_score,
        instructor_score,
        recommendation_score,
        overall_score,
        comments,
        from,
        calendarMonth,
        anchor
    } = req.body;

    try {
        await knex("surveys").insert({
            survey_satisfaction_score: satisfaction_score,
            survey_usefulness_score: usefulness_score,
            survey_instructor_score: instructor_score,
            survey_recommendation_score: recommendation_score,
            survey_overall_score: overall_score,
            survey_nps_bucket: (() => {
                const rec = parseInt(recommendation_score, 10);
                if (rec >= 5) return "Promoter";
                if (rec === 4) return "Passive";
                return "Detractor";
            })(),
            survey_comments: comments || "",
            survey_submission_date: new Date().toISOString(),
            participant_id: participantId,
            event_occurrence_id: eventId
        });

        if (from === "homepage") {
            const hash = anchor ? `#${anchor}` : "";
            res.redirect(`/homepage${hash}`);
        } else {
            const monthQuery = calendarMonth ? `?month=${calendarMonth}` : "";
            res.redirect(`/calendar${monthQuery}`);
        }
    } catch (err) {
        console.error("Error submitting survey:", err);
        let event = null;
        try {
            event = await knex("event_occurrences as eo")
                .leftJoin("event_templates as et", "eo.event_template_id", "et.event_template_id")
                .select(
                    "eo.event_occurrence_id as id",
                    "et.event_name as name",
                    "eo.event_date_time_start as start",
                    "et.event_type as type"
                )
                .where("eo.event_occurrence_id", eventId)
                .first();
        } catch (_) {}
        res.render("takeSurvey", {
            success_message: "",
            error_message: "Could not submit survey. Please try again.",
            event: event || { id: eventId },
            from,
            calendarMonth,
            anchor
        });
    }
});

// Mark registration as no-show
app.post("/registrations/:id/no-show", requireLogin, async (req, res) => {
    const regId = req.params.id;
    const participantId = req.session.participant_id;
    if (!participantId) return res.redirect("/homepage");
    try {
        const reg = await knex("registrations").where("registration_id", regId).first();
        if (!reg || reg.participant_id !== participantId) {
            return res.status(403).send("Forbidden");
        }
        await knex("registrations")
            .where("registration_id", regId)
            .update({ registration_status: "no-show" });
        res.redirect("/homepage#tasks");
    } catch (err) {
        console.error("Error marking no-show:", err);
        res.redirect("/homepage#tasks");
    }
});

// Mark registration as attended
app.post("/registrations/:id/attended", requireLogin, async (req, res) => {
    const regId = req.params.id;
    const participantId = req.session.participant_id;
    if (!participantId) return res.redirect("/homepage");
    try {
        const reg = await knex("registrations").where("registration_id", regId).first();
        if (!reg || reg.participant_id !== participantId) {
            return res.status(403).send("Forbidden");
        }
        await knex("registrations")
            .where("registration_id", regId)
            .update({ registration_status: "attended" });
        res.redirect("/homepage#tasks");
    } catch (err) {
        console.error("Error marking attended:", err);
        res.redirect("/homepage#tasks");
    }
});

// Events page
app.get("/events", async (req, res) => {
    if (!req.session.isLoggedIn) {
        return res.redirect("/login");
    }

    const pageSize = 20;
    const page = Math.max(parseInt(req.query.page) || 1, 1);
    const offset = (page - 1) * pageSize;

    const search = req.query.search || "";
    // SQL to grab events from database
    try {
        let query = knex("event_templates")
            .select(
                "event_template_id as eventid",
                "event_name as eventname",
                "event_type as eventtype",
                "event_description as eventdescription",
                "event_default_capacity as eventdefaultcapacity",
                "event_recurrence_pattern as eventrecurrencepattern"
            )
            .orderBy("eventname", "asc");

    if (search.trim() !== "") {
            query = query.where(builder => {
                builder
                    .whereILike("event_name", `%${search}%`)
                    .orWhereILike("event_type", `%${search}%`)
                    .orWhereILike("event_description", `%${search}%`)
                    .orWhereILike("event_recurrence_pattern", `%${search}%`)
                    .orWhereRaw("CAST(event_default_capacity AS TEXT) ILIKE ?", [`%${search}%`])
            });
        }

        const totalRow = await query.clone().clearSelect().clearOrder().count("* as count").first();
        const total = parseInt(totalRow.count, 10) || 0;
        const totalPages = Math.max(1, Math.ceil(total / pageSize));

        const events = await query.limit(pageSize).offset(offset);

        res.render("events", {
            username: req.session.username,
            role: req.session.role,
            events,
            search,
            pagination: { page, totalPages }
        });

    } catch (err) {
        console.error("Error loading events:", err);
        res.render("events", {
            username: req.session.username,
            role: req.session.role,
            events: [],
            error_message: "Error loading events",
            search,
            pagination: { page: 1, totalPages: 1 }
        });
    }
});


// Add Event - form
app.get("/events/add", requireManager, (req, res) => {
    res.render("addEvents", { error_message: "" });
});

// Add Event - submit
app.post("/events/add", requireManager, (req, res) => {
    const { eventname, eventtype, eventdescription, eventrecurrencepattern, eventdefaultcapacity } = req.body;
    knex("event_templates")
        .insert({
            event_name: eventname,
            event_type: eventtype,
            event_description: eventdescription,
            event_recurrence_pattern: eventrecurrencepattern,
            event_default_capacity: eventdefaultcapacity
        })
        .then(() => res.redirect("/events"))
        .catch(err => {
            console.error("Error adding event:", err);
            res.render("addEvents", { error_message: "Failed to add event" });
        });
});

// Edit Event - form
app.get("/events/edit/:id", requireManager, (req, res) => {
    const id = req.params.id;
    knex("event_templates")
        .where("event_template_id", id)
        .first()
        .then(event => {
            if (!event) {
                return res.redirect("/events");
            }
            res.render("editEvents", {
                error_message: "",
                event: {
                    eventid: event.event_template_id,
                    eventname: event.event_name,
                    eventtype: event.event_type,
                    eventdescription: event.event_description,
                    eventrecurrencepattern: event.event_recurrence_pattern,
                    eventdefaultcapacity: event.event_default_capacity
                }
            });
        })
        .catch(err => {
            console.error("Error loading event:", err);
            res.redirect("/events");
        });
});

// Edit Event - submit
app.post("/events/edit/:id", requireManager, (req, res) => {
    const id = req.params.id;
    const { eventname, eventtype, eventdescription, eventrecurrencepattern, eventdefaultcapacity } = req.body;
    knex("event_templates")
        .where("event_template_id", id)
        .update({
            event_name: eventname,
            event_type: eventtype,
            event_description: eventdescription,
            event_recurrence_pattern: eventrecurrencepattern,
            event_default_capacity: eventdefaultcapacity
        })
        .then(() => res.redirect("/events"))
        .catch(err => {
            console.error("Error updating event:", err);
            res.render("editEvents", {
                error_message: "Failed to update event",
                event: {
                    eventid: id,
                    eventname,
                    eventtype,
                    eventdescription,
                    eventrecurrencepattern,
                    eventdefaultcapacity
                }
            });
        });
});

// Delete Event
app.post("/events/delete/:id", requireManager, (req, res) => {
    const id = req.params.id;
    knex("event_templates")
        .where("event_template_id", id)
        .del()
        .then(() => res.redirect("/events"))
        .catch(err => {
            console.error("Error deleting event:", err);
            res.redirect("/events");
        });
});

// Post surveys page route
app.get("/postsurveys", async (req, res) => {
    if (!req.session.isLoggedIn) return res.redirect("/login");

    const search = req.query.search || "";
    const isManager = (req.session.role || "").toLowerCase() === "admin";
    const pageSize = 20;
    const page = Math.max(parseInt(req.query.page) || 1, 1);
    const offset = (page - 1) * pageSize;

    try {
        let query = knex("surveys as s")
            .leftJoin("participants as p", "s.participant_id", "p.participant_id")
            .leftJoin("event_occurrences as eo", "s.event_occurrence_id", "eo.event_occurrence_id")
            .leftJoin("event_templates as et", "eo.event_template_id", "et.event_template_id")
            .select(
                "s.survey_id as surveyid",
                "et.event_name as eventname",
                "eo.event_date_time_start as eventdatetimestart",
                knex.raw("concat(coalesce(p.participant_first_name,''), ' ', coalesce(p.participant_last_name,'')) as participantname"),
                "s.survey_overall_score as rating",
                "s.survey_comments as comments"
            )
            .orderBy("s.survey_id", "desc");

        if (search.trim() !== "") {
            query = query.where(builder => {
                builder
                    .whereILike("et.event_name", `%${search}%`)
                    .orWhereILike("s.survey_comments", `%${search}%`)
                    .orWhereILike(knex.raw("concat(coalesce(p.participant_first_name,''), ' ', coalesce(p.participant_last_name,''))"), `%${search}%`)
                    .orWhereRaw("CAST(s.survey_overall_score AS TEXT) ILIKE ?", [`%${search}%`])
                    .orWhereRaw("CAST(eo.event_date_time_start AS TEXT) ILIKE ?", [`%${search}%`]);
            });
        }

        const totalRow = await query.clone().clearSelect().clearOrder().count("* as count").first();
        const total = parseInt(totalRow.count, 10) || 0;
        const totalPages = Math.max(1, Math.ceil(total / pageSize));

        const surveys = await query.limit(pageSize).offset(offset);

        res.render("postsurveys", {
            username: req.session.username,
            role: req.session.role,
            isManager,
            surveys,
            search,
            pagination: { page, totalPages }
        });

    } catch (err) {
        console.error("Error loading surveys:", err);
        res.render("postsurveys", {
            username: req.session.username,
            role: req.session.role,
            isManager,
            surveys: [],
            error_message: "Error loading surveys",
            search,
            pagination: { page: 1, totalPages: 1 }
        });
    }
});


// Add Survey - form
app.get("/postsurveys/add", requireManager, async (req, res) => {
    try {
        const events = await knex("event_occurrences as eo")
            .leftJoin("event_templates as et", "eo.event_template_id", "et.event_template_id")
            .select(
                "eo.event_occurrence_id as eventid",
                "et.event_name as eventname",
                "eo.event_date_time_start as eventdatetimestart"
            )
            .orderBy("eo.event_date_time_start", "desc");

        const participants = await knex("participants")
            .select(
                "participant_id as participantid",
                knex.raw("concat(coalesce(participant_first_name,''),' ', coalesce(participant_last_name,'')) as participantname")
            )
            .orderBy("participant_first_name");

        res.render("addPostsurveys", { error_message: "", events, participants });
    } catch (err) {
        console.error("Error loading survey form data:", err);
        res.render("addPostsurveys", { error_message: "Failed to load form data", events: [], participants: [] });
    }
});

// Add Survey - submit
app.post("/postsurveys/add", requireManager, async (req, res) => {
    const { eventid, participantid, rating, comments } = req.body;
    try {
        await knex("surveys").insert({
            event_occurrence_id: eventid,
            participant_id: participantid,
            survey_overall_score: rating,
            survey_comments: comments,
            survey_submission_date: knex.fn.now()
        });
        res.redirect("/postsurveys");
    } catch (err) {
        console.error("Error adding survey:", err);
        res.redirect("/postsurveys");
    }
});

// Edit Survey - form
app.get("/postsurveys/edit/:id", requireManager, async (req, res) => {
    const id = req.params.id;
    try {
        const survey = await knex("surveys as s")
            .leftJoin("participants as p", "s.participant_id", "p.participant_id")
            .leftJoin("event_occurrences as eo", "s.event_occurrence_id", "eo.event_occurrence_id")
            .leftJoin("event_templates as et", "eo.event_template_id", "et.event_template_id")
            .select(
                "s.survey_id as surveyid",
                "et.event_name as eventname",
                "eo.event_date_time_start as eventdatetimestart",
                knex.raw("concat(coalesce(p.participant_first_name,''),' ', coalesce(p.participant_last_name,'')) as participantname"),
                "s.survey_overall_score as rating",
                "s.survey_comments as comments"
            )
            .where("s.survey_id", id)
            .first();

        if (!survey) return res.redirect("/postsurveys");
        res.render("editPostsurveys", { error_message: "", survey });
    } catch (err) {
        console.error("Error loading survey:", err);
        res.redirect("/postsurveys");
    }
});

// Edit Survey - submit
app.post("/postsurveys/edit/:id", requireManager, async (req, res) => {
    const id = req.params.id;
    const { rating, comments } = req.body;
    try {
        await knex("surveys")
            .where("survey_id", id)
            .update({
                survey_overall_score: rating,
                survey_comments: comments
            });
        res.redirect("/postsurveys");
    } catch (err) {
        console.error("Error updating survey:", err);
        res.redirect("/postsurveys");
    }
});

// Delete Survey
app.post("/postsurveys/delete/:id", requireManager, async (req, res) => {
    const id = req.params.id;
    try {
        await knex("surveys").where("survey_id", id).del();
        res.redirect("/postsurveys");
    } catch (err) {
        console.error("Error deleting survey:", err);
        res.redirect("/postsurveys");
    }
});

// Donations page
app.get("/donations", async (req, res) => {
    if (!req.session.isLoggedIn) {
        req.session.redirectAfterLogin = "/addDonations";
        return res.render("login", { error_message: "Please log in or register to make a Donation" });
    }
    const search = req.query.search || "";
    const pageSize = 20;
    const page = Math.max(parseInt(req.query.page) || 1, 1);
    const offset = (page - 1) * pageSize;

    try {
        let query = knex("donations as d")
            .join("participants as p", "d.participant_id", "p.participant_id")
            .select(
                "d.donation_id as id",
                "d.donation_date",
                "d.donation_amount",
                "p.participant_first_name as first_name",
                "p.participant_last_name as last_name"
            )
            .orderByRaw("d.donation_date DESC NULLS LAST");

        if (search.trim() !== "") {
            query = query.where(function () {
                this.orWhereRaw(
                    "concat(coalesce(p.participant_first_name,''),' ',coalesce(p.participant_last_name,'')) ILIKE ?",
                    [`%${search}%`]
                )
                .orWhereRaw("CAST(d.donation_amount AS TEXT) ILIKE ?", [`%${search}%`])
                .orWhereRaw("CAST(d.donation_date AS TEXT) ILIKE ?", [`%${search}%`]);
            });
        }

        const totalRow = await query.clone().clearSelect().clearOrder().count("* as count").first();
        const total = parseInt(totalRow.count, 10) || 0;
        const totalPages = Math.max(1, Math.ceil(total / pageSize));

        const donations = await query.limit(pageSize).offset(offset);

        res.render("donations", {
            donations,
            role: req.session.role,
            error_message: null,
            search,
            pagination: { page, totalPages }
        });

    } catch (err) {
        console.error("error:", err);
        res.render("donations", {
            donations: [],
            role: req.session.role,
            error_message: "Error loading donations",
            search,
            pagination: { page: 1, totalPages: 1 }
        });
    }
});

// Add Donation - form
app.get("/addDonations", requireLogin, async (req, res) => {
    try {
        const participants = await knex("participants")
            .select("participant_id", "participant_first_name", "participant_last_name");
        res.render("addDonations", { error_message: "", participants });
    } catch (err) {
        console.error("Error loading participants for donation:", err);
        res.render("addDonations", { error_message: "Failed to load participants", participants: [] });
    }
});

// Add Donation - submit
app.post("/addDonations", requireLogin, async (req, res) => {
    const { donation_date, donation_amount, participant_id } = req.body;
    try {
        await knex("donations").insert({
            donation_date: donation_date || null,
            donation_amount,
            participant_id
        });
        res.redirect("/donations");
    } catch (err) {
        console.error("Error adding donation:", err);
        const participants = await knex("participants")
            .select("participant_id", "participant_first_name", "participant_last_name");
        res.render("addDonations", { error_message: "Failed to add donation", participants });
    }
});

// Edit Donation - form
app.get("/editDonations/:id", requireManager, async (req, res) => {
    const id = req.params.id;
    try {
        const donation = await knex("donations").where("donation_id", id).first();
        if (!donation) return res.redirect("/donations");
        const participants = await knex("participants")
            .select("participant_id", "participant_first_name", "participant_last_name");
        res.render("editDonations", { error_message: "", donation, participants });
    } catch (err) {
        console.error("Error loading donation:", err);
        res.redirect("/donations");
    }
});

// Edit Donation - submit
app.post("/editDonations/:id", requireManager, async (req, res) => {
    const id = req.params.id;
    const { donation_date, donation_amount, participant_id } = req.body;
    try {
        await knex("donations")
            .where("donation_id", id)
            .update({
                donation_date: donation_date || null,
                donation_amount,
                participant_id
            });
        res.redirect("/donations");
    } catch (err) {
        console.error("Error updating donation:", err);
        const participants = await knex("participants")
            .select("participant_id", "participant_first_name", "participant_last_name");
        res.render("editDonations", { error_message: "Failed to update donation", donation: { donation_id: id, donation_date, donation_amount, participant_id }, participants });
    }
});

// Delete Donation
app.post("/deleteDonations/:id", requireManager, async (req, res) => {
    const id = req.params.id;
    try {
        await knex("donations").where("donation_id", id).del();
        res.redirect("/donations");
    } catch (err) {
        console.error("Error deleting donation:", err);
        res.redirect("/donations");
    }
});

// Users page route with search bar
app.get("/users", requireManager, async (req, res) => {
    try {
        const search = req.query.search || "";
        const pageSize = 20;
        const page = Math.max(parseInt(req.query.page) || 1, 1);
        const offset = (page - 1) * pageSize;

        let query = knex("participants as p")
            .select(
                "p.participant_id",
                "p.participant_email",
                "p.participant_first_name",
                "p.participant_last_name",
                "p.participant_role"
            );

        if (search.trim() !== "") {
            const s = `%${search}%`;

            query.where(function () {
                this.orWhereILike(knex.raw("concat(coalesce(p.participant_first_name,''),' ',coalesce(p.participant_last_name,''))"), s)
                    .orWhereILike("p.participant_email", s)
                    .orWhereILike("p.participant_role", s);
            });
        }

        const totalRow = await query.clone().clearSelect().clearOrder().count("* as count").first();
        const total = parseInt(totalRow.count, 10) || 0;
        const totalPages = Math.max(1, Math.ceil(total / pageSize));

        query.orderBy("p.participant_last_name", "asc")
        query.orderBy("p.participant_first_name", "asc")
        query.limit(pageSize).offset(offset);

        const users = await query;

        res.render("users", {
            users,
            role: req.session.role,
            error_message: null,
            search,
            pagination: { page, totalPages }
        });

    } catch (err) {
        console.error("Error loading users:", err);

        res.render("users", {
            users: [],
            role: req.session.role,
            error_message: "Error loading users",
            search: "",
            pagination: { page: 1, totalPages: 1 }
        });
    }
});

// Add User - form
app.get("/addUsers", requireManager, (req, res) => {
    res.render("addUsers", { error_message: "", user: {} });
});

// Add User - submit
app.post("/addUsers", requireManager, async (req, res) => {
    const {
        participant_email,
        password,
        participant_first_name,
        participant_last_name,
        participant_role
    } = req.body;

    try {
        if (!participant_email || !password || !participant_first_name || !participant_last_name) {
            return res.render("addUsers", {
                error_message: "Email, password, first name, and last name are required.",
                user: req.body
            });
        }

        const existingUser = await knex("participants")
            .where("participant_email", participant_email)
            .first();

        if (existingUser) {
            return res.render("addUsers", {
                error_message: "A user with that email already exists.",
                user: req.body
            });
        }

        const hashed = await bcrypt.hash(password, 10);

        await knex("participants").insert({
            participant_email,
            password: hashed,
            participant_first_name,
            participant_last_name,
            participant_role: participant_role || "participant"
        });

        res.redirect("/users");
    } catch (err) {
        console.error("Error adding user:", err);
        res.render("addUsers", {
            error_message: "Failed to add user",
            user: req.body
        });
    }
});

// Edit User - form
app.get("/editUsers/:id", requireManager, async (req, res) => {
    const id = req.params.id;
    try {
        const user = await knex("participants")
            .where("participant_id", id)
            .first();

        if (!user) {
            return res.redirect("/users");
        }

        res.render("editUsers", { error_message: "", user });
    } catch (err) {
        console.error("Error loading user:", err);
        res.redirect("/users");
    }
});

// Edit User - submit
app.post("/editUsers/:id", requireManager, async (req, res) => {
    const id = req.params.id;
    const {
        participant_email,
        password,
        participant_first_name,
        participant_last_name,
        participant_role
    } = req.body;

    try {
        const existingUser = await knex("participants")
            .where("participant_email", participant_email)
            .andWhereNot("participant_id", id)
            .first();

        if (existingUser) {
            return res.render("editUsers", {
                error_message: "Email already in use by another user.",
                user: { ...req.body, participant_id: id }
            });
        }

        const updates = {
            participant_email,
            participant_first_name,
            participant_last_name,
            participant_role: participant_role || "participant"
        };

        if (password && password.trim() !== "") {
            updates.password = await bcrypt.hash(password, 10);
        }

        await knex("participants")
            .where("participant_id", id)
            .update(updates);

        res.redirect("/users");
    } catch (err) {
        console.error("Error updating user:", err);
        res.render("editUsers", {
            error_message: "Failed to update user",
            user: { ...req.body, participant_id: id }
        });
    }
});

// Delete User
app.post("/deleteUsers/:id", requireManager, async (req, res) => {
    const id = req.params.id;
    try {
        await knex("participants").where("participant_id", id).del();
        res.redirect("/users");
    } catch (err) {
        console.error("Error deleting user:", err);
        res.redirect("/users");
    }
});

// Participants page route with search bar
app.get("/participants", async (req, res) => {
    try {
        const search = req.query.search || "";
        const pageSize = 20;
        const page = Math.max(parseInt(req.query.page) || 1, 1);
        const offset = (page - 1) * pageSize;

        // Start building the query
        let query = knex("participants as p").select(
            "p.participant_id",
            "p.participant_first_name",
            "p.participant_last_name",
            "p.participant_email",
            "p.participant_dob",
            "p.participant_phone",
            "p.participant_city",
            "p.participant_state",
            "p.participant_zip",
            "p.participant_school_or_employer",
            "p.participant_field_of_interest"
        );

        // Apply search filters if search query is not empty
        if (search.trim() !== "") {
            const s = `%${search}%`;
            query.where(function () {
                this.orWhereILike(knex.raw("concat(coalesce(p.participant_first_name,''),' ',coalesce(p.participant_last_name,''))"), s)
                    .orWhereILike("p.participant_email", s)
                    .orWhereILike("p.participant_city", s)
                    .orWhereILike("p.participant_state", s)
                    .orWhereILike("p.participant_school_or_employer", s)
                    .orWhereRaw("CAST(p.participant_dob AS TEXT) ILIKE ?", [s]);
            });
        }

        const totalRow = await query.clone().clearSelect().clearOrder().count("* as count").first();
        const total = parseInt(totalRow.count, 10) || 0;
        const totalPages = Math.max(1, Math.ceil(total / pageSize));

        // Sort by last name/first name and page
        query.orderBy("p.participant_last_name", "asc").orderBy("p.participant_first_name", "asc").limit(pageSize).offset(offset);

        const participants = await query;

        // Render page with results
        res.render("participants", {
            participants,
            role: req.session.role,
            error_message: null,
            search, // pass search query back to input field
            pagination: { page, totalPages }
        });

    } catch (err) {
        console.error("Error loading participants:", err);
        res.render("participants", {
            participants: [],
            role: req.session.role,
            error_message: "Error loading participants",
            search: "",
            pagination: { page: 1, totalPages: 1 }
        });
    }
});

// Milestones page route
app.get("/milestones", async (req, res) => {
    if (!req.session.isLoggedIn) return res.redirect("/login");

    const search = req.query.search || "";
    const isManager = (req.session.role || "").toLowerCase() === "admin";
    const pageSize = 20;
    const page = Math.max(parseInt(req.query.page) || 1, 1);
    const offset = (page - 1) * pageSize;

    try {
        let query = knex("milestones as m")
            .leftJoin("participants as p", "m.participant_id", "p.participant_id")
            .select(
                "m.milestone_id",
                "m.milestone_title",
                "m.milestone_date",
                knex.raw("concat(coalesce(p.participant_first_name,''), ' ', coalesce(p.participant_last_name,'')) as participant_name")
            )
            .orderBy("p.participant_last_name", "asc")
            .orderBy("p.participant_first_name", "asc");

        if (search.trim() !== "") {
            const like = `%${search}%`;

            query.where(builder => {
                builder
                    .whereILike("m.milestone_title", like)
                    .orWhereILike(knex.raw("concat(coalesce(p.participant_first_name,''), ' ', coalesce(p.participant_last_name,''))"), like)
                    .orWhereRaw("CAST(m.milestone_date AS TEXT) ILIKE ?", [like]);
            });
        }

        const totalRow = await query.clone().clearSelect().clearOrder().countDistinct("m.participant_id as count").first();
        const total = parseInt(totalRow.count, 10) || 0;
        const totalPages = Math.max(1, Math.ceil(total / pageSize));

        const milestones = await query
            .orderBy("p.participant_last_name", "asc")
            .orderBy("p.participant_first_name", "asc")
            .limit(pageSize)
            .offset(offset);

        res.render("milestones", {
            username: req.session.username,
            role: req.session.role,
            milestones,
            isManager,
            search,
            pagination: { page, totalPages }
        });

    } catch (err) {
        console.error("Error loading milestones:", err);
        res.render("milestones", {
            username: req.session.username,
            role: req.session.role,
            milestones: [],
            isManager,
            error_message: "Error loading milestones",
            search,
            pagination: { page: 1, totalPages: 1 }
        });
    }
});

// Add Milestones - form
app.get("/milestones/add", requireManager, async (req, res) => {
    try {
        const participants = await knex("participants")
            .select(
                "participant_id as participantid",
                knex.raw("concat(coalesce(participant_first_name,''),' ', coalesce(participant_last_name,'')) as participantname")
            )
            .orderBy("participant_first_name");
        res.render("addMilestones", { error_message: "", participants });
    } catch (err) {
        console.error("Error loading participants for milestones:", err);
        res.render("addMilestones", { error_message: "Failed to load participants", participants: [] });
    }
});

// Add Milestones - submit
app.post("/milestones/add", requireManager, async (req, res) => {
    const { participantid, milestonetitles, milestonedates } = req.body;
    try {
        const titles = (milestonetitles || "").split(";").map(s => s.trim()).filter(Boolean);
        const dates = (milestonedates || "").split(";").map(s => s.trim()).filter(Boolean);
        if (titles.length !== dates.length) {
            throw new Error("Titles/dates length mismatch");
        }
        const rows = titles.map((t, idx) => ({
            participant_id: participantid,
            milestone_title: t,
            milestone_date: dates[idx] || null
        }));
        if (rows.length > 0) {
            await knex("milestones").insert(rows);
        }
        res.redirect("/milestones");
    } catch (err) {
        console.error("Error adding milestones:", err);
        const participants = await knex("participants")
            .select(
                "participant_id as participantid",
                knex.raw("concat(coalesce(participant_first_name,''),' ', coalesce(participant_last_name,'')) as participantname")
            );
        res.render("addMilestones", { error_message: "Failed to add milestones", participants });
    }
});

// Edit Milestones - form (by first milestone id, edits all for that participant)
app.get("/milestones/edit/:id", requireManager, async (req, res) => {
    const id = req.params.id;
    try {
        const target = await knex("milestones").where("milestone_id", id).first();
        if (!target) return res.redirect("/milestones");

        const participantId = target.participant_id;
        const participant = await knex("participants")
            .select(
                "participant_id",
                knex.raw("concat(coalesce(participant_first_name,''),' ', coalesce(participant_last_name,'')) as participantname")
            )
            .where("participant_id", participantId)
            .first();

        const rows = await knex("milestones")
            .where("participant_id", participantId)
            .orderBy("milestone_date");

        const milestonetitles = rows.map(r => r.milestone_title).join("; ");
        const milestonedates = rows.map(r => r.milestone_date ? r.milestone_date.toISOString().slice(0,10) : "").join("; ");

        res.render("editMilestones", {
            error_message: "",
            milestone: {
                milestoneid: id,
                participantname: participant ? participant.participantname : "",
                milestonetitles,
                milestonedates,
                participant_id: participantId
            }
        });
    } catch (err) {
        console.error("Error loading milestone:", err);
        res.redirect("/milestones");
    }
});

// Edit Milestones - submit (rewrite milestones for participant)
app.post("/milestones/edit/:id", requireManager, async (req, res) => {
    const id = req.params.id;
    const { milestonetitles, milestonedates } = req.body;
    try {
        const target = await knex("milestones").where("milestone_id", id).first();
        if (!target) return res.redirect("/milestones");
        const participantId = target.participant_id;

        const titles = (milestonetitles || "").split(";").map(s => s.trim()).filter(Boolean);
        const dates = (milestonedates || "").split(";").map(s => s.trim()).filter(Boolean);
        if (titles.length !== dates.length) {
            throw new Error("Titles/dates length mismatch");
        }

        await knex("milestones").where("participant_id", participantId).del();

        const rows = titles.map((t, idx) => ({
            participant_id: participantId,
            milestone_title: t,
            milestone_date: dates[idx] || null
        }));
        if (rows.length > 0) {
            await knex("milestones").insert(rows);
        }
        res.redirect("/milestones");
    } catch (err) {
        console.error("Error updating milestones:", err);
        res.redirect("/milestones");
    }
});

// Delete Milestones (all for participant of given milestone id)
app.post("/milestones/delete/:id", requireManager, async (req, res) => {
    const id = req.params.id;
    try {
        const target = await knex("milestones").where("milestone_id", id).first();
        if (target) {
            await knex("milestones").where("participant_id", target.participant_id).del();
        }
        res.redirect("/milestones");
    } catch (err) {
        console.error("Error deleting milestones:", err);
        res.redirect("/milestones");
    }
});
// Add Participant - form
app.get("/addParticipants", requireManager, (req, res) => {
    res.render("addParticipants", { error_message: "", participant: {} });
});

// Add Participant - submit
app.post("/addParticipants", requireManager, async (req, res) => {
    const {
        participant_email,
        password,
        participant_first_name,
        participant_last_name,
        participant_dob,
        participant_phone,
        participant_city,
        participant_state,
        participant_zip,
        participant_school_or_employer,
        participant_field_of_interest,
        participant_role
    } = req.body;

    try {
        const phoneResult = normalizePhoneNumber(participant_phone, { required: !!participant_phone });
        if (phoneResult.error) {
            return res.render("addParticipants", { error_message: phoneResult.error, participant: req.body });
        }
        const hashed = await bcrypt.hash(password, 10);
        await knex("participants").insert({
            participant_email,
            password: hashed,
            participant_first_name,
            participant_last_name,
            participant_dob,
            participant_role: participant_role || "user",
            participant_phone: phoneResult.value,
            participant_city,
            participant_state,
            participant_zip,
            participant_school_or_employer,
            participant_field_of_interest
        });
        res.redirect("/participants");
    } catch (err) {
        console.error("Error adding participant:", err);
        res.render("addParticipants", { error_message: "Failed to add participant", participant: req.body });
    }
});

// Edit Participant - form
app.get("/editParticipants/:id", requireManager, async (req, res) => {
    const id = req.params.id;
    try {
        const participant = await knex("participants")
            .where("participant_id", id)
            .first();
        if (!participant) {
            return res.redirect("/participants");
        }
        res.render("editParticipants", { error_message: "", participant });
    } catch (err) {
        console.error("Error loading participant:", err);
        res.redirect("/participants");
    }
});

// Edit Participant - submit
app.post("/editParticipants/:id", requireManager, async (req, res) => {
    const id = req.params.id;
    const {
        participant_email,
        password,
        participant_first_name,
        participant_last_name,
        participant_dob,
        participant_phone,
        participant_city,
        participant_state,
        participant_zip,
        participant_school_or_employer,
        participant_field_of_interest,
        participant_role
    } = req.body;

    try {
        const phoneResult = normalizePhoneNumber(participant_phone, { required: !!participant_phone });
        if (phoneResult.error) {
            return res.render("editParticipants", { error_message: phoneResult.error, participant: { ...req.body, participant_id: id } });
        }
        let newPw = null;
        if (password && password.trim() !== "") {
            newPw = await bcrypt.hash(password, 10);
        }
        await knex("participants")
            .where("participant_id", id)
            .update({
                participant_email,
                password: newPw || undefined,
                participant_first_name,
                participant_last_name,
                participant_dob,
                participant_role: participant_role || "user",
                participant_phone: phoneResult.value,
                participant_city,
                participant_state,
                participant_zip,
                participant_school_or_employer,
                participant_field_of_interest
            });
        res.redirect("/participants");
    } catch (err) {
        console.error("Error updating participant:", err);
        res.render("editParticipants", { error_message: "Failed to update participant", participant: { ...req.body, participant_id: id } });
    }
});

// Delete Participant
app.post("/deleteParticipants/:id", requireManager, async (req, res) => {
    const id = req.params.id;
    try {
        await knex("participants")
            .where("participant_id", id)
            .del();
        res.redirect("/participants");
    } catch (err) {
        console.error("Error deleting participant:", err);
        res.redirect("/participants");
    }
});

// Error route - teapot
app.get("/teapot", (req, res) => {
    res.status(418);
    console.log(res.statusCode);

    res.send(`
        <html>
            <head>
                <title>418 I'm a teapot!</title>
            </head>
            <body style="text-align:center; font-family:sans-serif;">
                <h1>🫖 I'm a teapot!</h1>
                <p>This page returns a 418 status code.</p>
                <iframe width="560" height="315" 
                    src="https://www.youtube.com/embed/xvFZjo5PgG0?autoplay=1&mute=1&si=RJBpqvHuqyTb4Avw" 
                    title="YouTube video player" 
                    frameborder="0" 
                    allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" 
                    referrerpolicy="strict-origin-when-cross-origin" 
                    allow="autoplay; fullscreen" 
                    allowfullscreen>
                </iframe>
            </body>
        </html>
    `);
});

app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
});
