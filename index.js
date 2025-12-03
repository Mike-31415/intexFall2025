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
        "font-src 'self' https://fonts.gstatic.com;"
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
// alias for older references
const requireManager = requireAdmin;

// Global authentication middleware
app.use((req, res, next) => {
    console.log("Auth middleware: checking path:", req.path);
    if (
        req.path === '/' ||
        req.path === '/login' ||
        req.path === '/logout' ||
        req.path === '/register' ||
        (req.method === 'GET' && req.path === '/donations') // public donations page
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

// Register (simple version, no hashing yet)
app.get("/register", (req, res) => {
    if (req.session.isLoggedIn) {
        return res.redirect("/");
    }
    res.render("register", { error_message: "" });
});

app.post("/register", async (req, res) => {
    const { username, password } = req.body;
    try {
        // Basic split of name into first/last (best-effort)
        const [first, ...rest] = (username || "").split(" ");
        const last = rest.join(" ");
        const hashed = await bcrypt.hash(password, 10);
        // Insert participant as the auth user record
        const [created] = await knex("participants")
            .insert({
                participant_email: username,
                participant_first_name: first || username,
                participant_last_name: last || "",
                password: hashed,
                participant_role: "participant"
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

app.get("/logout", (req, res) => {
    req.session.destroy(() => {
        res.redirect("/login");
    });
});

app.post("/login", (req, res) => {
    let sEmail = req.body.email;
    let sPassword = req.body.password;
    console.log('Post Login')
    knex("participants")
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
            res.redirect("/");
        })
        .catch(err => {
            console.error("Login error:", err);
            res.render("login", { error_message: "Invalid login"});
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

    knex("event_templates")
        .select(
            "event_template_id as eventid",
            "event_name as eventname",
            "event_type as eventtype",
            "event_description as eventdescription",
            "event_default_capacity as eventdefaultcapacity",
            "event_recurrence_pattern as eventrecurrencepattern"
        )
        .orderBy("event_template_id", "asc")
        .then(events => {
            res.render("events", {
                username: req.session.username,
                role: req.session.role,
                events
            });
        })
        .catch(err => {
            console.error("Error loading events:", err);
            res.render("events", {
                username: req.session.username,
                role: req.session.role,
                events: [],
                error_message: "Error loading events"
            });
        });
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

app.get("/postsurveys", (req, res) => {
    if (!req.session.isLoggedIn) {
        return res.redirect("/login");
    }

    const isManager = (req.session.role || "").toLowerCase() === "admin";

    knex("surveys as s")
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
        .orderBy("s.survey_id", "desc")
        .then(surveys => {
            res.render("postsurveys", {
                username: req.session.username,
                role: req.session.role,
                isManager,
                surveys
            });
        })
        .catch(err => {
            console.error("Error loading surveys:", err);
            res.render("postsurveys", {
                username: req.session.username,
                role: req.session.role,
                isManager,
                surveys: [],
                error_message: "Error loading surveys"
            });
        });
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

// DONATIONS PAGE
app.get("/donations", async (req, res) => {
    try {
        const donations = await knex("donations as d")
            .join("participants as p", "d.participant_id", "p.participant_id")
            .select(
                "d.donation_id as id",
                "d.donation_date",
                "d.donation_amount",
                "p.participant_first_name as first_name",
                "p.participant_last_name as last_name"
            )
            .orderBy("d.donation_date", "desc");

        res.render("donations", {
            donations,
            role: req.session.role,
            error_message: null
        });

    } catch (err) {
        console.error(err);
        res.render("donations", {
            donations: [],
            role: req.session.role,
            error_message: "Error loading donations"
        });
    }
});

// Add Donation - form
app.get("/addDonations", requireManager, async (req, res) => {
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
app.post("/addDonations", requireManager, async (req, res) => {
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

// USERS PAGE WITH SEARCH
app.get("/users", requireManager, async (req, res) => {
    try {
        const search = req.query.search || "";

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
                this.whereILike("p.participant_first_name", s)
                    .orWhereILike("p.participant_last_name", s)
                    .orWhereILike("p.participant_email", s)
                    .orWhereILike("p.participant_role", s);
            });
        }

        query.orderBy("p.participant_last_name", "asc");

        const users = await query;

        res.render("users", {
            users,
            role: req.session.role,
            error_message: null,
            search
        });

    } catch (err) {
        console.error("Error loading users:", err);

        res.render("users", {
            users: [],
            role: req.session.role,
            error_message: "Error loading users",
            search: ""
        });
    }
});

// PARTICIPANTS PAGE WITH SEARCH
app.get("/participants", async (req, res) => {
    try {
        const search = req.query.search || "";

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
                this.whereILike("p.participant_first_name", s)
                    .orWhereILike("p.participant_last_name", s)
                    .orWhereILike("p.participant_email", s)
                    .orWhereILike("p.participant_city", s)
                    .orWhereILike("p.participant_state", s)
                    .orWhereILike("p.participant_school_or_employer", s)
                    .orWhereRaw("CAST(p.participant_dob AS TEXT) ILIKE ?", [s]);
            });
        }

        // Sort by last name
        query.orderBy("p.participant_last_name", "asc");

        const participants = await query;

        // Render page with results
        res.render("participants", {
            participants,
            role: req.session.role,
            error_message: null,
            search // pass search query back to input field
        });

    } catch (err) {
        console.error("Error loading participants:", err);
        res.render("participants", {
            participants: [],
            role: req.session.role,
            error_message: "Error loading participants",
            search: ""
        });
    }
});

// MILESTONES PAGE
app.get("/milestones", async (req, res) => {
    if (!req.session.isLoggedIn) {
        return res.redirect("/login");
    }
    const isManager = (req.session.role || "").toLowerCase() === "admin";
    try {
        const milestones = await knex("milestones as m")
            .leftJoin("participants as p", "m.participant_id", "p.participant_id")
            .select(
                "m.participant_id",
                knex.raw("min(m.milestone_id) as milestoneid"),
                knex.raw("concat(coalesce(p.participant_first_name,''),' ', coalesce(p.participant_last_name,'')) as participantname"),
                knex.raw("string_agg(m.milestone_title, '; ' order by m.milestone_date) as milestonetitles"),
                knex.raw("string_agg(to_char(m.milestone_date, 'YYYY-MM-DD'), '; ' order by m.milestone_date) as milestonedates")
            )
            .groupBy("m.participant_id", "p.participant_first_name", "p.participant_last_name");

        res.render("milestones", {
            milestones,
            isManager
        });
    } catch (err) {
        console.error("Error loading milestones:", err);
        res.render("milestones", {
            milestones: [],
            isManager,
            error_message: "Error loading milestones"
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
        const hashed = await bcrypt.hash(password, 10);
        await knex("participants").insert({
            participant_email,
            password: hashed,
            participant_first_name,
            participant_last_name,
            participant_dob,
            participant_role: participant_role || "user",
            participant_phone,
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
                participant_phone,
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


app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
});
