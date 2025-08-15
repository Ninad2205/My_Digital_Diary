// app.js
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const path = require("path");
const bcrypt = require("bcrypt");
const crypto = require("crypto"); // for shareable link IDs
require("./config/mongooseconnection");

const User = require("./models/user");
const DiaryEntry = require("./models/DiaryEntry");

const app = express();

// View engine
app.set("view engine", "ejs");
app.use(express.static(path.join(__dirname, "public")));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// session setup
app.use(session({
    secret: "supersecretkey",
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: "mongodb://127.0.0.1:27017/DiaryApp",
        collectionName: "sessions"
    }),
    cookie: {
        maxAge: 1000 * 60 * 60 * 24,
        httpOnly: true,
        secure: false 
    }
}));

// Middleware to check authentication
function requireLogin(req, res, next) {
    if (!req.session.userId) {
        return res.redirect("/login");
    }
    next();
}

// Home route 
app.get("/", (req, res) => {
    if (req.session.userId) {
        return res.redirect("/index");
    }
    res.redirect("/login");
});

// Login page
app.get("/login", (req, res) => {
    res.render("login", { error: null, success: null, email: "" });
});

// Login handler
app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.render("login", { error: "User not found", success: null, email });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.render("login", { error: "Wrong password", success: null, email });
        }

        req.session.userId = user._id;
        res.redirect("/index");
    } catch (err) {
        console.error(err);
        res.render("login", { error: "Server error", success: null, email });
    }
});

// Signup page
app.get("/signup", (req, res) => {
    res.render("signup", { error: null, email: "" });
});

// Signup handler
app.post("/signup", async (req, res) => {
    const { email, password, confirmPassword } = req.body;

    try {
        if (password !== confirmPassword) {
            return res.render("signup", { error: "Passwords do not match", email });
        }

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.render("signup", { error: "User already exists", email });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ email, password: hashedPassword });
        await newUser.save();

        res.render("login", { success: "User created successfully, please login", error: null, email });
    } catch (err) {
        console.error(err);
        res.render("signup", { error: "Server error", email });
    }
});

// Dashboard — show entries
app.get("/index", requireLogin, async (req, res) => {
    try {
        const entries = await DiaryEntry.find({ user: req.session.userId }).sort({ createdAt: -1 });
        res.render("index", { entries });
    } catch (err) {
        console.error(err);
        res.status(500).send("Server error");
    }
});

// Add a new diary entry form
app.get("/entries/new", requireLogin, async (req, res) => {
    try {
        const entries = await DiaryEntry.find({ user: req.session.userId })
            .sort({ createdAt: -1 });
        res.render("entries", { entries });
    } catch (err) {
        console.error(err);
        res.status(500).send("Server error");
    }
});

// Create a new diary entry
app.post("/entries", requireLogin, async (req, res) => {
    try {
        const { title, content } = req.body;
        const newEntry = new DiaryEntry({
            title,
            content,
            user: req.session.userId
        });
        await newEntry.save();
        res.redirect("/index");
    } catch (err) {
        console.error(err);
        res.status(500).send("Server error");
    }
});

// View a specific diary entry
app.get("/entries/:id", requireLogin, async (req, res) => {
    try {
        const entry = await DiaryEntry.findById(req.params.id);
        if (!entry) return res.status(404).send("Entry not found");
        res.render("viewEntry", { entry });
    } catch (err) {
        console.error(err);
        res.status(500).send("Server error");
    }
});

// Delete a diary entry
app.post("/entries/:id/delete", requireLogin, async (req, res) => {
    try {
        const entry = await DiaryEntry.findOneAndDelete({
            _id: req.params.id,
            user: req.session.userId
        });

        if (!entry) {
            return res.status(404).send("Entry not found or not authorized");
        }

        res.redirect("/index"); 
    } catch (err) {
        console.error(err);
        res.status(500).send("Server error");
    }
});

// Edit route
app.get("/entries/:id/edit", requireLogin, async (req, res) => {
    try {
        const entry = await DiaryEntry.findOne({
            _id: req.params.id,
            user: req.session.userId
        });

        if (!entry) {
            return res.status(404).send("Entry not found or not authorized");
        }

        res.render("edit", { entry });
    } catch (err) {
        console.error(err);
        res.status(500).send("Server error");
    }
});
app.post("/entries/:id/edit", requireLogin, async (req, res) => {
    try {
        const { title, content } = req.body;
        const entry = await DiaryEntry.findOneAndUpdate(
            { _id: req.params.id, user: req.session.userId },
            { title, content },
            { new: true }
        );

        if (!entry) {
            return res.status(404).send("Entry not found or not authorized");
        }

        res.redirect("/index");
    } catch (err) {
        console.error(err);
        res.status(500).send("Server error");
    }
});

//Public/Private Toggle & Sharing

// Make entry public
app.post("/entries/:id/set-public", requireLogin, async (req, res) => {
    try {
        const entry = await DiaryEntry.findOne({ _id: req.params.id, user: req.session.userId });
        if (!entry) return res.status(404).send("Not found");

        entry.isPublic = true;
        entry.shareId = crypto.randomBytes(8).toString("hex");
        await entry.save();
        res.redirect("/index");
    } catch (err) {
        console.error(err);
        res.status(500).send("Server error");
    }
});

// Make entry private again
app.post("/entries/:id/set-private", requireLogin, async (req, res) => {
    try {
        const entry = await DiaryEntry.findOne({ _id: req.params.id, user: req.session.userId });
        if (!entry) return res.status(404).send("Not found");

        entry.isPublic = false;
        entry.shareId = undefined;
        await entry.save();
        res.redirect("/index");
    } catch (err) {
        console.error(err);
        res.status(500).send("Server error");
    }
});

// Public view
app.get("/share/:shareId", async (req, res) => {
    try {
        const entry = await DiaryEntry.findOne({ shareId: req.params.shareId, isPublic: true });
        if (!entry) return res.status(404).send("Not found or private");
        res.render("public-entry", { entry });
    } catch (err) {
        console.error(err);
        res.status(500).send("Server error");
    }
});

/* ================================================ */

// Logout
app.get("/logout", (req, res) => {
    req.session.destroy(() => {
        res.redirect("/");
    });
});

app.listen(3000, () => console.log("Server running on http://localhost:3000"));
