// app.js
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const path = require("path");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
require("dotenv").config();
require("./config/mongooseconnection");

const User = require("./models/user");
const DiaryEntry = require("./models/DiaryEntry");

const app = express();

// View engine
app.set("view engine", "ejs");
app.use(express.static(path.join(__dirname, "public")));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

//----------------------------------------------------------------
// Error Classes
//----------------------------------------------------------------
class AppError extends Error {
  constructor(message, statusCode) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = true;
    Error.captureStackTrace(this, this.constructor);
  }
}

class ValidationError extends AppError {
  constructor(message) {
    super(message, 400);
  }
}

class AuthenticationError extends AppError {
  constructor(message = "Authentication failed") {
    super(message, 401);
  }
}

class NotFoundError extends AppError {
  constructor(message = "Resource not found") {
    super(message, 404);
  }
}

//----------------------------------------------------------------
// Encryption functionality with enhanced error handling
//----------------------------------------------------------------
const ENCRYPTION_KEY = (() => {
  try {
    return crypto
      .createHash("sha256")
      .update(String("supersecretkey"))
      .digest("base64")
      .substr(0, 32);
  } catch (error) {
    console.error("Failed to generate encryption key:", error);
    process.exit(1);
  }
})();
const IV_LENGTH = 16;

function encrypt(text) {
  try {
    if (!text || typeof text !== "string") {
      throw new Error("Invalid input for encryption");
    }

    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(
      "aes-256-cbc",
      Buffer.from(ENCRYPTION_KEY),
      iv
    );
    let encrypted = cipher.update(text, "utf8", "hex");
    encrypted += cipher.final("hex");
    return iv.toString("hex") + ":" + encrypted;
  } catch (error) {
    console.error("Encryption failed:", error);
    throw new Error("Failed to encrypt content");
  }
}

function decrypt(text) {
  try {
    if (!text || typeof text !== "string" || !text.includes(":")) {
      throw new Error("Invalid encrypted text format");
    }

    const textParts = text.split(":");
    if (textParts.length !== 2) {
      throw new Error("Invalid encrypted text structure");
    }

    const iv = Buffer.from(textParts[0], "hex");
    const encryptedText = textParts[1];

    if (iv.length !== IV_LENGTH) {
      throw new Error("Invalid IV length");
    }

    const decipher = crypto.createDecipheriv(
      "aes-256-cbc",
      Buffer.from(ENCRYPTION_KEY),
      iv
    );
    let decrypted = decipher.update(encryptedText, "hex", "utf8");
    decrypted += decipher.final("utf8");
    return decrypted;
  } catch (error) {
    console.error("Decryption failed:", error);
    throw new Error("Failed to decrypt content");
  }
}

//----------------------------------------------------------------
// Session setup with error handling
//----------------------------------------------------------------
app.use(
  session({
    secret: "supersecretkey",
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: process.env.MongoURI,//mongodb://127.0.0.1:27017/DiaryApp
      collectionName: "sessions",
    }),
    cookie: {
      maxAge: 1000 * 60 * 60 * 24,
      httpOnly: true,
      secure: false,
    },
  })
);

//----------------------------------------------------------------
// Utility functions
//----------------------------------------------------------------
function validateEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

function validatePassword(password) {
  return password && password.length >= 6;
}

function sanitizeInput(input) {
  if (typeof input !== "string") return "";
  return input.trim();
}

//----------------------------------------------------------------
// Middleware
//----------------------------------------------------------------
function requireLogin(req, res, next) {
  try {
    if (!req.session.userId) {
      return res.redirect("/login");
    }
    next();
  } catch (error) {
    console.error("Authentication middleware error:", error);
    res.redirect("/login");
  }
}

// Error handling middleware
function handleError(error, req, res, next) {
  console.error("Error details:", {
    message: error.message,
    stack: error.stack,
    url: req.url,
    method: req.method,
    timestamp: new Date().toISOString(),
  });

  // If response already sent, delegate to Express default error handler
  if (res.headersSent) {
    return next(error);
  }

  const statusCode = error.statusCode || 500;
  const message = error.isOperational ? error.message : "Internal Server Error";

  // For API requests, send JSON
  if (req.accepts("json") && !req.accepts("html")) {
    return res.status(statusCode).json({
      error: true,
      message: message,
      ...(process.env.NODE_ENV === "development" && { stack: error.stack }),
    });
  }

  // For web requests, render error page or redirect appropriately
  if (statusCode === 404) {
    return res.status(404).render("error", {
      error: "Page not found",
      statusCode: 404,
    });
  }

  if (statusCode === 401) {
    return res.redirect("/login");
  }

  res.status(statusCode).render("error", {
    error: message,
    statusCode: statusCode,
  });
}

//----------------------------------------------------------------
// Routes
//----------------------------------------------------------------

// Home route
app.get("/", (req, res, next) => {
  try {
    if (req.session.userId) {
      return res.redirect("/index");
    }
    res.render("home", { error: null, success: null });
  } catch (error) {
    next(error);
  }
});

// Login page
app.get("/login", (req, res, next) => {
  try {
    res.render("login", { error: null, success: null, email: "" });
  } catch (error) {
    next(error);
  }
});
app.get("/about", (req, res, next) => {
  try {   
    res.render("about", { error: null });
  } catch (error) {
    next(error);  
  }
});

// Login handler
app.post("/login", async (req, res, next) => {
  try {
    const { email, password } = req.body;

    // Input validation
    if (!email || !password) {
      return res.render("login", {
        error: "Email and password are required",
        success: null,
        email: sanitizeInput(email),
      });
    }

    const sanitizedEmail = sanitizeInput(email).toLowerCase();

    if (!validateEmail(sanitizedEmail)) {
      return res.render("login", {
        error: "Invalid email format",
        success: null,
        email: sanitizedEmail,
      });
    }

    const user = await User.findOne({ email: sanitizedEmail });
    if (!user) {
      return res.render("login", {
        error: "Invalid email or password",
        success: null,
        email: sanitizedEmail,
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.render("login", {
        error: "Invalid email or password",
        success: null,
        email: sanitizedEmail,
      });
    }

    req.session.userId = user._id;
    res.redirect("/index");
  } catch (error) {
    console.error("Login error:", error);
    res.render("login", {
      error: "Server error. Please try again.",
      success: null,
      email: sanitizeInput(req.body.email || ""),
    });
  }
});

// Signup page
app.get("/signup", (req, res, next) => {
  try {
    res.render("login", { error: null, email: "" });
  } catch (error) {
    next(error);
  }
});

// Signup handler
app.post("/signup", async (req, res, next) => {
  try {
    const { email, password, confirmPassword } = req.body;

    // Input validation
    if (!email || !password || !confirmPassword) {
      return res.render("login", {
        error: "All fields are required",
        email: sanitizeInput(email),
      });
    }

    const sanitizedEmail = sanitizeInput(email).toLowerCase();

    if (!validateEmail(sanitizedEmail)) {
      return res.render("login", {
        error: "Invalid email format",
        email: sanitizedEmail,
      });
    }

    if (!validatePassword(password)) {
      return res.render("login", {
        error: "Password must be at least 6 characters long",
        email: sanitizedEmail,
      });
    }

    if (password !== confirmPassword) {
      return res.render("login", {
        error: "Passwords do not match",
        email: sanitizedEmail,
      });
    }

    const existingUser = await User.findOne({ email: sanitizedEmail });
    if (existingUser) {
      return res.render("login", {
        error: "User already exists",
        email: sanitizedEmail,
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({
      email: sanitizedEmail,
      password: hashedPassword,
    });
    await newUser.save();

    res.render("login", {
      success: "Account created successfully! Please login.",
      error: null,
      email: sanitizedEmail,
    });
  } catch (error) {
    console.error("Signup error:", error);
    res.render("login", {
      error: "Server error. Please try again.",
      email: sanitizeInput(req.body.email || ""),
    });
  }
});

// Dashboard — show entries
app.get("/index", requireLogin, async (req, res, next) => {
  try {
    let entries = await DiaryEntry.find({ user: req.session.userId }).sort({
      createdAt: -1,
    });

    // Decrypt content for display with error handling
    entries = entries.map((entry) => {
      try {
        return {
          ...entry._doc,
          content: decrypt(entry.content),
        };
      } catch (decryptError) {
        console.error(`Failed to decrypt entry ${entry._id}:`, decryptError);
        return {
          ...entry._doc,
          content: "[Content could not be decrypted]",
        };
      }
    });

    res.render("index", { entries });
  } catch (error) {
    next(error);
  }
});

// Add a new diary entry form
app.get("/entries/new", requireLogin, async (req, res, next) => {
  try {
    const entries = await DiaryEntry.find({ user: req.session.userId }).sort({
      createdAt: -1,
    });
    res.render("entries", { entries });
  } catch (error) {
    next(error);
  }
});

// Create a new diary entry
app.post("/entries", requireLogin, async (req, res, next) => {
  try {
    const { title, content } = req.body;

    // Input validation
    if (!title || !content) {
      throw new ValidationError("Title and content are required");
    }

    const sanitizedTitle = sanitizeInput(title);
    const sanitizedContent = sanitizeInput(content);

    if (sanitizedTitle.length > 200) {
      throw new ValidationError("Title must be less than 200 characters");
    }

    if (sanitizedContent.length > 50000) {
      throw new ValidationError("Content must be less than 50,000 characters");
    }

    const encryptedContent = encrypt(sanitizedContent);
    const newEntry = new DiaryEntry({
      title: sanitizedTitle,
      content: encryptedContent,
      user: req.session.userId,
    });

    await newEntry.save();
    res.redirect("/index");
  } catch (error) {
    next(error);
  }
});

// View a specific diary entry content
app.get("/entries/:id", requireLogin, async (req, res, next) => {
  try {
    const entryId = req.params.id;

    // Validate ObjectId format
    if (!entryId.match(/^[0-9a-fA-F]{24}$/)) {
      throw new NotFoundError("Invalid entry ID");
    }

    const entry = await DiaryEntry.findOne({
      _id: entryId,
      user: req.session.userId,
    });

    if (!entry) {
      throw new NotFoundError("Entry not found or not authorized");
    }

    try {
      entry.content = decrypt(entry.content);
    } catch (decryptError) {
      console.error(`Failed to decrypt entry ${entry._id}:`, decryptError);
      entry.content = "[Content could not be decrypted]";
    }

    res.render("viewEntry", { entry });
  } catch (error) {
    next(error);
  }
});

// Delete a diary entry
app.post("/entries/:id/delete", requireLogin, async (req, res, next) => {
  try {
    const entryId = req.params.id;

    // Validate ObjectId format
    if (!entryId.match(/^[0-9a-fA-F]{24}$/)) {
      throw new NotFoundError("Invalid entry ID");
    }

    const entry = await DiaryEntry.findOneAndDelete({
      _id: entryId,
      user: req.session.userId,
    });

    if (!entry) {
      throw new NotFoundError("Entry not found or not authorized");
    }

    res.redirect("/index");
  } catch (error) {
    next(error);
  }
});

// Edit route - GET
app.get("/entries/:id/edit", requireLogin, async (req, res, next) => {
  try {
    const entryId = req.params.id;

    // Validate ObjectId format
    if (!entryId.match(/^[0-9a-fA-F]{24}$/)) {
      throw new NotFoundError("Invalid entry ID");
    }

    const entry = await DiaryEntry.findOne({
      _id: entryId,
      user: req.session.userId,
    });

    if (!entry) {
      throw new NotFoundError("Entry not found or not authorized");
    }

    // Decrypt content before showing in the edit form
    let decryptedContent;
    try {
      decryptedContent = decrypt(entry.content);
    } catch (decryptError) {
      console.error(
        `Failed to decrypt entry ${entry._id} for editing:`,
        decryptError
      );
      decryptedContent = "[Content could not be decrypted]";
    }

    res.render("edit", {
      entry: { ...entry._doc, content: decryptedContent },
    });
  } catch (error) {
    next(error);
  }
});

// Edit route - POST
app.post("/entries/:id/edit", requireLogin, async (req, res, next) => {
  try {
    const entryId = req.params.id;
    const { title, content } = req.body;

    // Validate ObjectId format
    if (!entryId.match(/^[0-9a-fA-F]{24}$/)) {
      throw new NotFoundError("Invalid entry ID");
    }

    // Input validation
    if (!title || !content) {
      throw new ValidationError("Title and content are required");
    }

    const sanitizedTitle = sanitizeInput(title);
    const sanitizedContent = sanitizeInput(content);

    if (sanitizedTitle.length > 200) {
      throw new ValidationError("Title must be less than 200 characters");
    }

    if (sanitizedContent.length > 50000) {
      throw new ValidationError("Content must be less than 50,000 characters");
    }

    const encryptedContent = encrypt(sanitizedContent);
    const entry = await DiaryEntry.findOneAndUpdate(
      { _id: entryId, user: req.session.userId },
      { title: sanitizedTitle, content: encryptedContent },
      { new: true }
    );

    if (!entry) {
      throw new NotFoundError("Entry not found or not authorized");
    }

    res.redirect("/index");
  } catch (error) {
    next(error);
  }
});

// Make entry public
app.post("/entries/:id/set-public", requireLogin, async (req, res, next) => {
  try {
    const entryId = req.params.id;

    // Validate ObjectId format
    if (!entryId.match(/^[0-9a-fA-F]{24}$/)) {
      throw new NotFoundError("Invalid entry ID");
    }

    const entry = await DiaryEntry.findOne({
      _id: entryId,
      user: req.session.userId,
    });

    if (!entry) {
      throw new NotFoundError("Entry not found or not authorized");
    }

    entry.isPublic = true;
    entry.shareId = crypto.randomBytes(8).toString("hex");
    await entry.save();
    res.redirect("/index");
  } catch (error) {
    next(error);
  }
});

// Make entry private again
app.post("/entries/:id/set-private", requireLogin, async (req, res, next) => {
  try {
    const entryId = req.params.id;

    // Validate ObjectId format
    if (!entryId.match(/^[0-9a-fA-F]{24}$/)) {
      throw new NotFoundError("Invalid entry ID");
    }

    const entry = await DiaryEntry.findOne({
      _id: entryId,
      user: req.session.userId,
    });

    if (!entry) {
      throw new NotFoundError("Entry not found or not authorized");
    }

    entry.isPublic = false;
    entry.shareId = undefined;
    await entry.save();
    res.redirect("/index");
  } catch (error) {
    next(error);
  }
});

// Public view
app.get("/share/:shareId", async (req, res, next) => {
  try {
    const shareId = req.params.shareId;

    // Validate shareId format (should be hex string)
    if (!/^[a-fA-F0-9]+$/.test(shareId) || shareId.length !== 16) {
      throw new NotFoundError("Invalid share link");
    }

    const entry = await DiaryEntry.findOne({
      shareId: shareId,
      isPublic: true,
    });

    if (!entry) {
      throw new NotFoundError("Shared entry not found or no longer public");
    }

    // Decrypt content before showing
    let decryptedContent;
    try {
      decryptedContent = decrypt(entry.content);
    } catch (decryptError) {
      console.error(
        `Failed to decrypt public entry ${entry._id}:`,
        decryptError
      );
      decryptedContent = "[Content could not be decrypted]";
    }

    res.render("public-entry", {
      entry: { ...entry._doc, content: decryptedContent },
    });
  } catch (error) {
    next(error);
  }
});

// Logout
app.get("/logout", (req, res, next) => {
  try {
    req.session.destroy((err) => {
      if (err) {
        console.error("Session destruction error:", err);
        return next(err);
      }
      res.redirect("/");
    });
  } catch (error) {
    next(error);
  }
});

// Add debugging middleware to catch route registration issues
app.use((req, res, next) => {
  console.log(`${req.method} ${req.url}`);
  next();
});

// Error handling middleware - must be last
app.use(handleError);

// Graceful shutdown handling
process.on("SIGTERM", () => {
  console.log("SIGTERM received, shutting down gracefully");
  server.close(() => {
    console.log("Process terminated");
  });
});

process.on("unhandledRejection", (reason, promise) => {
  console.error("Unhandled Rejection at:", promise, "reason:", reason);
  // Close server & exit process
  process.exit(1);
});

process.on("uncaughtException", (error) => {
  console.error("Uncaught Exception:", error);
  process.exit(1);
});

const server = app.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});

module.exports = app;
