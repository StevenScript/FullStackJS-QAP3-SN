const express = require("express");
const path = require("path");
const session = require("express-session");
const bcrypt = require("bcrypt");

// Initialize Express app
const app = express();
const PORT = 3000;
const SALT_ROUNDS = 10;
const {
  isAuthenticated,
  isNotAuthenticated,
  isAdmin,
} = require("./middleware/auth");

// Configure app
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));
app.use(
  session({
    secret: process.env.SESSION_SECRET || "default_secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true, // Prevents client-side JavaScript from accessing the cookies!
      secure: false, // Set to true if using HTTPS
      maxAge: 3600000, // Session expires after 1 hour (in milliseconds)
    },
  })
);

// Sets view engine
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// in-memory user storage
const USERS = [
  {
    id: 1,
    username: "AdminUser",
    email: "admin@example.com",
    password: bcrypt.hashSync("admin123", SALT_ROUNDS), //In a database, you'd just store the hashes, but for
    // our purposes we'll hash these existing users when the
    // app loads
    role: "admin",
  },
  {
    id: 2,
    username: "RegularUser",
    email: "user@example.com",
    password: bcrypt.hashSync("user123", SALT_ROUNDS),
    role: "user", // Regular user
  },
];

// Middleware Functions

function isAuthenticated(request, response, next) {
  if (request.session && request.session.user) {
    next();
  } else {
    response.redirect("/login");
  }
}

function isNotAuthenticated(request, response, next) {
  if (request.session && request.session.user) {
    response.redirect("/landing");
  } else {
    next();
  }
}

function isAdmin(request, response, next) {
  if (
    request.session &&
    request.session.user &&
    request.session.user.role === "admin"
  ) {
    next();
  } else {
    response.status(403).send("Access denied.");
  }
}

// Route Handlers

// GET / - Render index page or redirect to landing if logged in
app.get("/", (request, response) => {
  if (request.session.user) {
    return response.redirect("/landing");
  }
  response.render("index");
});

// GET /signup - Render signup form
app.get("/signup", isNotAuthenticated, (request, response) => {
  response.render("signup");
});

// POST /signup - Allows a user to signup
app.post("/signup", async (request, response) => {
  const { username, email, password } = request.body;

  // Input validation
  if (!username || !email || !password) {
    return response.render("signup", {
      error: "All fields are required.",
      username,
      email,
    });
  }

  const emailRegex = /\S+@\S+\.\S+/;
  if (!emailRegex.test(email)) {
    return response.render("signup", {
      error: "Invalid email format.",
      username,
      email,
    });
  }

  if (password.length < 6) {
    return response.render("signup", {
      error: "Password must be at least 6 characters long.",
      username,
      email,
    });
  }

  // Check if email is already registered
  const userExists = USERS.some((user) => user.email === email);
  if (userExists) {
    return response.render("signup", { error: "Email is already registered." });
  }

  try {
    // Hash the password
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    // Determine user role
    const role = USERS.length === 0 ? "admin" : "user";

    // Create new user object
    const newUser = {
      id: USERS.length + 1,
      username,
      email,
      password: hashedPassword,
      role,
    };

    // Add new user to USERS array
    USERS.push(newUser);

    // Redirect to login page
    response.redirect("/login");
  } catch (error) {
    console.error(error);
    response.render("signup", {
      error: "An error occurred. Please try again.",
    });
  }
});

// GET /login - Render login form
app.get("/login", isNotAuthenticated, (request, response) => {
  response.render("login");
});

// POST /login - Allows a user to login
app.post("/login", async (request, response) => {
  const { email, password } = request.body;

  if (!email || !password) {
    return response.render("login", {
      error: "Email and password are required.",
      email,
    });
  }

  // Validate input fields
  if (!email || !password) {
    return response.render("login", {
      error: "Email and password are required.",
    });
  }

  // Find the user by email
  const user = USERS.find((user) => user.email === email);

  if (!user) {
    // User not found
    return response.render("login", { error: "Invalid email or password." });
  }

  try {
    // Compare the provided password with the stored hashed password
    const match = await bcrypt.compare(password, user.password);

    if (match) {
      // Passwords match - authentication successful

      // Initiate user session
      request.session.user = {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
      };

      // Redirect to landing page
      return response.redirect("/landing");
    } else {
      // Passwords do not match
      return response.render("login", { error: "Invalid email or password." });
    }
  } catch (error) {
    // Handle errors during authentication
    console.error("Error during user login:", error);
    return response.render("login", {
      error: "An error occurred. Please try again.",
    });
  }
});

// GET /landing - Shows a welcome page for users, shows the names of all users if an admin
app.get("/landing", isAuthenticated, (request, response) => {
  const user = request.session.user;

  if (user.role === "admin") {
    // Admin view
    response.render("adminLanding", { user, users: USERS });
  } else {
    // Regular user view
    response.render("userLanding", { user });
  }
});

// GET /logout - Destroy the user session and redirect to home page
app.get("/logout", (request, response) => {
  request.session.destroy((err) => {
    if (err) {
      return response.redirect("/landing");
    }
    response.clearCookie("connect.sid");
    response.redirect("/");
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
