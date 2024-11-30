const express = require("express");
const path = require("path");
const session = require("express-session");
const bcrypt = require("bcrypt");

const app = express();
const PORT = 3000;
const SALT_ROUNDS = 10;

app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));
app.use(
  session({
    secret: "replace_this_with_a_secure_key",
    resave: false,
    saveUninitialized: true,
  })
);

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

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

// GET /login - Render login form
app.get("/login", (request, response) => {
  response.render("login");
});

// POST /login - Allows a user to login
app.post("/login", async (request, response) => {
  const { email, password } = request.body;

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

// GET /signup - Render signup form
app.get("/signup", (request, response) => {
  response.render("signup");
});

// POST /signup - Allows a user to signup
// added async to facilitate usage of "await"
app.post("/signup", async (request, response) => {
  const { username, email, password } = request.body;

  // Validate input
  if (!username || !email || !password) {
    return response.render("signup", { error: "All fields are required." });
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
      password: hashedPassword, // Store the hashed password
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

// GET / - Render index page or redirect to landing if logged in
app.get("/", (request, response) => {
  if (request.session.user) {
    return response.redirect("/landing");
  }
  response.render("index");
});

// GET /landing - Shows a welcome page for users, shows the names of all users if an admin
app.get("/landing", (request, response) => {});

// Start server
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
