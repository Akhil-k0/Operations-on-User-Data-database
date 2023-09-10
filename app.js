const express = require("express");
const app = express();
const bodyParser = require("body-parser");
const sqlite3 = require("sqlite3");
const { open } = require("sqlite");
const path = require("path");
const bcrypt = require("bcrypt");

app.use(bodyParser.json());

const dbPath = path.join(__dirname, "userData.db");

let db = null;

const initializeDB = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    });
    console.log("Connected to database");
  } catch (e) {
    console.error(`DB Error: ${e.message}`);
  }
};

initializeDB();

// API 1: User Registration
app.post("/register", async (req, res) => {
  const { username, name, password, gender, location } = req.body;
  try {
    const existingUser = await db.get(
      `SELECT username FROM user WHERE username = ?`,
      [username]
    );

    if (existingUser) {
      return res.status(400).send("User already exists");
    }

    if (password.length < 5) {
      return res.status(400).send("Password is too short");
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await db.run(
      `INSERT INTO user (username, name, password, gender, location) VALUES (?, ?, ?, ?, ?)`,
      [username, name, hashedPassword, gender, location]
    );

    return res.status(200).send("User created successfully");
  } catch (error) {
    console.error(`Error registering user: ${error.message}`);
    return res.status(500).send("Internal Server Error");
  }
});

// API 2: User Login
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await db.get(
      `SELECT username, password FROM user WHERE username = ?`,
      [username]
    );

    if (!user) {
      return res.status(400).send("Invalid user");
    }

    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(400).send("Invalid password");
    }

    return res.status(200).send("Login success!");
  } catch (error) {
    console.error(`Error logging in: ${error.message}`);
    return res.status(500).send("Internal Server Error");
  }
});

// API 3: Change Password
app.put("/change-password", async (req, res) => {
  const { username, oldPassword, newPassword } = req.body;
  try {
    const user = await db.get(
      `SELECT username, password FROM user WHERE username = ?`,
      [username]
    );

    if (!user) {
      return res.status(400).send("Invalid user");
    }

    const passwordMatch = await bcrypt.compare(oldPassword, user.password);

    if (!passwordMatch) {
      return res.status(400).send("Invalid current password");
    }

    if (newPassword.length < 5) {
      return res.status(400).send("Password is too short");
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await db.run(`UPDATE user SET password = ? WHERE username = ?`, [
      hashedPassword,
      username,
    ]);

    return res.status(200).send("Password updated");
  } catch (error) {
    console.error(`Error changing password: ${error.message}`);
    return res.status(500).send("Internal Server Error");
  }
});

module.exports = app;
