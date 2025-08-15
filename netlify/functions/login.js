require("dotenv").config();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
    username: String,
    email: String,
    passwordHash: String,
    avatar: String,
});

// Check if model already exists
const User = mongoose.models.User || mongoose.model("User", userSchema);


exports.handler = async (event) => {
    if (event.httpMethod !== "POST") {
        return { statusCode: 405, body: JSON.stringify({ error: "Method not allowed" }) };
    }

    try {
        const { email, password } = JSON.parse(event.body);

        if (!email || !password) {
            return { statusCode: 400, body: JSON.stringify({ error: "Email and password are required" }) };
        }

        const user = await User.findOne({ email: email.toLowerCase().trim() });
        if (!user) {
            return { statusCode: 401, body: JSON.stringify({ error: "Invalid credentials" }) };
        }

        const isValid = await bcrypt.compare(password, user.passwordHash);
        if (!isValid) {
            return { statusCode: 401, body: JSON.stringify({ error: "Invalid credentials" }) };
        }

        const token = jwt.sign(
            { username: user.username, avatar: user.avatar },
            process.env.JWT_SECRET
        );

        return {
            statusCode: 200,
            body: JSON.stringify({ message: "Login successful", token }),
        };
    } catch (err) {
        console.error("Login error:", err);
        return { statusCode: 500, body: JSON.stringify({ error: "Login failed" }) };
    }
};
