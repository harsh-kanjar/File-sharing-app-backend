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

// --- Helper: generate unique username from email ---
async function generateUniqueUsername(email) {
    const local = (email.split("@")[0] || "user").replace(/[^\w.-]/g, "");
    let candidate = local;
    let exists = await User.findOne({ username: candidate });
    let attempt = 0;
    while (exists) {
        attempt += 1;
        // append small random suffix or attempt count
        candidate = `${local}${Math.floor(1000 + Math.random() * 9000)}`;
        // fallback protection
        if (attempt > 10) candidate = `${local}-${Date.now().toString().slice(-5)}`;
        exists = await User.findOne({ username: candidate });
    }
    return candidate;
}

exports.handler = async (event) => {
    try {
        const { email, password, avatar, otp } = req.body;
        if (!email || !password || !otp) {
            return res.status(400).json({ error: "Email, password and OTP are required" });
        }

        const stored = otpStore.get(email.toLowerCase().trim());
        if (!stored || stored.otp !== otp || stored.expiresAt < Date.now()) {
            return res.status(400).json({ error: "Invalid or expired OTP" });
        }

        otpStore.delete(email.toLowerCase().trim());

        const existing = await User.findOne({ email: email.toLowerCase().trim() });
        if (existing) return res.status(409).json({ error: "Email already registered" });

        const username = await generateUniqueUsername(email);

        const saltRounds = 10;
        const passwordHash = await bcrypt.hash(password, saltRounds);

        const newUser = new User({
            email: email.toLowerCase().trim(),
            username,
            avatar,
            passwordHash
        });

        await newUser.save();

        const token = jwt.sign(
            { id: newUser._id, username: newUser.username, avatar: newUser.avatar },
            process.env.JWT_SECRET
        );

        res.status(201).json({ message: "User registered", username: newUser.username, token });

    } catch (err) {
        console.error("Register error:", err);
        res.status(500).json({ error: "Registration failed" });
    }
}