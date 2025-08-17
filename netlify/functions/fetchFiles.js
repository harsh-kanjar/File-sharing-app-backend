// Fetch all files for a given username (from headers)
const dotenv = require("dotenv");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
dotenv.config();

// --- Schemas ---

// File Schema
const fileSchema = new mongoose.Schema({
    username: { type: String, required: true },
    link: { type: String, required: true },
    filename: { type: String },
    size: { type: Number, required: true },
    timeStamp: { type: Date, default: Date.now },
});
const ShareFile = mongoose.model("share_files", fileSchema);

exports.handler = async (event) => {
    try {
        // 🔹 Get token from request body
        const { token } = req.body;
        if (!token) {
            return res.status(401).json({ error: "No token provided" });
        }

        // 🔹 Verify and decode token
        let decoded;
        try {
            decoded = jwt.verify(token, "6dsfta6sta87dad86as7d6asd7a6d");
        } catch (err) {
            return res.status(401).json({ error: "Invalid or expired token" });
        }

        const username = decoded.username || decoded.name;
        if (!username) {
            return res.status(400).json({ error: "Username not found in token" });
        }

        // 🔹 Fetch user's files from DB
        const files = await ShareFile.find({ username });

        res.json({
            total: files.length,
            files
        });
    } catch (error) {
        console.error("Error fetching files:", error);
        res.status(500).json({ error: "Failed to fetch files" });
    }
}