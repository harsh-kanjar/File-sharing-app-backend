const mongoose = require("mongoose");

// --- Schemas ---

// File Schema
const fileSchema = new mongoose.Schema({
  username: { type: String, required: true },
  link: { type: String, required: true },
  filename: {type:String},
  size: { type: Number, required: true },
  timeStamp: { type: Date, default: Date.now },
});
const ShareFile = mongoose.model("share_files", fileSchema);

exports.handler = async (event) => {
    try {
        const { username, link, filename, size, timeStamp } = req.body;

        // Validate required fields
        if (!username || !link || !filename || !size) {
            return res.status(400).json({ error: "All required fields must be provided" });
        }

        // Create new entry
        const newFile = new ShareFile({
            username,
            link,
            filename,
            size,
            timeStamp: timeStamp || Date.now()
        });

        await newFile.save();

        res.json({ message: "File shared successfully", file: newFile });
    } catch (error) {
        console.error("Share file error:", error);
        res.status(500).json({ error: "Failed to share file" });
    }
}