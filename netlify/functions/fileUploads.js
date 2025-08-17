const multer = require("multer");
const cloudinary = require("cloudinary").v2;
const dotenv = require("dotenv");
const fs = require("fs");
const jwt = require("jsonwebtoken");
dotenv.config();

// Multer Config
const upload = multer({
  dest: "uploads/",
  limits: { fileSize: 50 * 1024 * 1024 } // 50 MB
});

// Cloudinary Config
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

exports.handler = async (event) => {
    try {
        // 🔹 Get JWT token from Authorization header
        const authHeader = req.headers.authorization;
        if (!authHeader) {
            return res.status(401).json({ error: "No token provided" });
        }

        const token = authHeader.split(" ")[1]; // "Bearer <token>"
        if (!token) {
            return res.status(401).json({ error: "Invalid token format" });
        }

        // 🔹 Verify & decode token
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

        if (!req.file) {
            return res.status(400).json({ error: "File is required" });
        }

        const filePath = req.file.path;
        const fileSize = req.file.size;
        const originalName = req.file.originalname; // ✅ Get original filename

        // 🔹 Upload to Cloudinary
        const fileUpload = await cloudinary.uploader.upload(filePath, {
            resource_type: "raw",
            folder: "my-files"
        });

        fs.unlinkSync(filePath); // remove local file

        // 🔹 Save metadata in MongoDB with filename
        const newFile = new ShareFile({
            username,
            filename: originalName,  // ✅ Save original filename
            link: fileUpload.secure_url,
            size: fileSize
        });

        await newFile.save();

        res.json({
            message: "File uploaded & metadata saved successfully!",
            uploadedFile: fileUpload.secure_url,
            filename: originalName
        });

    } catch (error) {
        console.error("Upload error:", error);
        res.status(500).json({ error: "Failed to upload file" });
    }
}