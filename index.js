const express = require("express");
const multer = require("multer");
const cloudinary = require("cloudinary").v2;
const dotenv = require("dotenv");
const cors = require("cors");
const fs = require("fs");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
dotenv.config();

const app = express();
const port = 5000;

app.use(cors());
// enable body parsers
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// MongoDB Connection
mongoose.connect(process.env.MONGODB, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log("✅ MongoDB connected"))
.catch(err => {
  console.error("❌ MongoDB connection error:", err);
  process.exit(1);
});

// --- Schemas ---

// User Schema (separate collection)
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  username: { type: String, required: true, unique: true, trim: true },
  passwordHash: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model("users", userSchema);

// File Schema
const fileSchema = new mongoose.Schema({
  username: { type: String, required: true },
  link: { type: String, required: true },
  filename: {type:String},
  size: { type: Number, required: true },
  timeStamp: { type: Date, default: Date.now },
});
const ShareFile = mongoose.model("share_files", fileSchema);


// File Schema
app.post("/share-file", async (req, res) => {
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
});

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

// --- Auth routes ---

// Register
app.post("/register", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "Email and password are required" });

    // check if email already registered
    const existing = await User.findOne({ email: email.toLowerCase().trim() });
    if (existing) return res.status(409).json({ error: "Email already registered" });

    // generate unique username from email local-part
    const username = await generateUniqueUsername(email);

    // hash password
    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    const newUser = new User({
      email: email.toLowerCase().trim(),
      username,
      passwordHash
    });

    await newUser.save();

    // optionally sign a token right away (or require login)
    const token = jwt.sign(
      { id: newUser._id, username: newUser.username },
      process.env.JWT_SECRET,
    );

    res.status(201).json({ message: "User registered", username: newUser.username, token });
  } catch (err) {
    console.error("Register error:", err);
    res.status(500).json({ error: "Registration failed" });
  }
});

// Login
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "Email and password are required" });

    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user) return res.status(401).json({ error: "Invalid credentials" });

    const isValid = await bcrypt.compare(password, user.passwordHash);
    if (!isValid) return res.status(401).json({ error: "Invalid credentials" });

    const token = jwt.sign(
      {username: user.username},
      process.env.JWT_SECRET,
      
    );

    res.json({ message: "Login successful", token });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Login failed" });
  }
});

// Optionally: middleware to protect routes using Authorization header "Bearer <token>"
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith("Bearer ")) return res.status(401).json({ error: "Authorization required" });

  const token = auth.split(" ")[1];
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.user = payload; // contains id and username
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

// --- Upload Endpoint (unchanged, but will accept username from header/body) ---
app.post("/upload", upload.single("file"), async (req, res) => {
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
});

// DELETE
app.delete("/delete/:id", async (req, res) => {
  try {
    const {fileLink} = req.body;
    // 1. Get token from Authorization header
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return res.status(401).json({ error: "No token provided" });
    }

    const token = authHeader.split(" ")[1]; // "Bearer <token>"
    if (!token) {
      return res.status(401).json({ error: "Invalid token format" });
    }

    // 2. Verify and decode token
    let decoded;
    try {
      decoded = jwt.verify(token, "6dsfta6sta87dad86as7d6asd7a6d"); // use your secret
    } catch (err) {
      return res.status(401).json({ error: "Invalid or expired token" });
    }

    const username = decoded.username || decoded.name;
    if (!username) {
      return res.status(400).json({ error: "Username not found in token" });
    }

    // 3. Find the file in DB by id
    const fileRecord = await ShareFile.findById(req.params.id);
    if (!fileRecord) {
      return res.status(404).json({ error: "File not found" });
    }

    // 4. Check ownership (only uploader can delete)
    if (fileRecord.username !== username) {
      return res.status(403).json({ error: "You do not have permission to delete this file" });
    }

    // 5. Extract Cloudinary public_id from the file link
    const url = new URL(fileRecord.link);
    const pathname = url.pathname; // e.g. "/demo/upload/v1234567890/my-files/filename.ext"
    const publicIdWithExt = pathname.split("/upload/")[1]; // "v1234567890/my-files/filename.ext"

    const parts = publicIdWithExt.split("/");
    let publicIdParts = parts;

    // Remove version part if exists (e.g., v1234567890)
    if (parts[0].match(/^v\d+$/)) {
      publicIdParts = parts.slice(1);
    }

    const publicIdWithExtension = publicIdParts.join("/");
    const lastDotIndex = publicIdWithExtension.lastIndexOf(".");
    const publicId = lastDotIndex !== -1
      ? publicIdWithExtension.substring(0, lastDotIndex)
      : publicIdWithExtension;

    // 6. Delete file from Cloudinary
    await cloudinary.uploader.destroy(publicId, { resource_type: "raw" });

    // 7. Delete record from MongoDB
    // await ShareFile.findByIdAndDelete(req.params.id);
    await ShareFile.deleteMany({ link: fileLink });


    // 8. Respond success
    res.json({ message: "File deleted successfully" });
  } catch (error) {
    console.error("Delete error:", error);
    res.status(500).json({ error: "Failed to delete file" });
  }
});


// Fetch all files for a given username (from headers)
app.post("/files", async (req, res) => {
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
});


app.get("/get-info", (req, res) => {
  const auth = req.header("Authorization"); // yaha se header le rahe hain
  if (!auth || !auth.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Authorization token required" });
  }

  const token = auth.split(" ")[1];
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    res.json({ user: payload });
  } catch (err) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
});


// Share File Route
app.post("/share-file", async (req, res) => {
  try {
    const { fileId, recipientEmail } = req.body;

    // Validate input
    if (!fileId || !recipientEmail) {
      return res.status(400).json({ error: "File ID and recipient email are required" });
    }

    // 1. Find recipient by email
    const recipient = await User.findOne({ email: recipientEmail });
    if (!recipient) {
      return res.status(404).json({ error: "Recipient user not found" });
    }

    // 2. Find the file by ID
    const file = await ShareFile.findById(fileId);
    if (!file) {
      return res.status(404).json({ error: "File not found" });
    }

    // (Optional) Ownership check — uncomment if needed
    // if (file.owner !== decoded.username) {
    //   return res.status(403).json({ error: "You are not the owner of this file" });
    // }

    // 3. Share the file if not already shared
    if (!file.sharedWith.includes(recipient.email)) {
      file.sharedWith.push(recipient.email);
      await file.save();
    }

    res.json({ message: `File shared with ${recipient.email} successfully` });

  } catch (error) {
    console.error("Share file error:", error);
    res.status(500).json({ error: "Failed to share file" });
  }
});



app.listen(port, () => {
  console.log(`🚀 Server running at http://localhost:${port}`);
});
