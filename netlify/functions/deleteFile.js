const cloudinary = require("cloudinary").v2;
const dotenv = require("dotenv");
dotenv.config();

// Cloudinary Config
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

exports.handler = async (event) => {
    try {
        const { fileLink } = req.body;
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
}