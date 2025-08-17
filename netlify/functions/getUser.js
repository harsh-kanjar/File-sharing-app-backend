const dotenv = require("dotenv");
const jwt = require("jsonwebtoken");

dotenv.config();
exports.handler = async (event) => {
    const { token } = req.body;
    if (!token) {
        return res.status(401).json({ error: "Authorization token required" });
    }

    try {
        const payload = jwt.verify(token, process.env.JWT_SECRET);
        res.json({ user: payload });
    } catch (err) {
        return res.status(401).json({ error: "Invalid or expired token" });
    }
}