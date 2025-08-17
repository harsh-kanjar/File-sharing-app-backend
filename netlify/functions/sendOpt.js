const dotenv = require("dotenv");
const nodemailer = require("nodemailer");
dotenv.config();

// OTP store
const otpStore = new Map();

exports.handler = async (event) => {
    try {
        const { email } = req.body;
        if (!email) return res.status(400).json({ error: "Email is required" });

        const existing = await User.findOne({ email: email.toLowerCase().trim() });
        if (existing) return res.status(409).json({ error: "Email already registered" });

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        otpStore.set(email.toLowerCase().trim(), {
            otp,
            expiresAt: Date.now() + 5 * 60 * 1000
        });

        // ✅ Ensure `from` matches your Gmail user
        const transporter = nodemailer.createTransport({
            service: "gmail",
            auth: {
                user: "you-email@gmail.com",
                pass: "cqwy odvg gtii gkxj" // App password
            }
        });

        await transporter.sendMail({
            from: "your-email@gmail.com", // must match Gmail account
            to: email,
            subject: "Your OTP Code",
            text: `Your verification code is ${otp}. It will expire in 5 minutes.`
        });

        res.json({ message: "OTP sent to email" });

    } catch (err) {
        console.error("OTP send error:", err);
        res.status(500).json({ error: "Failed to send OTP" });
    }
}