import User from "../../models/auth/UserModel.js";
import generateToken from "../../helpers/generateToken.js";
import asynchandler from "express-async-handler";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import Token from "../../models/auth/Token.js";
import crypto from "node:crypto";
import hashToken from "../../helpers/hashToken.js";
import sendEmail from "../../helpers/sendEmail.js";
dotenv.config();

export const registerUser = asynchandler(async (req, res) => {
    const { name, email, password } = req.body;

    // Validation
    if (!name || !email || !password) {
        res.status(400).json({ message: "All fields are required" });
    }

    // Check password length
    if (password.length < 6) {
        return res
            .status(400)
            .json({ message: "Password must be at least 6 characters" });
    }

    // Check if user already exists
    const userExists = await User.findOne({ email });
    if (userExists) {
        return res.status(400).json({ message: "User already exists" });
    }

    // Create user
    const user = await User.create({
        name,
        email,
        password,
    });

    // Generate token
    const token = generateToken(user._id);

    // Set cookie in the response
    res.cookie("token", token, {
        path: "/",
        httpOnly: true,
        expires: new Date(Date.now() + 1000 * 60 * 60 * 24 * 30), // 30 days
        sameSite: "none",
        secure: true,
    });

    if (user) {
        const { _id, name, email, role, photo, bio, isVerified } = user;
        // 201 Created
        res.status(201).json({
            _id,
            name,
            email,
            role,
            photo,
            bio,
            isVerified,
            token,
        });
    } else {
        res.status(400).json({ message: "Invalid user data" });
    }
});

export const loginUser = asynchandler(async (req, res) => {
    const { email, password } = req.body;

    // Validation
    if (!email || !password) {
        return res.status(400).json({ message: "All fields are required" });
    }

    // Check if user exists
    const userExists = await User.findOne({ email });
    if (!userExists) {
        return res.status(400).json({ message: "User does not exist, please register!" });
    }

    const isMatch = await bcrypt.compare(password, userExists.password);
    if (!isMatch) {
        return res.status(400).json({ message: "Invalid email or password" });
    }

    // Generate token
    const token = generateToken(userExists._id);

    // Set cookie in the response
    res.cookie("token", token, {
        path: "/",
        httpOnly: true,
        // CORRECTED: Added an expiration to make the cookie persistent
        expires: new Date(Date.now() + 1000 * 60 * 60 * 24 * 30), // 30 days
        sameSite: "none",
        secure: true,
    });

    if (userExists && isMatch) {
        const { _id, name, email, role, photo, bio, isVerified } = userExists;
        // 200 OK
        res.status(200).json({
            _id,
            name,
            email,
            role,
            photo,
            bio,
            isVerified,
            token,
        });
    } else {
        res.status(400).json({ message: "Invalid email or password" });
    }
});

export const logoutUser = asynchandler(async (req, res) => {
    // To clear a cookie, you must provide the same options (path, domain, etc.)
    // with which the cookie was set.
    res.clearCookie("token", {
        // CORRECTED: Removed duplicate 'sameSite' and added 'path' for correctness
        path: "/",
        httpOnly: true,
        sameSite: "none",
        secure: true,
    });

    res.status(200).json({ message: "User logged out successfully" });
});

export const getUser = asynchandler(async (req, res) => {
    // Get user details from the token ----> exclude password
    const user = await User.findById(req.user._id).select("-password");

    if (user) {
        res.status(200).json(user);
    } else {
        res.status(404).json({ message: "User not found" });
    }
});

export const updateUser = asynchandler(async (req, res) => {
    const user = await User.findById(req.user._id);

    if (user) {
        const { name, bio, photo } = req.body;

        // Update user details
        user.name = name || user.name;
        user.bio = bio || user.bio;
        user.photo = photo || user.photo;

        const updated = await user.save();

        res.status(200).json({
            _id: updated._id,
            name: updated.name,
            email: updated.email,
            role: updated.role,
            photo: updated.photo,
            bio: updated.bio,
            isVerified: updated.isVerified,
        });
    } else {
        res.status(404).json({ message: "User not found" });
    }
});

export const userLoginStatus = asynchandler(async (req, res) => {
    const token = req.cookies.token;

    if (!token) {
        return res.status(401).json({ message: "Not authorized, please login!" });
    }

    try {
        jwt.verify(token, process.env.JWT_SECRET);
        return res.status(200).json(true);
    } catch (err) {
        return res.status(401).json(false);
    }
});

export const verifyEmail = asynchandler(async (req, res) => {
    const user = await User.findById(req.user._id);
    if (!user) {
        return res.status(404).json({ message: "User not found" });
    }

    if (user.isVerified) {
        return res.status(400).json({ message: "User already verified" });
    }

    let token = await Token.findOne({ userId: user._id });
    if (token) {
        await token.deleteOne();
    }

    const verificationToken = crypto.randomBytes(64).toString("hex") + user._id;
    const hashedToken = hashToken(verificationToken);

    await new Token({
        userId: user._id,
        verificationToken: hashedToken,
        createdAt: Date.now(),
        expiresAt: Date.now() + 24 * 60 * 60 * 1000, // 24 hours
    }).save();

    const verificationLink = `${process.env.CLIENT_URL}/verify-email/${verificationToken}`;
    const subject = "Email Verification - Auth2";
    const send_to = user.email;
    const reply_to = "noreply@gmail.com";
    const template = "emailVerification";
    const send_from = process.env.USER_EMAIL;
    const name = user.name;
    const url = verificationLink;

    try {
        await sendEmail(subject, send_to, send_from, reply_to, template, name, url);
        return res.json({ message: "Email sent" });
    } catch (error) {
        console.log("Error sending email: ", error);
        return res.status(500).json({ message: "Email could not be sent" });
    }
});

export const verifyUser = asynchandler(async (req, res) => {
    const { verificationToken } = req.params;
    if (!verificationToken) {
        return res.status(400).json({ message: "Invalid request" });
    }

    const hashedToken = hashToken(verificationToken);

    const userToken = await Token.findOne({
        verificationToken: hashedToken,
        expiresAt: { $gt: Date.now() },
    });

    if (!userToken) {
        return res.status(400).json({ message: "Invalid or expired verification token" });
    }

    const user = await User.findById(userToken.userId);

    if (user.isVerified) {
        return res.status(400).json({ message: "User already verified" });
    }

    user.isVerified = true;
    await user.save();
    res.status(200).json({ message: "User verified successfully" });
});

export const forgetPassword = asynchandler(async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ message: "Email is required" });
    }

    const user = await User.findOne({ email: email });
    if (!user) {
        return res.status(400).json({ message: "User does not exist" });
    }

    let token = await Token.findOne({ userId: user._id });
    if (token) {
        await token.deleteOne();
    }

    const passwordResetToken = crypto.randomBytes(64).toString("hex") + user._id;
    const hashedPasswordResetToken = hashToken(passwordResetToken);

    await new Token({
        userId: user._id,
        passwordResetToken: hashedPasswordResetToken,
        createdAt: Date.now(),
        expiresAt: Date.now() + 60 * 60 * 1000, // 1 hour
    }).save();

    const resetLink = `${process.env.CLIENT_URL}/reset-password/${passwordResetToken}`;
    const subject = "Password Reset - Auth2";
    const send_to = user.email;
    const send_from = process.env.USER_EMAIL;
    const reply_to = "noreply@noreply.com";
    const template = "forgotPassword";
    const name = user.name;
    const url = resetLink;

    try {
        await sendEmail(subject, send_to, send_from, reply_to, template, name, url);
        res.json({ message: "Email sent" });
    } catch (error) {
        console.log("Error sending email: ", error);
        return res.status(500).json({ message: "Email could not be sent" });
    }
});

export const resetPassword = asynchandler(async (req, res) => {
    const { resetPasswordToken } = req.params;
    const { password } = req.body;

    if (!password) {
        return res.status(400).json({ message: "Password is required" });
    }

    const hashedToken = hashToken(resetPasswordToken);

    const userToken = await Token.findOne({
        passwordResetToken: hashedToken,
        expiresAt: { $gt: Date.now() },
    });

    if (!userToken) {
        return res.status(400).json({ message: "Invalid or expired reset token" });
    }

    const user = await User.findById(userToken.userId);
    user.password = password;
    await user.save();

    res.status(200).json({ message: "Password reset successfully" });
});

export const changePassword = asynchandler(async (req, res) => {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
        return res.status(400).json({ message: "All fields are required" });
    }

    const user = await User.findById(req.user._id);
    const isMatch = await bcrypt.compare(currentPassword, user.password);

    if (!isMatch) {
        return res.status(400).json({ message: "Invalid password!" });
    }

    user.password = newPassword;
    await user.save();
    return res.status(200).json({ message: "Password changed successfully" });
});