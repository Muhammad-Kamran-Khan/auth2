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

    //validation
    if (!name || !email || !password) {
        // 400 Bad Request
        res.status(400).json({ message: "All fields are required" });
    }

    // check password length
    if (password.length < 6) {
        return res
            .status(400)
            .json({ message: "Password must be at least 6 characters" });
    }

    // check if user already exists
    const userExists = await User.findOne({ email });
    if (userExists) {
        return res.status(400).json({ message: "User already exists" });
    }

    // create user
    const user = await User.create({
        name,
        email,
        password,
    });

    // generate token
    const token = generateToken(user._id);

    //send back user data and token to client
    res.cookie("token", token, {
        path: "/",
        httpOnly: true,
        maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
        sameSite: "lax", // cross-site access --> allow all third-party cookies
        secure: false,
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
})

export const loginUser = asynchandler(async (req, res) => {
    const { email, password } = req.body;

    //validation
    if (!email || !password) {
        return res.status(400).json({ message: "All fields are required" });
    }

    // check if user exists
    const userExists = await User.findOne({ email });
    if (!userExists) {
        return res.status(400).json({ message: "User does not exist, please register!" });
    }

    const isMatch = await bcrypt.compare(password, userExists.password);
    if (!isMatch) {
        return res.status(400).json({ message: "Invalid email or password" });
    }

    // generate token
    const token = generateToken(userExists._id);

    //send back user data and token to client
    res.cookie("token", token, {
        path: "/",
        httpOnly: true,
        sameSite: "lax", // cross-site access --> allow all third-party cookies
        secure: false,
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
})

export const logoutUser = asynchandler(async (req, res) => {
    res.clearCookie("token", {
        httpOnly: true,
        sameSite: "none",
        secure: false,
        path: "/",
    });

    res.status(200).json({ message: "User logged out successfully" });
})

//getUser means after login, get user data for dashboard or other purposes
export const getUser = asynchandler(async (req, res) => {

    // get user details from the token ----> exclude password
    const user = await User.findById(req.user._id).select("-password");

    if (user) {
        res.status(200).json(user);
    } else {
        res.status(404).json({ message: "User not found" });
    }
})

export const updateUser = asynchandler(async (req, res) => {

    // get user details from the token ----> exclude password
    const user = await User.findById(req.user._id);

    if (user) {
        const { name, bio, photo } = req.body;

        // update user details
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
        })
    } else {
        res.status(404).json({ message: "User not found" });
    }
})

// login status
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


//verify user email
export const verifyEmail = asynchandler(async (req, res) => {
    const user = await User.findById(req.user._id);
    if (!user) {
        return res.status(404).json({ message: "User not found" });
    }

    if (user.isVerified) {
        return res.status(400).json({ message: "User already verified" });
    }

    const token = await Token.findOne({ userId: user._id });

    //if token exists, delete it
    if (token) {
        await token.deleteOne();
    }

    // create a new token using userId
    const verficationToken = crypto.randomBytes(64).toString("hex") + user._id;

    //hash the verfication token
    const hashedToken = hashToken(verficationToken);

    await new Token({
        userId: user._id,
        verificationToken: hashedToken,
        createdAt: Date.now(),
        expiresAt: Date.now() + 24 * 60 * 60 * 1000, // 24 hours
    }).save();

    const verificationLink = `${process.env.CLIENT_URL}/verify-email/${verficationToken}`;

    // send email
    const subject = "Email Verification - Auth2";
    const send_to = user.email;
    const reply_to = "noreply@gmail.com";
    const template = "emailVerification";
    const send_from = process.env.USER_EMAIL;
    const name = user.name;
    const url = verificationLink;

    try {
        // order matters ---> subject, send_to, send_from, reply_to, template, name, url
        await sendEmail(subject, send_to, send_from, reply_to, template, name, url);
        return res.json({ message: "Email sent" });
    } catch (error) {
        console.log("Error sending email: ", error);
        return res.status(500).json({ message: "Email could not be sent" });
    }
});

//verify user
export const verifyUser = asynchandler(async (req, res) => {
    const { verificationToken } = req.params;

    if (!verificationToken) {
        return res.status(400).json({ message: "Invalid request" });
    }

    // hash the verification token --> because it was hashed before saving
    const hashedToken = hashToken(verificationToken);

    // find the user with the verfication token
    const userToken = await Token.findOne({
        verificationToken: hashedToken,
        expiresAt: { $gt: Date.now() }, // check if token is not expired
    });

    if (!userToken) {
        return res
            .status(400)
            .json({ message: "Invalid or expired verification token" });
    }

    //find user with the user id in the token
    const user = await User.findById(userToken.userId);

    if (user.isVerified) {
        return res.status(400).json({ message: "User already verified" });
    }

    //update user to verified
    user.isVerified = true;
    await user.save();
    res.status(200).json({ message: "User verified successfully" });
})

//forget password
export const forgetPassword = asynchandler(async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ message: "Email is required" });
    }

    // check if user exists
    const user = await User.findOne({ email: email });

    if (!user) {
        return res.status(400).json({ message: "User does not exist" });
    }

    // see if reset token exists
    let token = await Token.findOne({ userId: user._id });

    // if token exists --> delete the token
    if (token) {
        await token.deleteOne();
    }

    // create a reset token using the user id ---> expires in 1 hour
    const passwordResetToken = crypto.randomBytes(64).toString("hex") + user._id;

    // hash the password reset token
    const hashedPasswordResetToken = hashToken(passwordResetToken);

    await new Token({
        userId: user._id,
        passwordResetToken: hashedPasswordResetToken,
        createdAt: Date.now(),
        expiresAt: Date.now() + 60 * 60 * 1000, // 1 hour
    }).save();

    // reset link
    const resetLink = `${process.env.CLIENT_URL}/reset-password/${passwordResetToken}`;

    // send email to user
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

// reset password
export const resetPassword = asynchandler(async (req, res) => {
    const { resetPasswordToken } = req.params;
    const { password } = req.body;

    if (!password) {
        return res.status(400).json({ message: "Password is required" });
    }

    // hash the reset token
    const hashedToken = hashToken(resetPasswordToken);

    // check if token exists and has not expired
    const userToken = await Token.findOne({
        passwordResetToken: hashedToken,
        // check if the token has not expired
        expiresAt: { $gt: Date.now() },
    });

    if (!userToken) {
        return res.status(400).json({ message: "Invalid or expired reset token" });
    }

    // find user with the user id in the token
    const user = await User.findById(userToken.userId);

    // update user password
    user.password = password;
    await user.save();

    res.status(200).json({ message: "Password reset successfully" });
});

// change password
export const changePassword = asynchandler(async (req, res) => {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
        return res.status(400).json({ message: "All fields are required" });
    }

    //find user by id
    const user = await User.findById(req.user._id);

    // compare current password with the hashed password in the database
    const isMatch = await bcrypt.compare(currentPassword, user.password);

    if (!isMatch) {
        return res.status(400).json({ message: "Invalid password!" });
    }

    // reset password
    if (isMatch) {
        user.password = newPassword;
        await user.save();
        return res.status(200).json({ message: "Password changed successfully" });
    } else {
        return res.status(400).json({ message: "Password could not be changed!" });
    }
});