// src/middleware/authMiddleware.js
// This file contains a suite of middleware functions for authentication and authorization.

import asynchandler from "express-async-handler";
// These imports were missing from your 'protect' middleware and are crucial for it to work.
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import User from "../models/auth/UserModel.js";

// Make sure your .env file is loaded.
dotenv.config();

/**
 * @desc Checks for a valid JWT token in the request cookies and attaches the user object to the request.
 * @param {object} req - The request object
 * @param {object} res - The response object
 * @param {function} next - The next middleware function
 */
export const protect = asynchandler(async (req, res, next) => {
    // Get the token from the cookie
    const token = req.cookies.token;

    // If no token exists, the user is not authenticated.
    if (!token) {
        res.status(401);
        throw new Error("Not authorized, no token");
    }

    try {
        // Verify the token with the secret key.
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        // Find the user by ID from the decoded token and exclude their password.
        const user = await User.findById(decoded.id).select("-password");

        if (!user) {
            res.status(401);
            throw new Error("Not authorized, user not found");
        }

        // Attach the user object to the request for use in subsequent handlers.
        req.user = user;
        next(); // Proceed to the next middleware or route handler.
    } catch (error) {
        // If the token is invalid or expired, handle the error.
        res.status(401);
        throw new Error("Not authorized, token failed");
    }
});

/**
 * @desc Restricts access to a route to users with the 'admin' role.
 * This middleware should be used *after* the 'protect' middleware.
 * @param {object} req - The request object
 * @param {object} res - The response object
 * @param {function} next - The next middleware function
 */
export const adminMiddleware = asynchandler(async (req, res, next) => {
    // We can assume `req.user` exists because this middleware follows `protect`.
    if (req.user && req.user.role === 'admin') {
        next();
    } else {
        res.status(403);
        throw new Error("Access denied, admin only");
    }
});

/**
 * @desc Restricts access to a route to users with the 'creator' or 'admin' roles.
 * This middleware should be used *after* the 'protect' middleware.
 * @param {object} req - The request object
 * @param {object} res - The response object
 * @param {function} next - The next middleware function
 */
export const creatorMiddleware = asynchandler(async (req, res, next) => {
    if (req.user && (req.user.role === "creator") || req.user && (req.user.role === "admin")) {
        next();
    } else {
        res.status(403);
        throw new Error("Only creators can do this!");
    }
});

/**
 * @desc Restricts access to a route to users who have a verified email address.
 * This middleware should be used *after* the 'protect' middleware.
 * @param {object} req - The request object
 * @param {object} res - The response object
 * @param {function} next - The next middleware function
 */
export const verifiedMiddleware = asynchandler(async (req, res, next) => {
    if (req.user && req.user.isVerified) {
        next();
    } else {
        res.status(403);
        throw new Error("Please verify your email address!");
    }
});
