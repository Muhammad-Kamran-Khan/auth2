import express from "express";
import { loginUser, logoutUser, registerUser, getUser, updateUser, userLoginStatus, verifyEmail, verifyUser, forgetPassword, resetPassword, changePassword} from "../controllers/auth/userControllers.js";
import adminControllers from "../controllers/auth/adminControllers.js";
const { deleteUser, getAllUsers } = adminControllers;
import {protect, adminMiddleware, creatorMiddleware} from"../middleware/authMiddlewares.js";
const router = express.Router();

//user routes
router.post("/register", registerUser);
router.post("/login", loginUser);
router.get("/logout", logoutUser);
router.get("/user", protect, getUser);
router.patch("/user", protect, updateUser);

//login status
router.get("/login-status", userLoginStatus);

// email verification
router.post("/verify-email", protect, verifyEmail);

// veriify user --> email verification
router.post("/verify-user/:verificationToken", verifyUser);

// forgot password
router.post("/forgot-password", forgetPassword);

//reset password
router.post("/reset-password/:resetPasswordToken", resetPassword);

// change password ---> user must be logged in
router.patch("/change-password", protect, changePassword);

// admin route
router.delete("/admin/users/:id", protect, adminMiddleware, deleteUser);
//admin get all users
router.get("/admin/users", protect, creatorMiddleware, getAllUsers);

export default router;