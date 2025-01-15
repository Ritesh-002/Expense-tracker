import { Router } from "express";
import { loginUser, logoutUser, registerUser, requestPasswordResetToken, sendOtp, validatePasswordResetToken } from "../controllers/auth.controller.js";

const authRouter = Router()

authRouter.post('/send-otp', sendOtp)
authRouter.post('/register', registerUser)
authRouter.post('/login', loginUser)
authRouter.post('/logout', logoutUser)
authRouter.post('/forget-password', requestPasswordResetToken)
authRouter.post('/reset-password', validatePasswordResetToken)

export default authRouter