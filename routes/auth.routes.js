import { Router } from "express";
import { registerUser, sendOtp } from "../controllers/auth.controller.js";

const authRouter = Router()

authRouter.post('/send-otp', sendOtp)
authRouter.post('/register', registerUser)

export default authRouter