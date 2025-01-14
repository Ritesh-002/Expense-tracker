import { Router } from "express";
import { loginUser, registerUser, sendOtp } from "../controllers/auth.controller.js";

const authRouter = Router()

authRouter.post('/send-otp', sendOtp)
authRouter.post('/register', registerUser)
authRouter.post('/login', loginUser)

export default authRouter