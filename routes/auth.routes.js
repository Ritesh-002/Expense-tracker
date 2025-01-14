import { Router } from "express";
import { sendOtp } from "../controllers/auth.controller.js";

const authRouter = Router()

authRouter.post('/send-otp', sendOtp)

export default authRouter