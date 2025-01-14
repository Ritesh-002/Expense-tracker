import User from '../models/user.model.js'
import OTP from '../models/otp.model.js'
import otpGenerator from 'otp-generator'
import * as emailValidator from 'email-validator'
import bcrypt from 'bcrypt'

export const sendOtp = async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) {
            return res.status(400).json({
                success: false,
                message: "Enter email first",
            });
        }
        if (!emailValidator.validate(email)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid email!'
            })
        }
        // Check if user is already present
        const checkUserPresent = await User.findOne({ email });
        // If user found with provided email
        if (checkUserPresent) {
            return res.status(401).json({
                success: false,
                message: 'User is already registered',
            });
        }
        let otp = otpGenerator.generate(6, {
            upperCaseAlphabets: false,
            lowerCaseAlphabets: false,
            specialChars: false,
        });
        let result = await OTP.findOne({ otp: otp });
        while (result) {
            otp = otpGenerator.generate(6, {
                upperCaseAlphabets: false,
            });
            result = await OTP.findOne({ otp: otp });
        }
        const otpPayload = { email, otp };
        const otpBody = await OTP.create(otpPayload);
        res.status(200).json({
            success: true,
            message: 'OTP sent successfully',
            otp,
        });
    } catch (error) {
        console.log(error.message);
        return res.status(500).json({ success: false, error: error.message });
    }
};

export const registerUser = async (req, res) => {
    try {
        const { name, email, password, otp } = req.body;
        if (!name || !email || !password) {
            return res.status(403).json({
                success: false,
                message: 'All fields are required'
            })
        }
        const existingUser = await User.findOne({ email })
        if (existingUser) {
            return res.status(400).json({
                success: false,
                message: 'User already registered'
            })
        }
        // if (password.length() < 8) {
        //     return res.status(400).json({
        //         success: false,
        //         message: 'Password length must be equal or greater than 8 characters'
        //     })
        // }
        if (!otp) {
            return res.status(400).json({
                success: false,
                message: 'Enter OTP'
            })
        }

        const otpFromDB = await OTP.find({ email }).sort({ createdAt: -1 }).limit(1);
        if (otpFromDB.length === 0 || otp != otpFromDB[0].otp) {
            return res.status(400).json({
                success: false,
                message: 'OTP Invalid!'
            })
        }
        let hashedPassword;
        try {
            hashedPassword = await bcrypt.hash(password, 10);
        } catch (error) {
            return res.status(500).json({
                success: false,
                message: `Hashing password error for ${password}: ` + error.message,
            });
        }
        const newUser = await User.create({ name, email, password: hashedPassword });
        return res.status(200).json({
            success: true,
            message: 'User registered successfully',
            user: newUser
        })

    } catch (error) {
        console.log(error.message);
        return res.status(500).json({ success: false, error: error.message });
    }
};