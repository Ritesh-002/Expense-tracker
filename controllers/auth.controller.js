import User from '../models/user.model.js'
import OTP from '../models/otp.model.js'
import otpGenerator from 'otp-generator'
import * as emailValidator from 'email-validator'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import mailSender from '../utils/send.email.js'

const cookieOptions = {
    secure: process.env.NODE_ENV == 'production' ? true : false,
    maxAge: 7 * 24 * 60 * 60 * 1000,
    httpOnly: true,
}

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
            return res.status(402).json({
                success: false,
                message: "error while hashing"
            })
        }
        console.log('hashedpassword', hashedPassword);
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

export const loginUser = async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(401).json({
                success: false,
                message: 'Missing fields found'
            })
        }
        const user = await User.findOne({ email }).select('+password');
        if (!user) {
            return res.status(401).json({
                success: false,
                message: 'user does not exist'
            })
        }
        const passwordMatch = await bcrypt.compare(password, user.password);
        // console.log(passwordMatch)
        // console.log('password', password)
        console.log('password', user.password)
        if (!passwordMatch) {
            return res.status(401).json({
                success: false,
                message: 'password did not match'
            })
        }
        const token = jwt.sign(
            {
                userId: user._id,
            },
            process.env.JWT_SECRET,
            {
                expiresIn: process.env.JWT_EXPIRY
            }
        )
        res.cookie('token', token, cookieOptions);
        user.password = undefined;
        return res.status(200).json({
            success: true,
            message: 'user logged in',
            user
        })
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: error,
        })
    }
}

export const logoutUser = async (req, res) => {
    res.cookie('token', null, {
        secure: process.env.NODE_ENV === 'production' ? true : false,
        maxAge: 0,
        httpOnly: true,
    });

    // Sending the response
    res.status(200).json({
        success: true,
        message: 'User logged out successfully',
    });
}

export const requestPasswordResetToken = async (req, res) => {
    const { email } = req.body;
    try {
        const user = await User.findOne({ email })
        if (!user) {
            return res.status(401).json({
                success: false,
                message: "email not registered"
            })
        }
        const secret = process.env.JWT_SECRET + user.password;
        const token = jwt.sign(
            {
                id: user._id,
                email: user.email
            },
            secret,
            {
                expiresIn: process.env.PASSWORD_RESET_EXPIRY
            }
        )
        const resetUrl = `${process.env.BASE_URL}/api/v1/auth/reset-password?id=${user._id}&token=${token}`;

        const mailResponse = await mailSender(
            email,
            'Password Reset Request',
            `You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n
            Please click on the following link, or paste this into your browser to complete the process:\n\n
            ${resetUrl}\n\n expires in ${process.env.PASSWORD_RESET_EXPIRY} \n\n
            If you did not request this, please ignore this email and your password will remain unchanged.\n`
        )
        console.log(mailResponse)
        return res.status(200).json({
            message: 'Password reset link sent',
            resetUrl
        });
    } catch (error) {
        return res.status(500).json({
            message: 'Something went wrong'
        });
    }
}

export const validatePasswordResetToken = async (req, res) => {
    const { id, token } = req.query
    const { password } = req.body
    try {
        const user = await User.findOne({ _id: id });
        if (!user) {
            return res.status(400).json({
                success: false,
                message: 'user not found'
            })
        }
        const secret = process.env.JWT_SECRET + user.password;
        console.log(token)
        const decodedPayload = jwt.verify(token, secret)
        const hashedPassword = await bcrypt.hash(password, 10);
        await User.updateOne(
            {
                _id: id
            },
            {
                $set: {
                    password: hashedPassword,
                },
            }
        )
        // await user.save()
        return res.status(200).json({
            message: 'Password has been reset'
        });
    } catch (error) {
        if (error.name === "TokenExpiredError") {
            return res.status(400).json({
                success: false,
                message: "Token has expired",
            });
        } else if (error.name === "JsonWebTokenError") {
            return res.status(400).json({
                success: false,
                message: "Invalid token",
            });
        }
        console.error("Error in password reset validation:", error);
        return res.status(500).json({
            success: false,
            message: "Something went wrong",
        });
    }
}