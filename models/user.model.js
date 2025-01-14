import mongoose from "mongoose";

const Schema = mongoose.Schema;

const userSchema = new Schema({
    name: {
        type: String,
        required: true,
        trim: true
    },
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true
    },
    password: {
        type: String,
        required: true
    },
    profileImg: {
        type: String,
    },
    pin: {
        type: String,
        default: null
    },
    accounts: [
        {
            type: {
                type: String,
                enum: ['bank', 'credit card', 'wallet'],
                required: true
            },
            accountName: {
                type: String,
                required: true
            },
            balance: {
                type: Number,
                default: 0
            },
        },
    ],
}, {
    timestamps: true
});

const User = mongoose.model('User', userSchema);
export default User;
