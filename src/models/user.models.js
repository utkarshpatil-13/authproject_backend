import mongoose from 'mongoose'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'

const userSchema = mongoose.Schema({
    firstname: {
        type: String,
        required: true,
    },
    lastname: {
        type: String,
        required: true,
    },
    email: {
        type: String,
        required: true,
    },
    password: {
        type: String,
        required: true,
    },
    refreshToken: {
        type: String,
    },
    isVerified: {
        type: Boolean,
    },
    verifyToken: {
        type: String,
    },
    verifyTokenExpiry:{
        type: Date,
    },
    twoFA: {
        secret: {
            type: String,
        },
        enabled: {
            type: Boolean,
            default: false,   
        }
    }
})


userSchema.pre("save", async function (next){
    if(!this.isModified("password")) return null;

    this.password = await bcrypt.hash(this.password, 10);
    next();
})

userSchema.methods.isPasswordCorrect = async function (password){
    return await bcrypt.compare(password, this.password);
}

userSchema.methods.generateAccessToken = function (){
    return jwt.sign(
        {
            _id: this._id
        },
        process.env.ACCESS_TOKEN_SECRET,
        {
            expiresIn: process.env.ACCESS_TOKEN_EXPIRY
        }
    )
}

userSchema.methods.generateRefreshToken = function(){
    return jwt.sign(
        {
            _id: this.id,
        },
        process.env.REFRESH_TOKEN_SECRET,
        {
            expiresIn: process.env.REFRESH_TOKEN_EXPIRY,
        }
    )
} 

const User = mongoose.model('User', userSchema);

export default User;

