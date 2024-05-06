import User from "../models/user.models.js";
import { ApiError } from "../utils/ApiError.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import bcrypt from 'bcrypt'
import nodemailer from 'nodemailer'

// QR and Authenticator
import qrcode from 'qrcode'
import {authenticator} from 'otplib'

// socket io
import io from "../index.js";
import Activity from "../models/activity.models.js";
import {Server, Socket} from 'socket.io'

// Map to store user ID and corresponding socket ID
const userSocketMap = new Map();

// Function to associate user ID with socket ID
const associateSocketWithUser = (userId, socketId) => {
    userSocketMap.set(userId, socketId);
}

const convertTimestamp = (timestamp) => {
    const date = new Date(timestamp);

    // Get the individual components of the date (year, month, day, hour, minute, second)
    const year = date.getFullYear();
    const month = date.getMonth() + 1; // Months are zero-based, so January is 0
    const day = date.getDate();
    const hours = date.getHours();
    const minutes = date.getMinutes();
    const seconds = date.getSeconds();

    // Format the date and time string as desired
    const formattedDateTime = `${year}-${month < 10 ? '0' : ''}${month}-${day < 10 ? '0' : ''}${day} ${hours < 10 ? '0' : ''}${hours}:${minutes < 10 ? '0' : ''}${minutes}:${seconds < 10 ? '0' : ''}${seconds}`;

    return formattedDateTime;
}

const registerUser = asyncHandler(async (req, res) => {
    // collect the info
    const {firstname, lastname, email, password} = req.body;

    // verify that it is empty or not 
    if([firstname, lastname, email, password].some((field) => field.trim() === '')){
        throw new ApiError(400, "All fields are required!");
    }

    // check if the User exists
    const existingUser = await User.findOne({email});

    if(existingUser){
        throw new ApiError(409, "User already exists!");
    }

    //  create User 
    const createdUser = await User.create({
        firstname,
        lastname,
        email,
        password
    });

    // disselect the password
    const user = await User.findById(createdUser._id).select(
        '-password'
    );


    if(!user){
        throw new ApiError(500, 'Something went wrong while createing the user!');
    }

    await sendEmail({email: email, emailType: "VERIFY", userId: user._id});

    return res
    .status(200)
    .json(new ApiResponse(200, user, 'User created successfully!'));

});

const generateAccessAndRefreshTokens = async (userId) => {
    try {
        const user = await User.findById(userId);
    
        if(!user){
            throw new ApiError(404, "User does not exists");
        }
    
        const accessToken = user.generateAccessToken();
        const refreshToken = user.generateRefreshToken();
    
        // save the refresh token in the database
    
        user.refreshToken = refreshToken;
    
        await user.save({'validateBeforeSave' : false});
    
        return {accessToken, refreshToken};
    } catch (error) {
        throw new ApiError(500, "Something went wrong while generating Access and Refresh Tokens");
    }
}

const loginUser = async (req, res) => {
    try{
        const {email, password} = req.body;
    
        if([email, password].some((field) => field.trim() === '')){
            throw new ApiError(400, "Enter all fields");
        }
    
        const user = await User.findOne({email});
    
        if(!user){
            throw new ApiError(400, 'User not found');
        }
    
        const isPasswordCorrect = await user.isPasswordCorrect(password);
    
        if(!isPasswordCorrect){
            throw new ApiError(401, 'Invalid user credentials!');
        }

        // console.log(email, password, code);
    
        const {accessToken} = await generateAccessAndRefreshTokens(user._id);
        console.log(user);
    
        const loggedInUser = await User.findById(user._id)
        .select('-password');

        
        // save login activity in the database

        const loginActivity = new Activity({
            userId: loggedInUser._id,
            activityType: "login",
            deviceInfo: req.headers['user-agent'],
            timestamp: new Date()
        })

        await loginActivity.save();

        // Associate socket with user
        
        io.on('connection', (socket) => {
            associateSocketWithUser(loggedInUser._id, socket.id);
            const formattedTime = convertTimestamp(loginActivity.timestamp);
            socket.emit('login', {
                userId: loggedInUser._id,
                timestamp: formattedTime,
                activityType: 'login',
                username: loggedInUser.firstname,
                deviceInfo: loginActivity.deviceInfo
            });
        });

        // Respond to the client
        res.status(200).json(new ApiResponse(200, {
            loggedInUser,
            accessToken
        }, `${loggedInUser.firstname} logged in successfully!`));
    }
    catch(error){
        console.log(error);
    }
};

const twofactor = async (req, res) => {
    try{
        const user = req.user;
    
        const {code} = req.query;
    
        console.log(code);
        
        if(user.twoFA.enabled && !code){
            throw new ApiError(400, "Code Required");
        }
        
        if(user.twoFA.enabled){
            const verified = authenticator.check(code, user.twoFA.secret);

            console.log(verified)
            
            if(!verified){
                console.log(user, code)
                throw new ApiError("Invalid Code");
            }
        }

        // save login activity in the database

        const loginActivity = new Activity({
            userId: user._id,
            activityType: "login",
            deviceInfo: req.headers['user-agent'],
            timestamp: new Date()
        })

        await loginActivity.save();

        // Associate socket with user
        
        io.on('connection', (socket) => {
            associateSocketWithUser(user._id, socket.id);
            const formattedTime = convertTimestamp(loginActivity.timestamp);
            socket.emit('login', {
                userId: user._id,
                username: user.firstname,
                timestamp: formattedTime,
                activityType: 'two factor',
                deviceInfo: loginActivity.deviceInfo
            });
        });

        console.log(user)
    
        res.status(200).json(200, {}, "Two Factor Verified!");
    }
    catch(error){
        console.log(error);
    }
    
};

const logoutUser = async (req, res) => {
    try {
        const decodedUser = req.user;
    
        // console.log(decodedUser);
        const user = await User.findById(decodedUser._id).select('-password');
    
        await User.findByIdAndUpdate(user._id, 
            {
                $unset : {
                    refreshToken : 1,
                },
            },
            {
                new: true
            }
        )

        // save logout activity in the database

        const logoutActivity = new Activity({
            userId: user._id,
            activityType: "logout",
            deviceInfo: req.headers['user-agent'],
            timestamp: new Date()
        });

        await logoutActivity.save();

        io.on('connection', (socket) => {
            const formattedTime = convertTimestamp(logoutActivity.timestamp);
            socket.emit('logout', {
                userId: user._id,
                username: user.firstname,
                activityType: "logout",
                deviceInfo: req.headers['user-agent'],
                timestamp: formattedTime
            });
            // if (socketId) {
            // }
        });
        
        // res.clearCookie('token');
    
        res.status(200).json(new ApiResponse(200, {}, "User logged out successfully!"));
    } catch (error) {
        console.log(error);
    }
};

const sendEmail = async({email, emailType, userId}) => {
    try {
        // create a hased token
        const hashedToken = await bcrypt.hash(userId.toString(), 10)

        if (emailType === "VERIFY") {
            await User.findByIdAndUpdate(userId, 
                {verifyToken: hashedToken, verifyTokenExpiry: Date.now() + 3600000})
        } else if (emailType === "RESET"){
            await User.findByIdAndUpdate(userId, 
                {forgotPasswordToken: hashedToken, forgotPasswordTokenExpiry: Date.now() + 3600000})
        }

        console.log("hashed token: "+hashedToken);

        var transport = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.EMAIL,
                pass: process.env.PASSWORD
            }
        });


        const mailOptions = {
            from: process.env.EMAIL,
            to: email,
            subject: emailType === "VERIFY" ? "Verify your email" : "Reset your password",
            html: `<p>Click <a href="${process.env.DOMAIN}/verifyemail?token=${hashedToken}">here</a> to ${emailType === "VERIFY" ? "verify    your email" : "reset your password"} or copy and paste the link below in your browser. <br> ${process.env.DOMAIN}/verifyemail?token=${hashedToken}
            </p>`
        }

        const mailresponse = await transport.sendMail
        (mailOptions);
        return mailresponse;

    } catch (error) {
        throw new Error(error.message);
    }
}

const verifyEmail = asyncHandler(async (req, res) => {
    try{
        const {token} = req.query;

        console.log(token);

        const user = await User.findOne({verifyToken: token, verifyTokenExpiry: {$gt: Date.now()}});

        if(!user){
            throw new ApiError(404, "User not found");
        }

        user.isVerified = true;
        user.verifyToken = undefined;
        user.verifyTokenExpiry = undefined;

        await user.save();

        res.status(200).json(new ApiResponse(200, {}, "Email verified successfully!"));
    }
    catch(error){
        throw new ApiError(500, "Something went wrong while verifying the email"+error.message);
    }
});

const isVerified = asyncHandler(async (req, res) => {
    const {token} = req.query;

    if(!token){
        throw new ApiError(400, 'Unauthorized request');
    }

    const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

    console.log(decodedToken);
    
    const user = await User.findById(decodedToken._id).select('-password -refreshToken');

    if(!user){
        throw new ApiError(401, 'Invalid access token');
    }

    const verified = false;
    if(user.isVerified){
        verified = user.isVerified;
    }

    res.status(200).json(new ApiResponse(200, {verified}, "User verification status"));
});

const getUser = async (req, res) => {
    try{
        const decodedUser = req.user;

        // console.log("Socket ID "+ socketId);
    
        console.log(decodedUser);
        const user = await User.findById(decodedUser._id).select('-password');
    
        res.status(200).json(new ApiResponse(200, {user}, "Current User"));
    }
    catch(error){
        console.log(error);
    }
};

const generate_qrImage = asyncHandler(async (req, res) => {
    const decodedUser = req.user;

    const user = await User.findById(decodedUser._id).select('-password');

    const secret = authenticator.generateSecret();
    const uri = authenticator.keyuri(user._id, "2FA", secret);

    const image = await qrcode.toDataURL(uri);

    user.twoFA.secret = secret;
    await user.save();

    res
    .status(200)
    .json(new ApiResponse(200, {qrImage: image}, "Generated QR image"))
});

const setTwoFa = asyncHandler(async (req, res) => {
    const {code} = req.query;
    const decodedUser = req.user;

    console.log("hi"+code);
    console.log(decodedUser);
    
    const user = await User.findById(decodedUser._id).select('-password');
    
    const verified = authenticator.check(code, user.twoFA.secret);

    if(!verified){
        throw new ApiError(401, "Invalid Code");
    }

    user.twoFA.enabled = true;

    await user.save();

    res.status(200).json(new ApiResponse(200, {}, "Verification Successful!"));
});

export {registerUser, loginUser, logoutUser, verifyEmail, getUser, isVerified, generate_qrImage, setTwoFa, twofactor};