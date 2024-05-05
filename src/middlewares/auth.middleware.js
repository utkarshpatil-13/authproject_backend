import jwt from 'jsonwebtoken'
import { asyncHandler } from '../utils/asyncHandler.js'
import User from '../models/user.models.js';
import { ApiError } from '../utils/ApiError.js';

const verifyJwt = asyncHandler(async (req, res, next) => {
    try {

        // console.log(req.cookies);

        const token = req.cookies.cookieToken || req.headers['authorization'].replace('Bearer ', '');

        // console.log(token);

        if(!token){
            throw new ApiError(400, 'Unauthorized request');
        }
    
        const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
   
        // console.log(decodedToken);
        
        const user = await User.findById(decodedToken._id).select('-password -refreshToken');
    
        // console.log(user);

        if(!user){
            throw new ApiError(401, 'Invalid access token');
        }
    
        req.user = user;
    
        next();
    } catch (error) {
        throw new ApiError(401, error);
    }
})

export {verifyJwt};