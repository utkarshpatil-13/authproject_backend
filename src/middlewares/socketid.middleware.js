import { asyncHandler } from "../utils/asyncHandler";


const extractSocketIdMiddleware = asyncHandler((req, res, next) => {
    // Extract the Socket ID from the headers
    const socketId = req.headers['x-socket-id']; // Assuming 'X-Socket-ID' is the custom header
    
    // Assign the Socket ID to the request object for further processing
    req.socketId = socketId;

    next();
});

export {extractSocketIdMiddleware};