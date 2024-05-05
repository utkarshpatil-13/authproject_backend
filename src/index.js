import mongoose from 'mongoose'
import dotenv from 'dotenv'
import express from 'express'
import cors from 'cors'
import cookieParser from 'cookie-parser'
import connectDB from './db/index.js'
import userRouter from './routes/user.routes.js'

import http from 'http'
import {Server} from 'socket.io'

const app = express()

// socket io server
const server = http.createServer(app);
const io = new Server(server);

dotenv.config({
    path: './.env'
})

// middlewares
const corsOptions = {
    origin: ['http://localhost:3000'],
    credentials: true,
    allowedHeaders: ['Content-Type', 'Authorization'], // Specify allowed headers
    methods: ['GET', 'POST', 'PUT', 'DELETE'], // Specify allowed methods
};
app.use(cors(corsOptions));
app.use(express.json({limit : '16kb'}))
app.use(express.urlencoded({limit: '16kb', extended: true}))
app.use(express.static('public'))
app.use(cookieParser())

// routes
app.use('/api/user', userRouter);

// connectDB
connectDB()
.then((res) => {
    app.listen(process.env.PORT, () => {
        console.log('Server is listening to the port', process.env.PORT);
    })

    app.on('error', (error) => {
        console.log('Error while connecting to the server', error);
    });
})
.catch((error) => {
    console.log('MongoDB connection problem !!!', error);
})

io.on('connection', (socket) => {
    console.log('A user connected');
})

export default io;