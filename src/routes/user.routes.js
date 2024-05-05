import mongoose from "mongoose";
import { Router } from "express";
import { verifyJwt } from "../middlewares/auth.middleware.js";

import { getUser, isVerified, loginUser, logoutUser, registerUser, verifyEmail, generate_qrImage, setTwoFa, twofactor } from "../controllers/user.controllers.js";

const router = Router();

router.route('/register').post(registerUser);
router.route('/login').post(loginUser);
router.route('/logout').post(verifyJwt, logoutUser);
router.route('/verifyemail').get(verifyEmail);
router.route('/getuser').get(verifyJwt, getUser);
router.route('/isverified').post(isVerified);
router.route('/qrimage').post(verifyJwt, generate_qrImage);
router.route('/settwofa').post(verifyJwt, setTwoFa);
router.route('/twofactor').post(verifyJwt, twofactor);

export default router;