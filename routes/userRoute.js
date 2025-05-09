import express from 'express';
import { loginUser, registerUser, adminLogin, forgotPassword,  getUserProfile, changePassword  } from '../controllers/userController.js';
import authUser from '../middleware/auth.js';


const userRouter = express.Router();

userRouter.post('/register', registerUser);
userRouter.post('/login', loginUser);
userRouter.post('/admin', adminLogin);
userRouter.post('/forgot-password', forgotPassword);
userRouter.get('/profile', authUser, getUserProfile); 
// userRouter.post('/change-password', authUser, changePassword);
userRouter.put('/change-password', authUser, changePassword);


export default userRouter;
