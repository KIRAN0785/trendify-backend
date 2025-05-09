import validator from "validator";
import bcrypt from "bcrypt";
import jwt from 'jsonwebtoken';
import userModel from "../models/userModel.js";
import nodemailer from 'nodemailer';


const createToken= (id) => {
    return jwt.sign({id},process.env.JWT_SECRET)
}

// route for user login
const loginUser = async (req, res) => {
    try{
        const { email, password} = req.body;
        // checking user already exists or not 
        const user = await userModel.findOne({email});
        if(!user){
            return res.json({success: false, message: "User doesn't exists"})
        }
    
        const isMatch = await bcrypt.compare(password, user.password);
        if(isMatch){
            const token = createToken(user._id)
            res.json({success:true,token})
        }else{
            res.json({ success:false, message: "Invalid credentials"})
        }
        

    } catch (error){
        console.log(error);
        res.json({ success:false, message:error.message})
    
     }
    }

    // forgot password
    const forgotPassword = async (req, res) => {
        try {
            const { email } = req.body;
    
            const user = await userModel.findOne({ email });
            if (!user) {
                return res.json({ success: false, message: "User not found with this email." });
            }
    
            // create transporter
            const transporter = nodemailer.createTransport({
                service: 'gmail',
                auth: {
                    user: process.env.SMTP_EMAIL,
                    pass: process.env.SMTP_PASS,
                }
            });
    
            // create a new random temporary password
            const tempPassword = Math.random().toString(36).slice(-8); // 8 characters
            const salt = await bcrypt.genSalt(10);
            const hashedPassword = await bcrypt.hash(tempPassword, salt);
    
            // update user's password in database
            user.password = hashedPassword;
            await user.save();
    
            // send email to user
            const mailOptions = {
                from: process.env.SMTP_EMAIL,
                to: email,
                subject: 'Password Reset - TrendifyNow',
                html: `
                    <h3>Password Reset</h3>
                    <p>Your temporary password is: <b>${tempPassword}</b></p>
                    <p>Please login using this password and change your password immediately.</p>
                `
            };
    
            await transporter.sendMail(mailOptions);
    
            res.json({ success: true, message: "Temporary password sent to your email." });
        } catch (error) {
            console.log(error);
            res.json({ success: false, message: error.message });
        }
    };
    

//route for user register
const registerUser = async (req,res) => {
 try{
    const {name, email, password} = req.body;
    // checking user already exists or not 
    const exists = await userModel.findOne({email});
    if(exists){
        return res.json({success:false, message:"User already exists"})
    }

    // validating email format & strong password
    if(!validator.isEmail(email)){
        return res.json({success:false, message:"Please enter a valid email"})

    }
    if(password.length < 8){
        return res.json({success:false, message:"Please enter a strong password"})

    }
    // hashing user password
    const salt = await bcrypt.genSalt(10)
    const hashedPassword = await bcrypt.hash(password,salt)

    const newUser = new userModel({
        name,
        email,
        password:hashedPassword
    })
    const user = await newUser.save() 
    const token = createToken(user._id)

    res.json({success:true,token})



 } catch (error){
    console.log(error);
    res.json({success:false,message:error.message})

 }
}

// Get user profile
const getUserProfile = async (req, res) => {
    try {
      const userId = req.userId; //  from middleware
      const user = await userModel.findById(userId).select('-password');
      
      if (!user) {
        return res.json({ success: false, message: 'User not found' });
      }
  
      res.json({ success: true, user });
    } catch (error) {
      console.error(error);
      res.json({ success: false, message: error.message });
    }
  };
  const changePassword = async (req, res) => {
    try {
      const userId = req.userId; // from middleware
      const { current, newPass } = req.body;
  
      if (!current || !newPass) {
        return res.json({ success: false, message: 'Please provide both current and new password.' });
      }
  
      const user = await userModel.findById(userId);
      if (!user) {
        return res.json({ success: false, message: 'User not found.' });
      }
  
      const isMatch = await bcrypt.compare(current, user.password);
      if (!isMatch) {
        return res.json({ success: false, message: 'Current password is incorrect.' });
      }
  
      if (newPass.length < 8) {
        return res.json({ success: false, message: 'New password must be at least 8 characters long.' });
      }
  
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(newPass, salt);
      user.password = hashedPassword;
      await user.save();
  
      res.json({ success: true, message: 'Password updated successfully.' });
    } catch (error) {
      console.error(error);
      res.json({ success: false, message: error.message });
    }
  };
  
  
  

//route for admin login
const adminLogin = async (req,res) => {
    try{
        const {email,password} = req.body
        if (email === process.env.ADMIN_EMAIL && password === process.env.ADMIN_PASSWORD){
            const token = jwt.sign(email+password,process.env.JWT_SECRET);
              res.json({success:true,token})
        }else {
            res.json({success:false,message:"Invalid credentials"})
        }

    } catch (error){
        console.log(error);
        res.json({success:false,message:error.message})
    }
}

export { loginUser, registerUser, adminLogin, forgotPassword,  getUserProfile, changePassword }
