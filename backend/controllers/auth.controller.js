import User from "../models/user.model.js";
import bcrypt from 'bcryptjs';
import { generateTokenAndSetCookie } from "../lib/utils/generateToken.js";


export const signup = async (req, res) => {
    try {
        const { fullName, username, email, password } = req.body;

        // Use .test() instead of .text() to check the email format
        const emailRegex = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

        if (!emailRegex.test(email)) {
            return res.status(400).json({ error: "Invalid email format" });
        }

        // Check if the username already exists
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ error: "Username is already taken" });
        }

        // Check if the email already exists
        const existingEmail = await User.findOne({ email });
        if (existingEmail) {
            return res.status(400).json({ error: "Email is already taken" });
        }

    
        if (password.length < 6)  {
            return res.status(400).json({ error: "Password must be at least 6 characters long" });
        }

        // Hash the password before saving
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create a new user
        const newUser = new User({
            fullName,
            username,
            email,
            password: hashedPassword,
        });

        if (newUser) {
            // If user is successfully created, generate the token and set the cookie
            generateTokenAndSetCookie(newUser._id, res);
            await newUser.save();

            // Return the user data as a response
            res.status(201).json({
                _id: newUser._id,
                fullName: newUser.fullName,
                username: newUser.username,
                email: newUser.email,
                followers: newUser.followers,
                following: newUser.following,
                profileImg: newUser.profileImg,
                coverImg: newUser.coverImg,
            });
        } else {
            res.status(400).json({ error: "Invalid user Data" });
        }
    } catch (error) {
        console.log("Error in signup controller", error.message);
        res.status(500).json({ error: "Internal Server Error" });
    }
};

export const login = async (req, res) => {
    try {
         const { username, password } = req.body;
 
         // Find the user by username
         const user = await User.findOne({ username });
 
         // If the user doesn't exist, or the password is incorrect
         const isPasswordCorrect = await bcrypt.compare(password, user?.password || "");
         if (!user || !isPasswordCorrect) {
             return res.status(400).json({ error: "Invalid username or password" });
         }
 
         // Generate the token and set the cookie
         generateTokenAndSetCookie(user._id, res);
 
         // Return the logged-in user data
         res.status(200).json({
             _id: user._id,
             fullName: user.fullName,
             username: user.username,
             email: user.email,
             followers: user.followers,
             following: user.following,
             profileImg: user.profileImg,
             coverImg: user.coverImg,
         });
 
    } catch (error) {
         console.log("Error in login controller", error.message);
         res.status(500).json({ error: "Internal Server Error" });
    }
 };
 

export const logout = async (req, res) => {
   try {
    res.cookie("jwt", "", {maxAge:0})
    res.status(200).json({message: "Logged out Successfully"})
   } catch (error) {
    console.log("Error in logout controller", error.message);
    res.status(500).json({ error: "Internal Server Error"});
    
   }
};


export const getMe = async (req, res) => {

    try {
        const user = await User.findById(req.user._id).select("-password");
        res.status(200).json(user);
    } catch (error) {
        console.log("Error in getMe controller", error.message);
        res.status(500).json({ error: "Internal server Error"});
        
    }
}
