import { User } from "../models/user.model.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import getDataUri from "../utils/datauri.js";
import cloudinary from "../utils/cloudinary.js";

export const register = async (req, res) => {
    try {
        const { fullname, email, phoneNumber, password, role } = req.body;

        if (!fullname || !email || !phoneNumber || !password || !role) {
            return res.status(400).json({ message: "All fields are required.", success: false });
        }

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'A user with this email already exists.', success: false });
        }

        let profilePhoto = "";
        if (req.file) {
            const fileUri = getDataUri(req.file);
            const cloudResponse = await cloudinary.uploader.upload(fileUri.content);
            profilePhoto = cloudResponse.secure_url;
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        await User.create({
            fullname,
            email,
            phoneNumber,
            password: hashedPassword,
            role,
            profile: { profilePhoto }
        });

        return res.status(201).json({ message: "Account created successfully.", success: true });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: "Internal server error", success: false });
    }
};

export const login = async (req, res) => {
    try {
        const { email, password, role } = req.body;

        if (!email || !password || !role) {
            return res.status(400).json({ message: "All fields are required.", success: false });
        }

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: "Incorrect email or password.", success: false });
        }

        const isPasswordMatch = await bcrypt.compare(password, user.password);
        if (!isPasswordMatch) {
            return res.status(400).json({ message: "Incorrect email or password.", success: false });
        }

        if (role !== user.role) {
            return res.status(400).json({ message: "Account doesn't exist with the current role.", success: false });
        }

        const token = jwt.sign({ userId: user._id }, process.env.SECRET_KEY, { expiresIn: '1d' });

        return res.status(200)
            .cookie("token", token, { maxAge: 1 * 24 * 60 * 60 * 1000, httpOnly: true, sameSite: 'strict' })
            .json({
                message: `Welcome back ${user.fullname}`,
                user: {
                    _id: user._id,
                    fullname: user.fullname,
                    email: user.email,
                    phoneNumber: user.phoneNumber,
                    role: user.role,
                    profile: user.profile
                },
                success: true
            });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: "Internal server error", success: false });
    }
};

export const logout = async (req, res) => {
    try {
        return res.status(200).cookie("token", "", { maxAge: 0 }).json({ message: "Logged out successfully.", success: true });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: "Internal server error", success: false });
    }
};

export const updateProfile = async (req, res) => {
    try {
        const { fullname, email, phoneNumber, bio, skills } = req.body;
        
        let resumeUrl = "";
        let resumeOriginalName = "";

        if (req.file) {
            const fileUri = getDataUri(req.file);
            const cloudResponse = await cloudinary.uploader.upload(fileUri.content);
            resumeUrl = cloudResponse.secure_url;
            resumeOriginalName = req.file.originalname;
        }

        const userId = req.userId; // assuming authentication middleware sets req.userId
        let user = await User.findById(userId);

        if (!user) {
            return res.status(404).json({ message: "User not found.", success: false });
        }

        if (fullname) user.fullname = fullname;
        if (email) user.email = email;
        if (phoneNumber) user.phoneNumber = phoneNumber;
        if (bio) user.profile.bio = bio;
        if (skills) user.profile.skills = skills.split(",");

        if (resumeUrl) {
            user.profile.resume = resumeUrl;
            user.profile.resumeOriginalName = resumeOriginalName;
        }

        await user.save();

        return res.status(200).json({
            message: "Profile updated successfully.",
            user: {
                _id: user._id,
                fullname: user.fullname,
                email: user.email,
                phoneNumber: user.phoneNumber,
                role: user.role,
                profile: user.profile
            },
            success: true
        });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: "Internal server error", success: false });
    }
};
