import User from "../models/userModel.js";
import jwt from "jsonwebtoken";

const protectRoute = async (req, res, next) => {
    try {
        let token = req.cookies.jwt; // Get token from cookies

        // If not found in cookies, check Authorization header
        if (!token && req.headers.authorization && req.headers.authorization.startsWith("Bearer")) {
            token = req.headers.authorization.split(" ")[1]; // Extract token from header
        }

        if (!token) {
            return res.status(401).json({ message: "Unauthorized - No token provided" });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.userId).select("-password");

        if (!user) {
            return res.status(401).json({ message: "Unauthorized - User not found" });
        }

        req.user = user;
        next();

    } catch (err) {
        console.log("Error in protect route:", err.message);
        return res.status(401).json({ message: "Unauthorized - Invalid token" });
    }
};

export default protectRoute;
    