import express from 'express';
import dotenv from 'dotenv';
import connectDB from './db/connectDB.js';
import cookieParser from 'cookie-parser';
import userRoutes from './routes/userRoutes.js';
import postRoutes from "./routes/postRoutes.js";
import {v2 as cloudinary} from "cloudinary";
import cors from "cors";

dotenv.config();

connectDB();
const app = express();

const PORT = process.env.PORT || 5000;

cloudinary.config({
    cloud_name:process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret:process.env.CLOUDINARY_API_SECRET

});
app.use(cors({
    origin: "https://threads-frontend-two.vercel.app", // Allow only your frontend
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true 
}));

app.use(express.json({limit:"50mb"})); // parse json data in req.body
app.use(express.urlencoded({extended:true})); // parse for data in req.body
app.use(cookieParser());

// Routes 

app.use("/api/users",userRoutes);
app.use("/api/posts",postRoutes);

app.use((req, res, next) => {
    res.status(404).json({ error: "Route not found" });
}); 

app.get("/", (req, res) => {
    res.send("Threads Backend is Live 🎉");
});

app.listen(PORT,()=>{
    console.log(`server started at port number ${PORT}`);
})