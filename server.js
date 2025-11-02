import express from "express";
import cors from "cors";
import "dotenv/config";
import cookieParser from "cookie-parser";
import connectDB from "./confi/mongodb.js";
import authRoute from "./routes/authRoute.js";

const app = express();
app.use(express.json());
const port = process.env.PORT || 4000;
connectDB();
// API Endpoints

app.use(cookieParser());
app.use(cors({ credentials: true }));
app.get("/", (req, res) => res.send("API Working"));
app.use("/api", authRoute);
app.listen(port, () => console.log(`server started on PORT:${port}`));
