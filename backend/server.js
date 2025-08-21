import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
dotenv.config();
import connect from './src/db/connect.js';
import userRoutes from './src/routes/userRoutes.js'
const app = express();

const port = process.env.PORT || 3000;

//middelwares
app.use(
  cors({
    origin: "https://auth2-sigma.vercel.app",
    credentials: true,
  })
);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

//routes
app.use("/api/v1", userRoutes);
   
//server function
const server = async () => {
  try {
    await connect();

    app.listen(port, () => {
      console.log('Server is running on port 3000');
    });
  } catch (error) {
    console.error('Error starting server:', error.message);
    process.exit(1);
  }
}

server();