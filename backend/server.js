import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
dotenv.config();
import connect from './src/db/connect.js';
import fs from 'node:fs';
const app = express();

const port = process.env.PORT || 3000;

//middelwares
app.use(
  cors({
    origin: "http://localhost:5173",
    credentials: true,
  })
);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

//routes
const routeFiles = fs.readdirSync("./src/routes");

routeFiles.forEach((file) => {
  // use dynamic import
  import(`./src/routes/${file}`)
    .then((route) => {
      app.use("/api/v1", route.default);
    })
    .catch((err) => {
      console.log("Failed to load route file", err);
    });
});

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