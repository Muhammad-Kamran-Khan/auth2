import jwt from "jsonwebtoken";

//generate a JWT token on basis of user id
const generateToken = (id) => {
  return jwt.sign(
    {
     id
    },
    process.env.JWT_SECRET,
    {
      expiresIn: "30d",
    }
  );
}

export default generateToken;