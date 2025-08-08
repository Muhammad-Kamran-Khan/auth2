import React from "react";
import Login from "../auth/Login";

function page() {
  return (
    <div className="auth-page w-full h-full flex justify-center items-center">
      <Login />
    </div>
  );
}

export default page;