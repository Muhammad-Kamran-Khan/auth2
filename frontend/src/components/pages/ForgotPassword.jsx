import React from "react";
import ForgotPasswordForm from "../auth/ForgotPassword";

function page() {
  return (
    <div className="auth-page w-full h-full flex justify-center items-center">
      <ForgotPasswordForm />
    </div>
  );
}

export default page;