import React from "react";
import { UserContextProvider } from "./userContext";

function UserProvider({ children }) {
  return <UserContextProvider>{children}</UserContextProvider>;
}

export default UserProvider;