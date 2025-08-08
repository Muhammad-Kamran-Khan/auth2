import { useEffect } from 'react';
import { useUserContext } from '../context/userContext';
import { useNavigate } from 'react-router-dom';

export default function useRedirect(redirectPath) {
  // Correct the function name from fetchLoginStatus to userLoginStatus
  const { userLoginStatus } = useUserContext(); 
  const navigate = useNavigate();

  useEffect(() => {
    (async () => {
      if (!(await userLoginStatus())) { // Call the correct function
        navigate(redirectPath);
      }
    })();
  }, [redirectPath, userLoginStatus, navigate]);
}