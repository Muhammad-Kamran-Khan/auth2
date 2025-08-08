import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { Toaster } from 'react-hot-toast';
import HomePage from './components/pages/Home'
import LoginPage from './components/pages/Login'
import RegisterPage from './components/pages/Register';
import ForgotPasswordPage from './components/pages/ForgotPassword';
import ResetPasswordPage from './components/pages/ResetPassword';
import VerifyEmailPage from './components/pages/VerifyEmail';
import UserProvider from './context/UserProvider';

function App() {
  return (
    <>
      <Router>
        {/* The Toaster and UserProvider wrap the entire application,
            similar to how they would in a Next.js RootLayout. */}
        <Toaster position="top-center" />
        <UserProvider>
          {/* React Router handles the routing. The 'children' from Next.js
              is replaced by the specific components for each route. */}
          <Routes>
            <Route path="/" element={<HomePage />} />
            <Route path="/login" element={<LoginPage />} />
            <Route path="/register" element={<RegisterPage />} />
            <Route path="/forgot-password" element={<ForgotPasswordPage />} />
            <Route path="/reset-password/:resetToken" element={<ResetPasswordPage />} />
            <Route path="/verify-email/:verificationToken" element={<VerifyEmailPage />} />
          </Routes>
        </UserProvider>
      </Router>
    </>
  );
}

export default App;
