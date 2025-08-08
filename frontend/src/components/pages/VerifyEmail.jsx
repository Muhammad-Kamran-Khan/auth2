import { useParams } from "react-router-dom";
import { useUserContext } from "../../context/userContext";

function VerifyEmailPage() {
  // Use the useParams hook to get the verificationToken from the URL
  const { verificationToken } = useParams();
  const { verifyUser } = useUserContext();

  return (
    <div className="w-full h-full flex flex-col justify-center items-center">
      <div className="bg-white flex flex-col justify-center gap-[1rem] px-[4rem] py-[2rem] rounded-md">
        <h1 className="text-[#999] text-[2rem]">Verify Your Account</h1>
        <button
          className="px-4 py-2 self-center bg-blue-500 text-white rounded-md hover:bg-blue-600 transition-colors"
          onClick={() => {
            verifyUser(verificationToken);
          }}
        >
          Verify
        </button>
      </div>
    </div>
  );
}

export default VerifyEmailPage;
