import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import { getToken, getUserData, setUserData } from '../services/auth';
import Navbar from '../component/Navbar';
import { BASE_URL } from '../services/api';

const SelfieUploadPage = () => {
  const [selfie, setSelfie] = useState(null);
  const navigate = useNavigate();

  const handleSubmit = async (event) => {
    event.preventDefault();

    const reader = new FileReader();
    reader.readAsDataURL(selfie);
    reader.onloadend = async () => {
      const selfieBase64 = reader.result.split(',')[1];
      const token = getToken();

      try {
        const response = await axios.post(
          BASE_URL + '/selfie-upload',
          { selfie: selfieBase64 },
          {
            headers: {
              Authorization: `Bearer ${token}`,
              'Content-Type': 'application/json',
            },
          }
        );

        const verificationStatus = response.data.data.verification_status;

        if (verificationStatus === 'Verified') {
          // Update the userData object with the new verification status
          const userData = getUserData();
          userData.verification_status = verificationStatus;
          setUserData(userData);

          navigate('/tasks');
        } else {
          alert('Selfie upload failed. Please try again.');
        }
      } catch (error) {
        console.error('Error uploading selfie:', error);
        alert('Selfie upload failed. Please try again.');
      }
    };
  };

  return (
    <>
    <Navbar  />
    <div className="flex justify-center items-center h-screen bg-gray-100">
      <div className="bg-white p-8 rounded shadow-md w-full max-w-md">
        <h1 className="text-2xl font-bold mb-6 text-center">Upload Selfie</h1>
        <form onSubmit={handleSubmit}>
          <div className="mb-4">
            <input
              type="file"
              accept="image/*"
              onChange={(e) => setSelfie(e.target.files[0])}
              required
              className="block w-full text-sm text-gray-500
                         file:mr-4 file:py-2 file:px-4
                         file:rounded-full file:border-0
                         file:text-sm file:font-semibold
                         file:bg-blue-50 file:text-blue-700
                         hover:file:bg-blue-100"
            />
          </div>
          <button
            type="submit"
            className="w-full bg-blue-500 text-white py-2 rounded-full hover:bg-blue-600"
          >
            Upload
          </button>
        </form>
      </div>
    </div>
    </>
  );
};

export default SelfieUploadPage;
