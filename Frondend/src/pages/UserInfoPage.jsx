import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import { getToken } from '../services/auth';
import Navbar from '../component/Navbar';
import { BASE_URL } from '../services/api';

const UserInfoPage = () => {
  const [userInfo, setUserInfo] = useState(null);
  const navigate = useNavigate();

  useEffect(() => {
    const fetchUserInfo = async () => {
      try {
        const token = getToken();

        if (!token) {
          console.error('No token found');
          navigate('/login'); 
          return;
        }

        const response = await axios.post(
          BASE_URL + '/user-details', 
          {}, 
          {
            headers: {
              'Content-Type': 'application/json',
              'Authorization': `Bearer ${token}`, 
            },
          }
        );

        setUserInfo(response.data.data);
      } catch (error) {
        console.error('Error fetching user info:', error);
        if (error.response) {
          console.error('Error response data:', error.response.data); 
          console.error('Error response status:', error.response.status); 
          if (error.response.status === 403) {
            console.error('Authorization failed, redirecting to login...');
            navigate('/login'); 
          }
        } else {
          console.error('Error message:', error.message); 
        }
      }
    };

    fetchUserInfo();
  }, [navigate]);

  const handleSelfieUpload = () => {
    navigate('/selfie-upload');
  };

  if (!userInfo) {
    return <div className="flex justify-center items-center h-screen">Loading...</div>;
  }

  console.log('User Info:', userInfo);

  return (
    <>
    <Navbar  />
    <div className="min-h-screen bg-gray-100 flex flex-col items-center justify-center py-12">
      <div className="bg-white shadow-md rounded-lg p-8 w-full max-w-md">
        <h1 className="text-2xl font-bold mb-6 text-center">User Information</h1>
        <div className="mb-4">
          <p className="text-lg"><strong>Profile Picture:</strong></p>
          <img src={userInfo.selfie_url} alt="Profile" className="w-32 h-32 rounded-full mx-auto" />
        </div>
        <div className="mb-4">
          <p className="text-lg"><strong>ID Card:</strong></p>
          <img src={userInfo.id_url} alt="Profile" />
        </div>
        <div className="mb-4">
          <p className="text-lg"><strong>Full Name:</strong> {userInfo.full_name}</p>
        </div>
        <div className="mb-4">
          <p className="text-lg"><strong>Email:</strong> {userInfo.email}</p>
        </div>
        <div className="mb-4">
          <p className="text-lg"><strong>Verification Status:</strong> {userInfo.verification_status}</p>
        </div>
        {userInfo.verification_status === 'Pending' && (
          <button 
            onClick={handleSelfieUpload}
            className="w-full bg-blue-500 text-white py-2 rounded-full hover:bg-blue-600"
          >
            Upload Selfie for Verification
          </button>
        )}
      </div>
    </div>
    </>
  );
};

export default UserInfoPage;
