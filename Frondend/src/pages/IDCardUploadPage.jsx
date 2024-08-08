import React, { useState } from 'react';
import { useHistory } from 'react-router-dom';
import { uploadIDCard } from '../services/api';
import { getToken } from '../services/auth';

const IDCardUploadPage = () => {
  const [idCard, setIdCard] = useState(null);
  const history = useHistory();

  const handleSubmit = async (event) => {
    event.preventDefault();

    const reader = new FileReader();
    reader.readAsDataURL(idCard);
    reader.onloadend = async () => {
      const idCardBase64 = reader.result;
      const token = getToken();

      try {
        const response = await uploadIDCard(idCardBase64, token);
        if (response.data.data.verification_status === 'Verified') {
          history.push('/tasks');
        }
      } catch (error) {
        alert('ID Card upload failed');
      }
    };
  };

  return (
    <div>
      <h1>Upload ID Card</h1>
      <form onSubmit={handleSubmit}>
        <input
          type="file"
          accept="image/*"
          onChange={(e) => setIdCard(e.target.files[0])}
          required
        />
        <button type="submit">Upload</button>
      </form>
    </div>
  );
};

export default IDCardUploadPage;
