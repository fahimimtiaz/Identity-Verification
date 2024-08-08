import axios from 'axios';

// Base URLs
export const BASE_URL = import.meta.env.VITE_BASE_URL;


// Login
export const loginUser = async (userData) => {
  try {
    const response = await axios.post(`${BASE_URL}/user-login`, userData);
    return response.data;
  } catch (error) {
    console.error('Error logging in user:', error);
    throw error;
  }
};

// Fetch User Details
export const fetchUserDetails = async (token) => {
  try {
    const response = await axios.post(`${BASE_URL}/user-details`, {}, {
      headers: {
        Authorization: `Bearer ${token}`
      }
    });
    return response.data;
  } catch (error) {
    console.error('Error fetching user details:', error);
    throw error;
  }
};

// Upload Selfie
export const uploadSelfie = async (selfieData, token) => {
  try {
    const response = await axios.post(`${BASE_URL}/selfie-upload`, selfieData, {
      headers: {
        Authorization: `Bearer ${token}`
      }
    });
    return response.data;
  } catch (error) {
    console.error('Error uploading selfie:', error);
    throw error;
  }
};

// Task


const API_URL = BASE_URL + '/task';

export const getTasks = (token) => {
  return axios.get(API_URL, {
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });
};

export const createTask = (taskData, token) => {
  return axios.post(API_URL, taskData, {
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
  });
};

export const updateTask = (taskData, token) => {
  return axios.put(API_URL, taskData, {
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
  });
};

export const deleteTask = (taskId, token) => {
  return axios.delete(API_URL, {
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    data: { task_id: taskId },
  });
};
