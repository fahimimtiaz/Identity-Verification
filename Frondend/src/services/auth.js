// services/auth.js

export const setToken = (token) => {
  localStorage.setItem('token', token);
};

export const getToken = () => {
  return localStorage.getItem('token');
};

export const clearToken = () => {
  localStorage.removeItem('token');
};

// Function to set user data in local storage
export const setUserData = (userData) => {
  localStorage.setItem('userData', JSON.stringify(userData));
};

// Function to get user data from local storage
export const getUserData = () => {
  const userData = localStorage.getItem('userData');
  return userData ? JSON.parse(userData) : {};
};
