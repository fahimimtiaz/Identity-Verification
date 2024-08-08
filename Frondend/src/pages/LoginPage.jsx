import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { loginUser } from '../services/api';
import { setToken, setUserData } from '../services/auth';
import { Link } from 'react-router-dom';
import "./styles.css";
import Navbar from '../component/Navbar';

const LoginPage = () => {
  const [values, setValues] = useState({
    email: '',
    password: ''
  });
  const [submitted, setSubmitted] = useState(false);
  const [valid, setValid] = useState(false);
  const navigate = useNavigate();

  const handleInputChange = (event) => {
    event.preventDefault();
    const { name, value } = event.target;
    setValues((values) => ({
      ...values,
      [name]: value
    }));
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    if (values.email && values.password) {
      setValid(true);
      try {
        const response = await loginUser(values);
        const { verification_status, token } = response.data;
        setToken(token);

        setUserData({ verification_status });

        switch (verification_status) {
          case 'Pending':
            navigate('/userinfo');
            break;
          case 'Failed':
            navigate('/selfie-upload');
            break;
          case 'Verified':
            navigate('/userinfo');
            break;
          default:
            break;
        }
      } catch (error) {
        alert('Login failed: ' + error.message);
      }
    } else {
      setValid(false);
    }
    setSubmitted(true);
  };

  return (
    <>
    <Navbar  />
    <section>
      <div className="flex items-center justify-center px-4 py-10 sm:px-6 sm:py-16 lg:px-8 lg:py-24">
        <div className="xl:mx-auto xl:w-full xl:max-w-sm 2xl:max-w-md">
          <h2 className="text-center text-2xl font-bold leading-tight text-black">
            Welcome Back!
          </h2>
          <p className="mt-2 text-center text-base text-gray-600">
            Don't have an account?{' '}
            <Link
              to="/"
              className="font-medium text-black transition-all duration-200 hover:underline"
            >
              Sign Up
            </Link>
          </p>
          <form className="mt-8" onSubmit={handleSubmit}>
            <div className="space-y-5">
              {submitted && valid && (
                <div className="success-message">
                  <h3>Welcome Back!</h3>
                  <div>Login successful. Redirecting...</div>
                </div>
              )}
              {!valid && (
                <>
                  <div>
                    <label htmlFor="email" className="text-base font-medium text-gray-900">
                      Email address
                    </label>
                    <div className="mt-2">
                      <input
                        className="flex h-10 w-full rounded-md border border-gray-300 bg-transparent px-3 py-2 text-sm placeholder:text-gray-400 focus:outline-none focus:ring-1 focus:ring-gray-400 focus:ring-offset-1 disabled:cursor-not-allowed disabled:opacity-50"
                        type="email"
                        name="email"
                        id="email"
                        value={values.email}
                        onChange={handleInputChange}
                        placeholder="Email"
                        required
                      />
                      {submitted && !values.email && (
                        <span className="text-red-600" id="email-error">Please enter an email address</span>
                      )}
                    </div>
                  </div>
                  <div>
                    <label htmlFor="password" className="text-base font-medium text-gray-900">
                      Password
                    </label>
                    <div className="mt-2">
                      <input
                        className="flex h-10 w-full rounded-md border border-gray-300 bg-transparent px-3 py-2 text-sm placeholder:text-gray-400 focus:outline-none focus:ring-1 focus:ring-gray-400 focus:ring-offset-1 disabled:cursor-not-allowed disabled:opacity-50"
                        type="password"
                        name="password"
                        id="password"
                        value={values.password}
                        onChange={handleInputChange}
                        placeholder="Password"
                        required
                      />
                      {submitted && !values.password && (
                        <span className="text-red-600" id="password-error">Please enter a password</span>
                      )}
                    </div>
                  </div>
                  <div>
                    <button
                      type="submit"
                      className="inline-flex w-full items-center justify-center rounded-md bg-black px-3.5 py-2.5 font-semibold leading-7 text-white hover:bg-black/80"
                    >
                      Login
                    </button>
                  </div>
                </>
              )}
            </div>
          </form>
        </div>
      </div>
    </section>
    </>
  );
};

export default LoginPage;
