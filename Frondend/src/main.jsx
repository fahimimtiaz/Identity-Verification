import ReactDOM from "react-dom/client";
import { createBrowserRouter, RouterProvider } from "react-router-dom";
import "./index.css";
import RegistrationPage from "./pages/RegistrationPage";
import LoginPage from "./pages/LoginPage";
import TaskManagementPage from "./pages/TaskManagementPage";
import UserInfoPage from "./pages/UserInfoPage"; 
import SelfieUploadPage from "./pages/SelfieUploadPage"; 
import Layout from "./Layout"; 
import Navbar from "./component/Navbar";

const router = createBrowserRouter([
  {
    path: "/",
    element: <Layout />, 
    children: [
      { path: "/", element: <RegistrationPage /> },
      { path: "/login", element: <LoginPage /> },
      { path: "/tasks", element: <TaskManagementPage /> },
      { path: "/userinfo", element: <UserInfoPage /> }, 
      { path: "/selfie-upload", element: <SelfieUploadPage /> }
    ]
  },
]);

ReactDOM.createRoot(document.getElementById('root')).render(
  <RouterProvider router={router} />
);
