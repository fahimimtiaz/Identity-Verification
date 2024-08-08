import { Link } from "react-router-dom";

const Navbar = () => {
  const userData = JSON.parse(localStorage.getItem('userData'));

  
  const handleLogout = () => {
    localStorage.removeItem('userData');
    localStorage.removeItem('token');
    window.location.href = '/login'; 
  };

  return (
    <div className="navbar bg-base-100">
      <div className="navbar-start">
        <div className="dropdown">
          <div tabIndex={0} role="button" className="btn btn-ghost lg:hidden">
            <svg
              xmlns="http://www.w3.org/2000/svg"
              className="h-5 w-5"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth="2"
                d="M4 6h16M4 12h8m-8 6h16"
              />
            </svg>
          </div>
          <ul
            tabIndex={0}
            className="menu menu-sm dropdown-content bg-base-100 rounded-box z-[1] mt-3 w-52 p-2 shadow"
          >
            <li><Link to="/tasks">Task Management</Link></li>
            <li>
              <Link to="/userinfo">User Info</Link>
            </li>
          </ul>
        </div>
        <Link className="btn btn-ghost text-xl" to="/tasks">Task Management</Link>
      </div>
      <div className="navbar-center hidden lg:flex">
        <ul className="menu menu-horizontal px-1">
          <li><Link to="/tasks">Task Management</Link></li>
          <li><Link to="/userinfo">User Info</Link></li>
        </ul>
      </div>
      <div className="navbar-end">
        {userData ? (
          <button className="btn" onClick={handleLogout}>Logout</button>
        ) : (
          <Link className="btn" to="/login">Login</Link>
        )}
      </div>
    </div>
  );
};

export default Navbar;
