import React from 'react';
import Navbar from './component/Navbar';
import { Outlet } from 'react-router-dom';

const Layout = () => {

  return (
    <>
      {/* <Navbar  /> */}
      <main>
        <Outlet /> 
      </main>
    </>
  );
};

export default Layout;
