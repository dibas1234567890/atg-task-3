// App.js
import logo from './logo.svg';
import './App.css';
import RegisterForm from './register';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import React, { useState, useEffect } from 'react';
import BlogForm from './blogpost';
import LoginForm from './login';
import CategoryForm from './category';
import BlogList from './BlogList';
import BlogsByCategory from "./BlogsByCategory";
import Navbar from './NavBar';
import Dashboard from './Dashboard';

function App() {



  
    const [isLoggedIn, setIsLoggedIn] = useState(false);

    useEffect(() => {
        const token = localStorage.getItem('access_token');
        setIsLoggedIn(!!token);
    }, []);

    const handleLogout = () => {
      localStorage.removeItem('access_token');
      localStorage.removeItem('refresh_token');
      setIsLoggedIn(false); 
      window.location.href = '/api/login';}

    return (
        <div className="App">
            <BrowserRouter>
                <Navbar isLoggedIn={isLoggedIn} handleLogout={handleLogout} />
                <Routes>
                    <Route path="/api/register" element={<RegisterForm />} />
                    <Route path="/api/login" element={<LoginForm />} />
                    <Route path="/api/blogpost" element={isLoggedIn ? <BlogForm /> : <Navigate to="/api/login" />} />
                    <Route path="/api/categories" element={isLoggedIn ? <CategoryForm /> : <Navigate to="/api/login" />} />
                    <Route path="/api/blogosphere" element={<BlogList />} />
                    <Route path="/api/patient_dashboard" element={ <Dashboard />} />

                    <Route path="/api/blogs_by_category/:category_id" element={<BlogsByCategory />} />
                </Routes>
            </BrowserRouter>
        </div>
    );
}

export default App;