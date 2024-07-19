import React, { useEffect, useState } from "react";
import axios from "axios";
import { useNavigate } from "react-router-dom";

const BlogList = () => {
    const [blogs, setBlogs] = useState([]);
    const [userData, setUserData] = useState({});
    const [categoryData, setCategoryData] = useState({});
    const [error, setError] = useState('');
    const navigate = useNavigate();

    useEffect(() => {
        const fetchUserBlogs = async () => {
            try {
                const token = localStorage.getItem('access_token'); 
                const response = await axios.get('http://127.0.0.1:8000/api/blogs', {
                    headers: {
                        'Authorization': `Bearer ${token}`
                    }
                });
                setBlogs(response.data); 

                response.data.forEach(blog => {
                    fetchUserData(blog.user);
                    fetchCategoryData(blog.category);
                });
            } catch (error) {
                setError(`Error fetching blogs ${error.message}`); 
            }
        };
        fetchUserBlogs(); 
    }, []);

    const fetchUserData = async (userId) => {
        const token = localStorage.getItem('access_token'); 
        try {
            const response = await axios.get(`http://127.0.0.1:8000/api/user/${userId}`, {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });
            setUserData(prevState => ({
                ...prevState,
                [userId]: response.data
            }));
        } catch (error) {
            console.error('Error fetching user:', error);
        }
    };

    const fetchCategoryData = async (categoryId) => {
        const token = localStorage.getItem('access_token'); 
        try {
            const response = await axios.get(`http://127.0.0.1:8000/api/categories/${categoryId}`, {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });
            setCategoryData(prevState => ({
                ...prevState,
                [categoryId]: response.data
            }));
        } catch (error) {
            console.error('Error fetching category:', error);
        }
    };

    const truncateSummary = (summary) => {
        const words = summary.split(' ');
        return words.length > 15 ? words.slice(0, 15).join(' ') + '...' : summary; 
    };

    return (
        <div className="container">
            {error && <div className="alert alert-danger">{error}</div>} 
            <table className="table">
                <thead>
                    <tr>
                        <th>Title</th>
                        <th>Summary</th>
                        <th>Status</th>
                        <th>Category</th>
                        <th>Author</th>
                    </tr>
                </thead>
                <tbody>
                    {blogs.map(blog => (
                        <tr key={blog.id}>
                            <td>{blog.title}</td>
                            <td>{truncateSummary(blog.summary)}</td>
                            <td>{blog.status}</td> 
                            <td>
                                <a href="" onClick={() => navigate(`/api/blogs_by_category/${blog.category}`)}>
                                    {categoryData[blog.category]?.category_name || 'Unknown'}
                                </a>
                            </td>
                            <td>{userData[blog.user]?.username || 'Unknown'}</td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
};

export default BlogList;
