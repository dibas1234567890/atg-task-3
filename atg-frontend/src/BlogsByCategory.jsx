import React, { useEffect, useState } from "react";
import axios from "axios";
import { useParams } from "react-router-dom";

const BlogsByCategory = () => {
    const { category_id } = useParams();
    const [blogs, setBlogs] = useState([]);
    const [error, setError] = useState('');

    useEffect(() => {
        const fetchBlogsByCategory = async () => {
            try {
                const token = localStorage.getItem('access_token');
                const response = await axios.get(`http://127.0.0.1:8000/api/blogs_by_category/${category_id}`, {
                    headers: {
                        'Authorization': `Bearer ${token}`
                    }
                });
                setBlogs(response.data);
            } catch (error) {
                setError('Error fetching blogs');
            }
        };

        fetchBlogsByCategory();
    }, [category_id]);

    return (
        <div className="container">
            {error && <div className="alert alert-danger">{error}</div>}
            <h2>Blogs in Category {category_id}</h2>
            <table className="table">
                <thead>
                    <tr>
                        <th>Title</th>
                        <th>Summary</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    {blogs.map(blog => (
                        <tr key={blog.id}>
                            <td>{blog.title}</td>
                            <td>{blog.summary}</td>
                            <td>{blog.status}</td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
};

export default BlogsByCategory;
