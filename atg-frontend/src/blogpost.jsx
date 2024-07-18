import React, { useEffect, useState } from "react";
import axios from "axios";

const CategoryForm = () => {
    const [formData, setFormData] = useState({
        title: '',
        image: null,
        category: '',
        summary: '',
        content: '',
        status: 'draft',
    });
    const [categories, setCategories] = useState([]);
    const [error, setError] = useState('');
    const [success, setSuccess] = useState('');

    useEffect(() => {
        const fetchCategories = async () => {
            try {
                const response = await axios.get('http://127.0.0.1:8000/api/categories');
                console.log(response.data)
                setCategories(response.data);
            } catch (error) {
                console.error('Error fetching categories:', error);
            }
        };
        fetchCategories();
    }, []);

    const handleChange = (e) => {
        const { name, value } = e.target;
        setFormData({
            ...formData,
            [name]: value,
        });
    };

    const handleFileChange = (e) => {
        setFormData({
            ...formData,
            image: e.target.files[0],
        });
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        
        const data = new FormData();
        data.append('title', formData.title);
        data.append('image', formData.image);
        data.append('category', formData.category); 
        data.append('summary', formData.summary);
        data.append('content', formData.content);
        data.append('status', formData.status);

        const token = localStorage.getItem('access_token'); 
        const csrfToken = await getCsrfToken();

        try {
            const response = await axios.post('http://127.0.0.1:8000/api/blogs', data, {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'X-CSRFToken': csrfToken,
                },
            });
            setSuccess("Blog created successfully!");
            console.log("Blog created:", response.data);
            setFormData({ title: '', image: null, category: '', summary: '', content: '', status: '' });
        } catch (error) {
            setError(error.response.data.detail || 'An error occurred');
        }
    };

    const getCsrfToken = async () => {
        try {
            const response = await axios.get('http://127.0.0.1:8000/api/csrf_token', {
                withCredentials: true,
            });
            return response.data.csrfToken;
        } catch (error) {
            console.error('Error fetching CSRF token:', error);
            setError('Error fetching CSRF token');
            return null;
        }
    };

    return (
        <div className="container">
            <div className="row">
                <div className="col">
                    <div className="card">
                        <div className="card-header">Create Blog</div>
                        <div className="card-body">
                            {error && <div className="alert alert-danger">{error}</div>}
                            {success && <div className="alert alert-success">{success}</div>}
                            <form onSubmit={handleSubmit}>
                                <div>
                                    <label htmlFor="title">Title</label>
                                    <input
                                        id="title"
                                        type="text"
                                        className="form-control"
                                        value={formData.title}
                                        name="title"
                                        onChange={handleChange}
                                        required
                                    />
                                </div>
                                <div>
                                    <label htmlFor="image">Image</label>
                                    <input
                                        id="image"
                                        type="file"
                                        className="form-control"
                                        name="image"
                                        onChange={handleFileChange}
                                        required
                                    />
                                </div>
                                <div>
                                    <label htmlFor="category">Category</label>
                                    <select
                                        id="category"
                                        className="form-control"
                                        value={formData.category}
                                        name="category"
                                        onChange={handleChange}
                                        required
                                    >
                                        <option value="">Select a category</option>
                                        {categories.map(category => (
                                            <option key={category.id} value={category.id}>
                                                {category.category_name}
                                            </option>
                                        ))}
                                    </select>
                                </div>
                                <div>
                                    <label htmlFor="summary">Summary</label>
                                    <textarea
                                        id="summary"
                                        className="form-control"
                                        value={formData.summary}
                                        name="summary"
                                        onChange={handleChange}
                                        required
                                    />
                                </div>
                                <div>
                                    <label htmlFor="content">Content</label>
                                    <textarea
                                        id="content"
                                        className="form-control"
                                        value={formData.content}
                                        name="content"
                                        onChange={handleChange}
                                        required
                                    />
                                </div>
                                <div>
                                    <label htmlFor="status">Status</label>
                                    <select
                                        id="status"
                                        className="form-control"
                                        value={formData.status}
                                        name="status"
                                        onChange={handleChange}
                                        required
                                    >
                                        <option value="">Select a status</option>
                                        <option value="draft">Draft</option>
                                        <option value="published">Published</option>
                                    </select>
                                </div>
                                <div className="mt-2">
                                    <button type="submit" className="btn btn-primary">Create Blog</button>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default CategoryForm;
