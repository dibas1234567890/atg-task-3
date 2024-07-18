import React, { useEffect, useState } from "react";
import axios from "axios";

const CategoryForm = () => {
    const [formData, setFormData] = useState({
        category_name: '',
        category_slug: '',
       
    });

    const [error, setError] = useState('');
    const [success, setSuccess] = useState('');

    useEffect(() => {
        setFormData(prevData => ({
            ...prevData,
            category_slug: generateSlug(prevData.category_name)
        }));
    }, [formData.category_name]);

    const handleChange = (e) => {
        const { name, value } = e.target;
        setFormData(prevData => ({
            ...prevData,
            [name]: value,
        }));
        
    };

    const generateSlug = (name) => {
        return name
            .toLowerCase()
            .trim()
            .replace(/ /g, '-')
            .replace(/[^\w-]+/g, '');
    };


    const handleSubmit = async (e) => {
        e.preventDefault();

        const token = localStorage.getItem('access_token'); 
        const csrfToken = await getCsrfToken();

        const dataToSubmit = {
            category_name: formData.category_name,
            category_slug: formData.category_slug,
        };

        try {
            const response = await axios.post('http://127.0.0.1:8000/api/categories', dataToSubmit, {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'X-CSRFToken': csrfToken,
                },
            });
            setSuccess("Category created successfully!");
            console.log("Category created:", response.data);
            setFormData({ category_name: '', category_slug: '' }); 
        } catch (error) {
            setError(error.response.data.detail || 'An error occurred');
        }
    };

    const getCsrfToken = async () => {
        try {
            const response = await axios.get('http://127.0.0.1:8000/api/csrf_token', {
                withCredentials: true
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
                        <div className="card-header">Create Category</div>
                        <div className="card-body">
                            {error && <div className="alert alert-danger">{error}</div>}
                            {success && <div className="alert alert-success">{success}</div>}
                            <form onSubmit={handleSubmit}>
                                <div>
                                    <label htmlFor="category_name">Category Name</label>
                                    <input
                                        id="category_name"
                                        type="text"
                                        className="form-control"
                                        value={formData.category_name}
                                        name="category_name"
                                        onChange={handleChange}
                                        required
                                    />
                                </div>
                                <div>
                                    <label htmlFor="category_slug">Category Slug - Auto Generated</label>
                                    <input
                                        id="category_slug"
                                        type="text"
                                        className="form-control"
                                        value={formData.category_slug}
                                        name="category_slug"
                                        readOnly={true}
                                    />
                                </div>
                                
                                <div className="mt-2">
                                    <button type="submit" className="btn btn-primary">Create Category</button>
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
