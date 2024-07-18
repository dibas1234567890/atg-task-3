import React, { useState } from "react";
import axios from "axios";
import { useNavigate } from 'react-router-dom';

const RegisterForm = () => {
    const [error, setError] = useState('');
    const [formData, setFormData] = useState({
        first_name: '',
        last_name: '',
        profile_picture: null,
        username: '',
        email: '',
        password1: '',
        password2: '',
        address_line1: '',
        city: '',
        state: '',
        pincode: '',
        user_type: 'patient'
    });
    const navigate = useNavigate();

    const handleChange = (e) => {
        const { name, value } = e.target;
        setFormData({
            ...formData,
            [name]: value,
        });
    }

    const handleFileChange = (e) => {
        setFormData({
            ...formData,
            profile_picture: e.target.files[0]
        });
    }

    const handleSubmit = async (e) => {
        e.preventDefault();
    
        const formDataToSubmit = new FormData();
        Object.keys(formData).forEach(key => {
            formDataToSubmit.append(key, formData[key]);
        });
    
        try {
            const response = await axios.post('http://127.0.0.1:8000/api/register', formDataToSubmit, {
                headers: {
                    'Content-Type': 'multipart/form-data'
                }
            });
            navigate('/api/login'); 
        } catch (error) {
            if (error.response && error.response.data) {
                setError(Object.values(error.response.data).join(', '));
            } else {
                setError('An unexpected error occurred.');
            }
        }
    }
    
    return (
        <div className="container">
            <div className="row">
                <div className="col">
                    <div className="card">
                        <div className="card-header">
                            Registration Form
                        </div>
                        <div className="card-body">
                            {error && <div className="alert alert-danger">{error}</div>}
                            <form onSubmit={handleSubmit}>
                                <div>
                                    <label htmlFor="first_name">First Name</label>
                                    <input id="first_name" type="text" className="form-control" value={formData.first_name} name="first_name" onChange={handleChange} required />
                                </div>
                                <div>
                                    <label htmlFor="last_name">Last Name</label>
                                    <input id="last_name" type="text" className="form-control" value={formData.last_name} name="last_name" onChange={handleChange} required />
                                </div>
                                <div>
                                    <label htmlFor="profile_picture">Profile Picture</label>
                                    <input id="profile_picture" type="file" className="form-control" name="profile_picture" onChange={handleFileChange} />
                                </div>
                                <div>
                                    <label htmlFor="username">Username</label>
                                    <input id="username" type="text" className="form-control" value={formData.username} name="username" onChange={handleChange} required />
                                </div>
                                <div>
                                    <label htmlFor="email">Email</label>
                                    <input id="email" type="email" className="form-control" value={formData.email} name="email" onChange={handleChange} required />
                                </div>
                                <div>
                                    <label htmlFor="password1">Password</label>
                                    <input id="password1" type="password" className="form-control" value={formData.password1} name="password1" onChange={handleChange} required />
                                </div>
                                <div>
                                    <label htmlFor="password2">Confirm Password</label>
                                    <input id="password2" type="password" className="form-control" value={formData.password2} name="password2" onChange={handleChange} required />
                                </div>
                                <div>
                                    <label htmlFor="address_line1">Address Line 1</label>
                                    <input id="address_line1" type="text" className="form-control" value={formData.address_line1} name="address_line1" onChange={handleChange} required />
                                </div>
                                <div>
                                    <label htmlFor="city">City</label>
                                    <input id="city" type="text" className="form-control" value={formData.city} name="city" onChange={handleChange} required />
                                </div>
                                <div>
                                    <label htmlFor="state">State</label>
                                    <input id="state" type="text" className="form-control" value={formData.state} name="state" onChange={handleChange} required />
                                </div>
                                <div>
                                    <label htmlFor="pincode">Pincode</label>
                                    <input id="pincode" type="text" className="form-control" value={formData.pincode} name="pincode" onChange={handleChange} required />
                                </div>
                                <div>
                                    <label htmlFor="user_type">User Type</label>
                                    <select id="user_type" className="form-control" value={formData.user_type} name="user_type" onChange={handleChange} required>
                                        <option value="patient">Patient</option>
                                        <option value="doctor">Doctor</option>
                                    </select>
                                </div>
                                <div>
                                    <button type="submit" className="btn btn-primary">Register</button>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    )
}

export default RegisterForm;
