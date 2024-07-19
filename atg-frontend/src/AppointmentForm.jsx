import React, { useState } from 'react';
import axios from 'axios';

const AppointmentForm = ({ doctorId, onClose }) => {
    const [formData, setFormData] = useState({
        doctor: doctorId,
        speciality: '',
        date: '',
        start_time: '',
    });
    const [error, setError] = useState(null);
    const [success, setSuccess] = useState(null);

    const handleChange = (e) => {
        const { name, value } = e.target;
        setFormData({
            ...formData,
            [name]: value,
        });
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        try {
            const response = await axios.post('http://127.0.0.1:8000/api/appointments', formData, {
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${localStorage.getItem('access_token')}`
                },
            });
            setSuccess('Appointment booked successfully');
            setFormData({
                doctor: doctorId,
                speciality: '',
                date: '',
                start_time: '',
            });
        } catch (error) {
            setError('Failed to book appointment');
        }
    };

    return (
        <div className="container">
            <h2>Book an Appointment</h2>
            {success && <div className="alert alert-success">{success}</div>}
            {error && <div className="alert alert-danger">{error}</div>}
            <form onSubmit={handleSubmit}>
                <div className="form-group">
                    <label htmlFor="speciality">Speciality</label>
                    <input
                        id="speciality"
                        name="speciality"
                        type="text"
                        className="form-control"
                        value={formData.speciality}
                        onChange={handleChange}
                        required
                    />
                </div>
                <div className="form-group">
                    <label htmlFor="date">Date</label>
                    <input
                        id="date"
                        name="date"
                        type="date"
                        className="form-control"
                        value={formData.date}
                        onChange={handleChange}
                        required
                    />
                </div>
                <div className="form-group">
                    <label htmlFor="start_time">Start Time</label>
                    <input
                        id="start_time"
                        name="start_time"
                        type="time"
                        className="form-control"
                        value={formData.start_time}
                        onChange={handleChange}
                        required
                    />
                </div>
                <div className="mt-2">
                <button type="submit" className="btn mx-2  btn-primary">Confirm</button>
                <button type="button" className="btn btn-secondary" onClick={onClose}>Cancel</button>
                </div>
                
            </form>
        </div>
    );
};

export default AppointmentForm;
