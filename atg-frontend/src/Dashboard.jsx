import React, { useEffect, useState } from "react";
import axios from "axios";
import AppointmentForm from './AppointmentForm';

const Dashboard = () => {
    const [doctors, setDoctors] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const BASE_URL = 'http://127.0.0.1:8000'; 
    const [showForm, setShowForm] = useState(false);
    const [currentDoctorId, setCurrentDoctorId] = useState(null);

    const formClick = (id) => {
        setCurrentDoctorId(id);
        setShowForm(true);
    };

    const bookConfirmClick = () => {
        setShowForm(false);
    };

    useEffect(() => {
        const fetchDoctors = async () => {
            try {
                const token = localStorage.getItem('access_token');
                if (!token) {
                    throw new Error('No authentication token found');
                }

                const response = await axios.get('http://127.0.0.1:8000/api/patient_dashboard', {
                    headers: {
                        'Authorization': `Bearer ${token}`, 
                    }
                });

                console.log("API Response Data:", response.data);

                if (Array.isArray(response.data)) {
                    setDoctors(response.data);
                } else {
                    setError('Unexpected response format');
                }
            } catch (error) {
                console.error("API Error:", error.response || error.message);
                setError(error.response ? error.response.data.detail || error.message : error.message);
            } finally {
                setLoading(false);
            }
        };

        fetchDoctors();
    }, []);

    useEffect(() => {
        console.log("Updated doctors state:", doctors); 
    }, [doctors]); 

    if (loading) return <p>Loading...</p>;
    if (error) return <p>Error: {error}</p>;

    return (
        <div className="container ">
            <div className="row justify-content-center">
                <div className="col text-center"><h1 className="h1">Our Doctors</h1></div>
            </div>
            <div className="row justify-content-center">
                <div className="col-6 text-center">
                    <div className="container">
                        <div className="row">
                            {doctors.length > 0 ? (
                                <ul className="list-group">
                                    {doctors.map((doctor) => {
                                        const imageUrl = `${BASE_URL}${doctor.profile_picture}`;
                                        return (
                                            <li className="list-group-item" key={doctor.id}>
                                                <div>
                                                    <div className="card">
                                                        <div className="card-header">
                                                            <div className="rounded border-end-5">
                                                                <img className="rounded" src={imageUrl} alt={`${doctor.first_name}'s profile`} style={{ width: '100px', height: '100px' }} />
                                                            </div>
                                                            <div className="card-body">
                                                                <div className="h6">Name: {doctor.first_name} {doctor.last_name} <br /></div>
                                                                <a href={`mailto:${doctor.email}`}>Email: {doctor.email}</a>
                                                            </div>
                                                            <button onClick={() => formClick(doctor.id)} className="btn btn-dark">Book Appointment</button>
                                                        </div>
                                                    </div>
                                                </div>
                                                {showForm && currentDoctorId === doctor.id && (
                                                    <AppointmentForm doctorId={doctor.id} onClose={bookConfirmClick} />
                                                )}
                                            </li>
                                        );
                                    })}
                                </ul>
                            ) : (
                                <p>No doctors available</p>
                            )}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default Dashboard;
