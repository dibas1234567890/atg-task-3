import React, { useState, useEffect } from "react";
import axios from "./axios_auth";

const DetailForm = () => {
    const token = localStorage.getItem('access_token');
   
    const [formData, setFormData] = useState({
        wood_species: '',
        quantity: '',
        dimension: '',
        total_amount: '',
        stamp_टाँचा_description: '',
        seal_description: '',
        remarks: '',
        anusuchi_cha_no: ''
    });
    
    const [options, setOptions] = useState([]);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');

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

    useEffect(() => {

        if(token === null){                   
            window.location.href = '/api/login'
            
        }
        else{
        
        const fetchDetails = async () => {
            setLoading(true);
            const csrfToken = await getCsrfToken();
            if (!csrfToken) return;

            try {
                const response = await axios.get('http://127.0.0.1:8000/api/detail_form', {
                    headers: {
                        'X-CSRFToken': csrfToken,
                        'Authorization': `Bearer ${token}`
                    },
                    withCredentials: true
                });
                setOptions(response.data);  
            } catch (error) {
                console.error('Error fetching details:', error);
                setError('Error fetching details');
            } finally {
                setLoading(false);
            }
        };

        fetchDetails();
 } }, [token]);

    const handleSubmit = async (e) => {
        e.preventDefault();
        const csrfToken = await getCsrfToken(); 

        if (!csrfToken) return;

        try {
            const postResponse = await axios.post('http://127.0.0.1:8000/api/detail_form', formData, {
                headers: {
                    'X-CSRFToken': csrfToken,
                    'Authorization': `Bearer ${token}`,
                },
                withCredentials: true,
            });

            console.log(postResponse.data);
            setFormData({
                wood_species: '',
                quantity: '',
                dimension: '',
                total_amount: '',
                stamp_टाँचा_description: '',
                seal_description: '',
                remarks: '',
                anusuchi_cha_no: '',
            });

        } catch (error) {
            console.error('Error submitting the form:', error);
            setError('There was an error submitting the form!');
        }
    };

    const handleChange = (e) => {
        setFormData({
            ...formData,
            [e.target.name]: e.target.value,
        });
    };

    return (
        <div className="container">
            <p className="h1">Detail Form</p>
            <div className="row">
                <div className="col">
                    <div className="card">
                        <div className="card-header">
                            Please Fill The Form Below
                        </div>
                        <div className="card-body">
                            <form className="form form-group" onSubmit={handleSubmit}>
                                <div>
                                    <label className="form-label">Wood Species:</label>
                                    <input className="form-control"
                                        type="text"
                                        name="wood_species"
                                        value={formData.wood_species}
                                        onChange={handleChange}
                                        required
                                    />
                                </div>
                                <div>
                                    <label>Quantity:</label>
                                    <input className="form-control"
                                        type="text"
                                        name="quantity"
                                        value={formData.quantity}
                                        onChange={handleChange}
                                        required
                                    />
                                </div>
                                <div>
                                    <label>Dimension:</label>
                                    <input className="form-control"
                                        type="text"
                                        name="dimension"
                                        value={formData.dimension}
                                        onChange={handleChange}
                                        required
                                    />
                                </div>
                                <div>
                                    <label>Total Amount:</label>
                                    <input className="form-control"
                                        type="number"
                                        name="total_amount"
                                        value={formData.total_amount}
                                        onChange={handleChange}
                                        required
                                    />
                                </div>
                                <div>
                                    <label>Stamp Description:</label>
                                    <input className="form-control"
                                        type="text"
                                        name="stamp_टाँचा_description"
                                        value={formData.stamp_टाँचा_description}
                                        onChange={handleChange}
                                        required
                                    />
                                </div>
                                <div>
                                    <label>Seal Description:</label>
                                    <input className="form-control"
                                        type="text"
                                        name="seal_description"
                                        value={formData.seal_description}
                                        onChange={handleChange}
                                        required
                                    />
                                </div>
                                <div>
                                    <label>Remarks:</label>
                                    <input className="form-control"
                                        type="text"
                                        name="remarks"
                                        value={formData.remarks}
                                        onChange={handleChange}
                                        required
                                    />
                                </div>
                                <div>
                                    <label>Anusuchi Form ID:</label>
                                    <select className="form-select"
                                        name="anusuchi_cha_no"
                                        value={formData.anusuchi_cha_no}
                                        onChange={handleChange}
                                        required
                                    >
                                        {options.map(option => (
                                            <option key={option.id} value={option.id}>
                                                {option.anusuchi_cha_no}
                                            </option>
                                        ))}
                                    </select>
                                </div>
                                <div className="div mt-2">
                                    <button type="submit" className="btn btn-primary">Submit</button>
                                </div>
                            </form>
                            {error && <p className="text-danger">{error}</p>} {/* Display error message if any */}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default DetailForm;
