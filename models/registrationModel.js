// models/registrationModel.js - Defines the schema and model for event registrations

const mongoose = require('mongoose');

// Define the Registration Schema
const registrationSchema = new mongoose.Schema({
    studentId: {
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'User', 
        required: [true, 'Student ID is required'] 
    },
    eventId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Event', 
        required: [true, 'Event ID is required']
    },
    registrationDate: {
        type: Date,
        default: Date.now 
    }
});


registrationSchema.index({ studentId: 1, eventId: 1 }, { unique: true });


const Registration = mongoose.model('Registration', registrationSchema);

module.exports = Registration;

