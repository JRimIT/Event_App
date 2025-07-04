// models/eventModel.js - Defines the schema and model for event data

const mongoose = require('mongoose');

// Define the Event Schema
const eventSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, 'Event name is required'], // Event name is mandatory
        trim: true, // Remove whitespace from both ends of a string
        unique: true // Each event name must be unique (consider if multiple events can have same name)
    },
    description: {
        type: String,
        required: [true, 'Event description is required'], // Description is mandatory
        trim: true
    },
    date: {
        type: Date,
        required: [true, 'Event date is required'] // Event date is mandatory
    },
    location: {
        type: String,
        required: [true, 'Event location is required'], // Location is mandatory
        trim: true
    },
    capacity: {
        type: Number,
        required: [true, 'Event capacity is required'], // Capacity is mandatory
        min: [1, 'Capacity must be at least 1'], // Capacity must be a positive number
        default: 1
    },
    createdAt: {
        type: Date,
        default: Date.now // Automatically set creation date when a new event is created
    }
});

// Create the Event Model from the schema
const Event = mongoose.model('Event', eventSchema);

module.exports = Event;

