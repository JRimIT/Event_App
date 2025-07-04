// models/userModel.js - Defines the schema and model for user data

const mongoose = require('mongoose');
const bcrypt = require('bcryptjs'); // For password hashing

// Define the User Schema
const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: [true, 'Username is required'], // Username is mandatory
        unique: true, // Each username must be unique
        trim: true, // Remove whitespace from both ends of a string
        minlength: [3, 'Username must be at least 3 characters long'] // Minimum length validation
    },
    password: {
        type: String,
        required: [true, 'Password is required'], // Password is mandatory
        minlength: [6, 'Password must be at least 6 characters long'] // Minimum length validation
    },
    role: {
        type: String,
        enum: ['admin', 'student'], // Role must be either 'admin' or 'student'
        default: 'student', // Default role for new users is 'student'
        required: [true, 'User role is required'] // Role is mandatory
    },
    createdAt: {
        type: Date,
        default: Date.now 
    }
});


userSchema.pre('save', async function(next) {
    if (!this.isModified('password')) {
        return next(); 
    }

    try {

        const salt = await bcrypt.genSalt(10);
        // Hash the password using the generated salt
        this.password = await bcrypt.hash(this.password, salt);
        next(); 
    } catch (error) {
        next(error); 
    }
});


userSchema.methods.matchPassword = async function(enteredPassword) {
    return await bcrypt.compare(enteredPassword, this.password);
};

// Create the User Model from the schema
const User = mongoose.model('User', userSchema);

module.exports = User;

