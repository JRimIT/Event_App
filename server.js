// server.js - Main entry point for the Event Management System

// Load environment variables from .env file
require('dotenv').config();

// Import necessary modules
const express = require('express');
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');
const path = require('path');

// Import routes
const authRoutes = require('./routes/authRoutes');
const eventRoutes = require('./routes/eventRoutes');
const registrationRoutes = require('./routes/registrationRoutes');

// Initialize Express app
const app = express();

// --- Database Connection ---
const mongoURI = process.env.MONGO_URI;

mongoose.connect(mongoURI)
    .then(() => console.log('MongoDB connected successfully!'))
    .catch(err => console.error('MongoDB connection error:', err));


app.use(express.static(path.join(__dirname, 'public')));


app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use((req, res, next) => {
    // A simple way to pass messages. In a real app, this would be more sophisticated.
    res.locals.message = '';
    res.locals.error = '';
    next();
});

// --- Route Handlers ---

// Use authentication routes for login/logout
app.use('/auth', authRoutes);
// Use event routes for event listing and registration (student view)
app.use('/events', eventRoutes);
// Use registration routes for managing registrations (student/admin)
app.use('/registrations', registrationRoutes);

// Root route - Redirect to login page initially
app.get('/', (req, res) => {
    res.redirect('/auth/login');
});

// --- Error Handling Middleware ---
// Catch-all for undefined routes
app.use((req, res, next) => {
    res.status(404).render('error', { title: '404 Not Found', message: 'The page you are looking for does not exist.' });
});

// General error handler
app.use((err, req, res, next) => {
    console.error(err.stack); // Log the error stack for debugging
    res.status(500).render('error', { title: '500 Server Error', message: 'Something went wrong on the server.' });
});

// --- Start the Server ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Access the application at http://localhost:${PORT}`);
});

