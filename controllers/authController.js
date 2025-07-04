// controllers/authController.js - Handles user authentication logic

const User = require('../models/userModel'); // Import the User model
const jwt = require('jsonwebtoken'); // For creating JSON Web Tokens

// Helper function to generate a JWT token
const generateToken = (id) => {
    return jwt.sign({ id }, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_LIFETIME, // Token expiry time (e.g., '1d' for 1 day)
    });
};

// @desc    Display login form
// @route   GET /auth/login
// @access  Public
const getLoginPage = (req, res) => {
    // Render the login EJS template.
    // res.locals.error will be available if set by middleware (e.g., 'Not authorized, no token')
    res.render('login', { title: 'Login' });
};

// @desc    Authenticate user & get token
// @route   POST /auth/login
// @access  Public
const loginUser = async (req, res) => {
    const { username, password } = req.body; // Extract username and password from request body

    // Simple validation: Check if both fields are provided
    if (!username || !password) {
        res.locals.error = 'Please enter both username and password'; // Set error message
        return res.status(400).render('login', { title: 'Login' }); // Re-render login page with error
    }

    try {
        // Find user by username in the database
        const user = await User.findOne({ username });

        // Check if user exists and if the provided password matches the stored hashed password
        if (user && (await user.matchPassword(password))) {
            // If credentials are correct, generate a JWT token
            const token = generateToken(user._id);

            // Set the JWT token as an HTTP-only cookie
            res.cookie('jwt', token, {
                httpOnly: true, // Prevents client-side JavaScript from accessing the cookie
                secure: process.env.NODE_ENV === 'production', // Send cookie only over HTTPS in production
                maxAge: 1000 * 60 * 60 * 24, // Cookie expires in 1 day (same as token lifetime)
                sameSite: 'Lax' // Protection against CSRF attacks
            });

            // Redirect based on user role
            if (user.role === 'admin') {
                // For admin, redirect to the list registrations page
                res.redirect('/registrations/list');
            } else {
                // For student, redirect to the register event page
                res.redirect('/events/register');
            }
        } else {
            // If credentials are incorrect
            res.locals.error = 'Invalid username or password'; // Set error message
            return res.status(401).render('login', { title: 'Login' }); // Re-render login page with error
        }
    } catch (error) {
        console.error('Login error:', error);
        res.locals.error = 'A server error occurred during login. Please try again.'; // Generic error
        return res.status(500).render('login', { title: 'Login' }); // Re-render login page with error
    }
};

// @desc    Register a new user (for initial setup, could be removed later)
// @route   GET /auth/register (optional, for initial user creation)
// @access  Public
const getRegisterPage = (req, res) => {
    res.render('register', { title: 'Register User' });
};

// @desc    Register a new user
// @route   POST /auth/register
// @access  Public (for initial setup)
const registerUser = async (req, res) => {
    const { username, password, role } = req.body;

    // Basic validation
    if (!username || !password || !role) {
        res.locals.error = 'Please enter all fields (username, password, role)';
        return res.status(400).render('register', { title: 'Register User' });
    }

    try {
        // Check if user already exists
        const userExists = await User.findOne({ username });
        if (userExists) {
            res.locals.error = 'User already exists with that username';
            return res.status(400).render('register', { title: 'Register User' });
        }

        // Create new user
        const user = await User.create({
            username,
            password,
            role
        });

        // If user created successfully, redirect to login or show success
        if (user) {
            res.locals.message = 'User registered successfully. Please log in.';
            res.redirect('/auth/login');
        } else {
            res.locals.error = 'Invalid user data';
            return res.status(400).render('register', { title: 'Register User' });
        }

    } catch (error) {
        console.error('Registration error:', error);
        // Handle Mongoose validation errors
        if (error.name === 'ValidationError') {
            const errors = Object.values(error.errors).map(err => err.message);
            res.locals.error = errors.join(', ');
        } else if (error.code === 11000) { // Duplicate key error
            res.locals.error = 'Username already exists.';
        } else {
            res.locals.error = 'A server error occurred during registration. Please try again.';
        }
        return res.status(500).render('register', { title: 'Register User' });
    }
};


// @desc    Log out user / clear cookie
// @route   GET /auth/logout
// @access  Private (but accessible after login)
const logoutUser = (req, res) => {
    // Clear the JWT cookie
    res.clearCookie('jwt');
    res.locals.message = 'You have been logged out successfully.';
    // Redirect to the login page
    res.redirect('/auth/login');
};

module.exports = {
    getLoginPage,
    loginUser,
    getRegisterPage, // Export for initial setup
    registerUser,    // Export for initial setup
    logoutUser,
};

