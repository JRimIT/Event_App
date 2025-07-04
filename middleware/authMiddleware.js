// middleware/authMiddleware.js - Middleware for authentication and role-based access control

const jwt = require('jsonwebtoken');
const User = require('../models/userModel'); // Import the User model

// Middleware to protect routes (ensure user is logged in)
const protect = async (req, res, next) => {
    let token;

    // Check if the JWT token exists in cookies
    if (req.cookies.jwt) {
        token = req.cookies.jwt;
    }

    // If no token is found, return an unauthorized error
    if (!token) {
        // Set an error message to display on the login page
        res.locals.error = 'Not authorized, no token';
        // Redirect to login page
        return res.status(401).redirect('/auth/login');
    }

    try {
        // Verify the token using the secret key from environment variables
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        // Find the user by ID from the decoded token payload
        // Select '-password' to exclude the password field from the returned user object
        req.user = await User.findById(decoded.id).select('-password');

        // If user not found, token is invalid or user no longer exists
        if (!req.user) {
            res.locals.error = 'Not authorized, user not found';
            return res.status(401).redirect('/auth/login');
        }

        // Proceed to the next middleware or route handler
        next();
    } catch (error) {
        console.error('Token verification failed:', error);
        // Clear the invalid token from cookies
        res.clearCookie('jwt');
        res.locals.error = 'Not authorized, token failed';
        return res.status(401).redirect('/auth/login');
    }
};

// Middleware to restrict access based on user roles
const authorizeRoles = (...roles) => { // Accepts a variable number of roles (e.g., 'admin', 'student')
    return (req, res, next) => {
        // Check if the user's role is included in the allowed roles
        if (!roles.includes(req.user.role)) {
            // If not authorized, set an error message and redirect
            res.locals.error = `User role ${req.user.role} is not authorized to access this route`;
            // Depending on the context, you might redirect to a dashboard or a forbidden page
            // For this project, redirecting to login or a restricted view
            return res.status(403).render('error', { title: '403 Forbidden', message: res.locals.error });
        }
        // If authorized, proceed to the next middleware or route handler
        next();
    };
};

module.exports = { protect, authorizeRoles };

