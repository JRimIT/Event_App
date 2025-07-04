// routes/authRoutes.js - Defines routes for authentication (login, logout)

const express = require('express');
const router = express.Router(); // Create an Express router
const authController = require('../controllers/authController'); // Import the authentication controller
const { protect } = require('../middleware/authMiddleware'); // Import protect middleware

router.get('/login', authController.getLoginPage);
router.post('/login', authController.loginUser);
router.get('/register', authController.getRegisterPage);
router.post('/register', authController.registerUser);
router.get('/logout', protect, authController.logoutUser);

module.exports = router;

