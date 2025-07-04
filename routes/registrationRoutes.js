// routes/registrationRoutes.js - Defines routes for event registration management (student and admin side)

const express = require('express');
const router = express.Router(); // Create an Express router
const registrationController = require('../controllers/registrationController'); // Import the registration controller
const { protect, authorizeRoles } = require('../middleware/authMiddleware'); // Import middleware


router.get('/cancel', protect, authorizeRoles('student'), registrationController.getCancelRegistrationPage);
router.post('/cancel/:id', protect, authorizeRoles('student'), registrationController.cancelRegistration);
router.get('/list', protect, authorizeRoles('admin'), registrationController.listAllRegistrations);
router.get('/search', protect, authorizeRoles('admin'), registrationController.getSearchRegistrationsPage);
router.post('/search', protect, authorizeRoles('admin'), registrationController.searchRegistrationsByDate);


module.exports = router;

