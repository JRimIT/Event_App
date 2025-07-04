const express = require('express');
const router = express.Router();
const eventController = require('../controllers/eventController');
const { protect, authorizeRoles } = require('../middleware/authMiddleware');

router.get('/register', protect, authorizeRoles('student'), eventController.getRegisterEventPage);

router.post('/register/:id', protect, authorizeRoles('student'), eventController.registerForEvent);

module.exports = router;

