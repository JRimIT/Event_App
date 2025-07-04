// controllers/registrationController.js - Handles event registration management logic for students and admins

const Registration = require('../models/registrationModel'); // Import Registration model
const Event = require('../models/eventModel');             // Import Event model
const User = require('../models/userModel');               // Import User model

// --- Student Specific Functions ---

// @desc    Display a list of events the student has registered for
// @route   GET /registrations/cancel
// @access  Private (Students only)
const getCancelRegistrationPage = async (req, res) => {
    try {
        const studentId = req.user._id; // Get the logged-in student's ID

        // Find all registrations for the current student
        // Populate event details (name, date) and student details (username)
        const registrations = await Registration.find({ studentId: studentId })
            .populate('eventId', 'name date') // Get 'name' and 'date' from the Event model
            .populate('studentId', 'username') // Get 'username' from the User model
            .sort({ registrationDate: -1 }); // Sort by most recent registration first

        res.render('cancelRegistration', {
            title: 'My Registrations',
            registrations: registrations,
            user: req.user, // Pass user info for navbar
            message: res.locals.message,
            error: res.locals.error
        });
    } catch (error) {
        console.error('Error fetching student registrations:', error);
        res.locals.error = 'Could not fetch your registrations. Please try again later.';
        res.status(500).render('cancelRegistration', {
            title: 'My Registrations',
            registrations: [],
            user: req.user,
            message: res.locals.message,
            error: res.locals.error
        });
    }
};

// @desc    Cancel a student's registration for an event
// @route   POST /registrations/cancel/:id
// @access  Private (Students only)
const cancelRegistration = async (req, res) => {
    const registrationId = req.params.id; // Get the registration ID from URL parameters
    const studentId = req.user._id;       // Get the logged-in student's ID

    try {
        // Find and delete the registration, ensuring it belongs to the current student
        const result = await Registration.deleteOne({ _id: registrationId, studentId: studentId });

        if (result.deletedCount === 0) {
            // If no document was deleted, it means either ID was wrong or it didn't belong to the student
            res.locals.error = 'Registration not found or you are not authorized to cancel it.';
            return res.status(404).redirect('/registrations/cancel');
        }

        res.locals.message = 'Registration cancelled successfully.';
        res.redirect('/registrations/cancel'); // Redirect back to the student's registrations list
    } catch (error) {
        console.error('Error cancelling registration:', error);
        res.locals.error = 'A server error occurred during cancellation. Please try again.';
        res.status(500).redirect('/registrations/cancel');
    }
};


const listAllRegistrations = async (req, res) => {
    const page = parseInt(req.query.page) || 1; // Current page number, default to 1
    const limit = parseInt(req.query.limit) || 10; // Number of registrations per page, default to 10
    const skip = (page - 1) * limit; // Number of documents to skip

    try {
        const totalRegistrations = await Registration.countDocuments({}); // Total count for pagination

        // Fetch registrations with pagination
        const registrations = await Registration.find({})
            .populate('studentId', 'username') // Populate student username
            .populate('eventId', 'name date') // Populate event name and date
            .sort({ registrationDate: -1 }) // Sort by most recent registration first
            .skip(skip)
            .limit(limit);

        const totalPages = Math.ceil(totalRegistrations / limit);

        res.render('listRegistrations', {
            title: 'All Event Registrations',
            registrations: registrations,
            currentPage: page,
            totalPages: totalPages,
            totalRegistrations: totalRegistrations,
            user: req.user, // Pass user info for navbar
            message: res.locals.message,
            error: res.locals.error
        });
    } catch (error) {
        console.error('Error fetching all registrations:', error);
        res.locals.error = 'Could not fetch registrations. Please try again later.';
        res.status(500).render('listRegistrations', {
            title: 'All Event Registrations',
            registrations: [],
            currentPage: 1,
            totalPages: 1,
            totalRegistrations: 0,
            user: req.user,
            message: res.locals.message,
            error: res.locals.error
        });
    }
};


const getSearchRegistrationsPage = (req, res) => {
    res.render('searchRegistrations', {
        title: 'Search Registrations by Date',
        registrations: [], // Initially empty
        user: req.user, // Pass user info for navbar
        message: res.locals.message,
        error: res.locals.error,
        startDate: '', // For pre-filling form
        endDate: ''    // For pre-filling form
    });
};


const searchRegistrationsByDate = async (req, res) => {
    const { startDate, endDate } = req.body; // Dates from form input

    // Basic validation for date format and presence
    if (!startDate || !endDate) {
        res.locals.error = 'Both start date and end date are required for search.';
        return res.status(400).render('searchRegistrations', {
            title: 'Search Registrations by Date',
            registrations: [],
            user: req.user,
            message: res.locals.message,
            error: res.locals.error,
            startDate: startDate,
            endDate: endDate
        });
    }

    const start = new Date(startDate);
    const end = new Date(endDate);
    end.setHours(23, 59, 59, 999); // Set end date to end of the day for inclusive search

    // Constraint: The start date must be earlier than the end date
    if (start >= end) {
        res.locals.error = 'Start date must be earlier than end date.';
        return res.status(400).render('searchRegistrations', {
            title: 'Search Registrations by Date',
            registrations: [],
            user: req.user,
            message: res.locals.message,
            error: res.locals.error,
            startDate: startDate,
            endDate: endDate
        });
    }

    try {
        // Find registrations within the date range
        const registrations = await Registration.find({
            registrationDate: {
                $gte: start, // Greater than or equal to start date
                $lte: end    // Less than or equal to end date
            }
        })
        .populate('studentId', 'username') // Populate student username
        .populate('eventId', 'name date') // Populate event name and date
        .sort({ registrationDate: 1 }); // Sort results by registration date ascending

        res.render('searchRegistrations', {
            title: 'Search Results',
            registrations: registrations,
            user: req.user,
            message: registrations.length === 0 ? 'No registrations found for the specified date range.' : '',
            error: '', // Clear any previous errors
            startDate: startDate,
            endDate: endDate
        });
    } catch (error) {
        console.error('Error searching registrations by date:', error);
        res.locals.error = 'A server error occurred during search. Please try valid dates and try again.';
        res.status(500).render('searchRegistrations', {
            title: 'Search Registrations by Date',
            registrations: [],
            user: req.user,
            message: res.locals.message,
            error: res.locals.error,
            startDate: startDate,
            endDate: endDate
        });
    }
};

module.exports = {
    getCancelRegistrationPage,
    cancelRegistration,
    listAllRegistrations,
    getSearchRegistrationsPage,
    searchRegistrationsByDate,
};

