// controllers/eventController.js - Handles event-related logic for students

const Event = require('../models/eventModel'); // Import the Event model
const Registration = require('../models/registrationModel'); // Import the Registration model


const getRegisterEventPage = async (req, res) => {
    try {
        // Fetch all available events
        const events = await Event.find({}).sort({ date: 1 }); // Sort by date ascending

        // For each event, count the number of registered students
        const eventsWithRegistrationCounts = await Promise.all(events.map(async (event) => {
            const registeredCount = await Registration.countDocuments({ eventId: event._id });
            return {
                ...event.toObject(), // Convert Mongoose document to plain JavaScript object
                registeredCount: registeredCount,
                isFull: registeredCount >= event.capacity,
                isRegisteredByCurrentUser: await Registration.exists({ eventId: event._id, studentId: req.user._id })
            };
        }));

        res.render('registerEvent', {
            title: 'Register for Events',
            events: eventsWithRegistrationCounts,
            user: req.user, // Pass the authenticated user to the view
            message: res.locals.message, // Flash message success
            error: res.locals.error      // Flash message error
        });
    } catch (error) {
        console.error('Error fetching events for registration:', error);
        res.locals.error = 'Could not fetch events. Please try again later.';
        res.status(500).render('registerEvent', {
            title: 'Register for Events',
            events: [], // Pass empty array in case of error
            user: req.user,
            message: res.locals.message,
            error: res.locals.error
        });
    }
};


const registerForEvent = async (req, res) => {
    const eventId = req.params.id; // Get event ID from URL parameters
    const studentId = req.user._id; // Get student ID from authenticated user

    try {
        // 1. Check if the event exists
        const event = await Event.findById(eventId);
        if (!event) {
            res.locals.error = 'Event not found.';
            return res.status(404).redirect('/events/register');
        }

        // 2. Check if the event has reached maximum capacity
        const registeredCount = await Registration.countDocuments({ eventId: event._id });
        if (registeredCount >= event.capacity) {
            res.locals.error = 'Event has reached its maximum capacity. Cannot register.';
            return res.status(400).redirect('/events/register');
        }

        // 3. Check if the student has already registered for this event
        const existingRegistration = await Registration.findOne({ studentId, eventId });
        if (existingRegistration) {
            res.locals.error = 'You have already registered for this event.';
            return res.status(400).redirect('/events/register');
        }

        // 4. Create a new registration
        const newRegistration = await Registration.create({
            studentId,
            eventId
        });

        if (newRegistration) {
            res.locals.message = `Successfully registered for ${event.name}!`;
        } else {
            res.locals.error = 'Failed to register for the event.';
        }
        res.redirect('/events/register'); // Redirect back to the event list
    } catch (error) {
        console.error('Error registering for event:', error);
        res.locals.error = 'A server error occurred during registration. Please try again.';
        res.status(500).redirect('/events/register');
    }
};


module.exports = {
    getRegisterEventPage,
    registerForEvent,
};

