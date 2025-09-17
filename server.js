// attendance-server/server.js

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const User = require('./models/User'); // Import the User Model (models/User.js)

const app = express();

// --- Configuration ---
const PORT = process.env.PORT || 5000;

// --- CORS Configuration (Fixes the Connection Refused Error) ---
// This is set to handle the common localhost/127.0.0.1 port variations
const allowedOrigins = [
    'http://localhost',
    'http://127.0.0.1:5500', // Example common Live Server port
    'http://localhost:5500' // Example common Live Server port
];

app.use(cors({
    origin: function (origin, callback) {
        // Allow requests with no origin (like mobile apps or postman)
        if (!origin) return callback(null, true);
        
        // If the origin is in our allowed list, allow it
        if (allowedOrigins.includes(origin)) {
            return callback(null, true);
        }
        
        // OR, if the origin starts with http://127.0.0.1: or http://localhost:, allow it
        if (origin.startsWith('http://127.0.0.1:') || origin.startsWith('http://localhost:')) {
            return callback(null, true);
        }

        return callback(new Error('The CORS policy for this site does not allow access from the specified Origin.'), false);
    },
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true,
    allowedHeaders: ['Content-Type', 'Authorization', 'x-auth-token'], 
}));

// Middleware
app.use(express.json()); // Allows parsing of JSON request bodies

// DB Connection
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('MongoDB connected successfully!'))
    .catch(err => console.error('DB Connection Error:', err));


// --- Authentication Middleware (for protecting routes) ---
const auth = (req, res, next) => {
    const token = req.header('x-auth-token') || req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
        return res.status(401).json({ message: 'No token, authorization denied' });
    }
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded.user; 
        next();
    } catch (e) {
        res.status(401).json({ message: 'Token is not valid' });
    }
};


// --- API Endpoints ---

// 1. REGISTER USER
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    try {
        let user = await User.findOne({ username });
        if (user) {
            return res.status(400).json({ message: 'User already exists' });
        }

        // Create a new user with default preferences
        user = new User({ 
            username, 
            password,
            preferences: {
                section: '1', 
                desiredAttendance: 75, 
                absentDates: [],
                studentHolidays: []
            }
        });

        // Hash password before saving
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(password, salt);
        await user.save(); 

        // Create and return JWT token
        const payload = { user: { id: user.id } };
        jwt.sign(
            payload,
            process.env.JWT_SECRET,
            { expiresIn: '5h' },
            (err, token) => {
                if (err) throw err;
                res.json({ token, userId: user.id, message: 'Registration successful' });
            }
        );
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// 2. LOGIN USER
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        let user = await User.findOne({ username });
        if (!user) {
            return res.status(400).json({ message: 'Invalid Credentials' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid Credentials' });
        }

        // Return JWT token on successful login
        const payload = { user: { id: user.id } };
        jwt.sign(
            payload,
            process.env.JWT_SECRET,
            { expiresIn: '5h' },
            (err, token) => {
                if (err) throw err;
                res.json({ token, userId: user.id, message: 'Login successful' });
            }
        );
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// 3. LOAD USER PREFERENCES (PROTECTED ROUTE)
app.get('/api/user/preferences/:userId', auth, async (req, res) => {
    try {
        if (req.user.id !== req.params.userId) {
            return res.status(403).json({ message: 'Access denied' });
        }
        
        const user = await User.findById(req.params.userId).select('preferences');
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.json(user.preferences);

    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// 4. SAVE USER PREFERENCES (PROTECTED ROUTE)
app.post('/api/user/preferences', auth, async (req, res) => {
    const userId = req.user.id; 
    const newPreferences = req.body;
    
    try {
        const user = await User.findByIdAndUpdate(
            userId,
            { $set: { preferences: newPreferences } },
            { new: true, runValidators: true }
        ).select('preferences');

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.json({ message: 'Preferences saved', preferences: user.preferences });
        
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});


// 5. TEMP ROUTES to serve the JSON files (for initial setup)
// In a real application, these files would be structured differently,
// but we include them here to avoid network errors on load.
const fs = require('fs');
const path = require('path');

app.get('/api/data/timetable', (req, res) => {
    const filePath = path.join(__dirname, '..', 'attendance-app', 'timetable.json');
    fs.readFile(filePath, (err, data) => {
        if (err) return res.status(500).json({ message: 'Could not load timetable data.' });
        res.setHeader('Content-Type', 'application/json');
        res.send(data);
    });
});

app.get('/api/data/holidays', (req, res) => {
    const filePath = path.join(__dirname, '..', 'attendance-app', 'holidays.json');
    fs.readFile(filePath, (err, data) => {
        if (err) return res.status(500).json({ message: 'Could not load holidays data.' });
        res.setHeader('Content-Type', 'application/json');
        res.send(data);
    });
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));