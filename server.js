// attendance-server/server.js

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

const User = require('./models/User'); // Mongoose User model

const app = express();
const PORT = process.env.PORT || 5000;

// --- CORS Configuration ---
app.use(cors({
    origin: function (origin, callback) {
        if (!origin) return callback(null, true);
        return callback(null, true); // allow all origins for simplicity
    },
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true,
    allowedHeaders: ['Content-Type', 'Authorization', 'x-auth-token'],
}));

// --- Middleware ---
app.use(express.json()); // Parse JSON bodies

// --- MongoDB Connection ---
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('MongoDB connected successfully!'))
    .catch(err => console.error('DB Connection Error:', err));

// --- Authentication Middleware ---
const auth = (req, res, next) => {
    const token = req.header('x-auth-token') || req.header('Authorization')?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ message: 'No token, authorization denied' });
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded.user;
        next();
    } catch (err) {
        res.status(401).json({ message: 'Token is not valid' });
    }
};

// --- User Routes ---

// Register
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    try {
        let user = await User.findOne({ username });
        if (user) return res.status(400).json({ message: 'User already exists' });

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        user = new User({
            username,
            password: hashedPassword,
            preferences: {
                section: '1',
                desiredAttendance: 75,
                absentDates: [],
                studentHolidays: [],
            }
        });

        await user.save();

        const payload = { user: { id: user.id } };
        jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '5h' }, (err, token) => {
            if (err) throw err;
            res.json({ token, userId: user.id, message: 'Registration successful' });
        });

    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// Login
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await User.findOne({ username });
        if (!user) return res.status(400).json({ message: 'Invalid Credentials' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ message: 'Invalid Credentials' });

        const payload = { user: { id: user.id } };
        jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '5h' }, (err, token) => {
            if (err) throw err;
            res.json({ token, userId: user.id, message: 'Login successful' });
        });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// Get user preferences
app.get('/api/user/preferences/:userId', auth, async (req, res) => {
    try {
        if (req.user.id !== req.params.userId) return res.status(403).json({ message: 'Access denied' });

        const user = await User.findById(req.params.userId).select('preferences');
        if (!user) return res.status(404).json({ message: 'User not found' });

        res.json(user.preferences);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// Save user preferences
app.post('/api/user/preferences', auth, async (req, res) => {
    try {
        const newPreferences = req.body;
        const user = await User.findByIdAndUpdate(
            req.user.id,
            { $set: { preferences: newPreferences } },
            { new: true, runValidators: true }
        ).select('preferences');

        if (!user) return res.status(404).json({ message: 'User not found' });

        res.json({ message: 'Preferences saved', preferences: user.preferences });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// --- JSON Data Routes ---
const timetablePath = path.join(__dirname, 'data', 'timetable.json');
const holidaysPath = path.join(__dirname, 'data', 'holidays.json');

app.get('/api/data/timetable', (req, res) => {
    fs.readFile(timetablePath, 'utf-8', (err, data) => {
        if (err) {
            console.error('Error reading timetable:', err);
            return res.status(500).json({ message: 'Could not load timetable data.' });
        }
        try {
            const jsonData = JSON.parse(data);
            res.json(jsonData);
        } catch (parseErr) {
            console.error('Error parsing timetable JSON:', parseErr);
            res.status(500).json({ message: 'Invalid timetable JSON format.' });
        }
    });
});

app.get('/api/data/holidays', (req, res) => {
    fs.readFile(holidaysPath, 'utf-8', (err, data) => {
        if (err) {
            console.error('Error reading holidays:', err);
            return res.status(500).json({ message: 'Could not load holidays data.' });
        }
        try {
            const jsonData = JSON.parse(data);
            res.json(jsonData);
        } catch (parseErr) {
            console.error('Error parsing holidays JSON:', parseErr);
            res.status(500).json({ message: 'Invalid holidays JSON format.' });
        }
    });
});

// --- Start Server ---
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
