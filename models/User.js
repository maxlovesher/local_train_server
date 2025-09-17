// models/User.js
const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true
    },
    password: { // This will store the HASHED password
        type: String,
        required: true
    },
    // --- Preferences will be nested here, linked to the user ---
    preferences: {
        section: { type: String, default: '1' },
        desiredAttendance: { type: Number, default: 75 },
        absentDates: { type: [String], default: [] }, // Array of date strings
        studentHolidays: { type: [Object], default: [] } // Array of holiday objects
    },
    date: {
        type: Date,
        default: Date.now
    }
});

module.exports = mongoose.model('User', UserSchema);