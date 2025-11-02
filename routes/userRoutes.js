const express = require('express');
const router = express.Router();
const {register, login, getProfile, getAllUsers,deleteUser} = require('../controllers/userControllers');
const {authorize,protect} = require('../middleware/auth');

// Register a new user
router.post('/register', register);
// Login user
router.post('/login', login);
// Get user profile
router.get('/me', protect, getProfile);
// Get all users (admin only)
router.get('/', protect, authorize('admin'), getAllUsers);
// Delete user by ID (admin only)
router.delete('/:id', protect, authorize('admin'), deleteUser);

module.exports = router;
