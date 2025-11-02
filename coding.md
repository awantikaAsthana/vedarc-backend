# MERN STACK COMPLETE GUIDE FOR STUDENTS

## TABLE OF CONTENTS
1. Introduction to MERN Stack
2. Prerequisites & Environment Setup
3. MongoDB - Database Layer
4. Node.js & Express.js - Backend
5. React.js - Frontend
6. Full-Stack Integration
7. Authentication & Authorization
8. Advanced Topics
9. Deployment
10. Best Practices

---

## 1. INTRODUCTION TO MERN STACK

### What is MERN?
- **M**ongoDB - NoSQL Database
- **E**xpress.js - Backend Framework
- **R**eact.js - Frontend Library
- **N**ode.js - Runtime Environment

### Why MERN?
- Full JavaScript stack (frontend & backend)
- Fast development
- Large community support
- Scalable applications
- Single language throughout

---

## 2. PREREQUISITES & ENVIRONMENT SETUP

### Required Software:
```bash
# 1. Install Node.js (includes npm)
# Download from: https://nodejs.org/ (LTS version)

# Verify installation
node --version
npm --version

# 2. Install MongoDB
# Download from: https://www.mongodb.com/try/download/community

# 3. Install VS Code
# Download from: https://code.visualstudio.com/

# 4. Install Postman (for API testing)
# Download from: https://www.postman.com/
```

### VS Code Extensions:
- ES7+ React/Redux/React-Native snippets
- Prettier - Code formatter
- ESLint
- MongoDB for VS Code
- Thunder Client (alternative to Postman)

---

## 3. MONGODB - DATABASE LAYER

### Understanding MongoDB

**MongoDB Basics:**
```javascript
// Database → Collections → Documents

// Example Document Structure
{
  _id: ObjectId("507f1f77bcf86cd799439011"),
  name: "John Doe",
  email: "john@example.com",
  age: 25,
  createdAt: ISODate("2024-01-01T00:00:00Z")
}
```

### Installing Mongoose (ODM - Object Data Modeling)
```bash
npm install mongoose
```

### Connecting to MongoDB
```javascript
// config/database.js
const mongoose = require('mongoose');

const connectDB = async () => {
  try {
    const conn = await mongoose.connect('mongodb://localhost:27017/mern_app', {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log(`MongoDB Connected: ${conn.connection.host}`);
  } catch (error) {
    console.error(`Error: ${error.message}`);
    process.exit(1);
  }
};

module.exports = connectDB;
```

### Creating a Schema & Model
```javascript
// models/User.js
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Please add a name'],
    trim: true,
    maxlength: [50, 'Name cannot be more than 50 characters']
  },
  email: {
    type: String,
    required: [true, 'Please add an email'],
    unique: true,
    lowercase: true,
    match: [
      /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/,
      'Please add a valid email'
    ]
  },
  password: {
    type: String,
    required: [true, 'Please add a password'],
    minlength: 6,
    select: false // Don't return password by default
  },
  role: {
    type: String,
    enum: ['user', 'admin'],
    default: 'user'
  },
  isActive: {
    type: Boolean,
    default: true
  },
  profileImage: {
    type: String,
    default: 'default.jpg'
  }
}, {
  timestamps: true // Adds createdAt and updatedAt
});

module.exports = mongoose.model('User', userSchema);
```

### Advanced Schema Example (with relationships)
```javascript
// models/Post.js
const mongoose = require('mongoose');

const postSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
    trim: true
  },
  content: {
    type: String,
    required: true
  },
  author: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User', // Reference to User model
    required: true
  },
  tags: [{
    type: String
  }],
  likes: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],
  comments: [{
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    text: String,
    date: {
      type: Date,
      default: Date.now
    }
  }],
  status: {
    type: String,
    enum: ['draft', 'published', 'archived'],
    default: 'draft'
  }
}, {
  timestamps: true
});

// Index for better query performance
postSchema.index({ title: 'text', content: 'text' });

module.exports = mongoose.model('Post', postSchema);
```

---

## 4. NODE.JS & EXPRESS.JS - BACKEND

### Project Structure
```
backend/
├── config/
│   └── database.js
├── controllers/
│   ├── userController.js
│   └── postController.js
├── models/
│   ├── User.js
│   └── Post.js
├── routes/
│   ├── userRoutes.js
│   └── postRoutes.js
├── middleware/
│   ├── auth.js
│   └── errorHandler.js
├── utils/
│   └── helpers.js
├── .env
├── server.js
└── package.json
```

### Initialize Backend Project
```bash
# Create project directory
mkdir mern-app
cd mern-app
mkdir backend
cd backend

# Initialize npm
npm init -y

# Install dependencies
npm install express mongoose dotenv cors
npm install -D nodemon

# Security packages
npm install bcryptjs jsonwebtoken express-validator
npm install helmet express-rate-limit
```

### Package.json Configuration
```json
{
  "name": "mern-backend",
  "version": "1.0.0",
  "description": "MERN Stack Backend",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js"
  },
  "dependencies": {
    "express": "^4.18.2",
    "mongoose": "^8.0.0",
    "dotenv": "^16.3.1",
    "cors": "^2.8.5",
    "bcryptjs": "^2.4.3",
    "jsonwebtoken": "^9.0.2",
    "express-validator": "^7.0.1",
    "helmet": "^7.1.0",
    "express-rate-limit": "^7.1.5"
  },
  "devDependencies": {
    "nodemon": "^3.0.2"
  }
}
```

### Environment Variables (.env)
```env
NODE_ENV=development
PORT=5000
MONGO_URI=mongodb://localhost:27017/mern_app
JWT_SECRET=your_jwt_secret_key_here_make_it_long_and_random
JWT_EXPIRE=30d
```

### Main Server File
```javascript
// server.js
const express = require('express');
const dotenv = require('dotenv');
const cors = require('cors');
const helmet = require('helmet');
const connectDB = require('./config/database');
const errorHandler = require('./middleware/errorHandler');

// Load env vars
dotenv.config();

// Connect to database
connectDB();

const app = express();

// Middleware
app.use(express.json()); // Body parser
app.use(express.urlencoded({ extended: true }));
app.use(cors()); // Enable CORS
app.use(helmet()); // Security headers

// Routes
app.use('/api/users', require('./routes/userRoutes'));
app.use('/api/posts', require('./routes/postRoutes'));

// Welcome route
app.get('/', (req, res) => {
  res.json({ message: 'Welcome to MERN API' });
});

// Error handler (should be last)
app.use(errorHandler);

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Server running in ${process.env.NODE_ENV} mode on port ${PORT}`);
});
```

### Controllers (Business Logic)

**User Controller:**
```javascript
// controllers/userController.js
const User = require('../models/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// @desc    Register new user
// @route   POST /api/users/register
// @access  Public
exports.register = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Check if user exists
    let user = await User.findOne({ email });
    if (user) {
      return res.status(400).json({ 
        success: false, 
        message: 'User already exists' 
      });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create user
    user = await User.create({
      name,
      email,
      password: hashedPassword
    });

    // Create token
    const token = jwt.sign(
      { id: user._id }, 
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRE }
    );

    res.status(201).json({
      success: true,
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });

  } catch (error) {
    res.status(500).json({ 
      success: false, 
      message: error.message 
    });
  }
};

// @desc    Login user
// @route   POST /api/users/login
// @access  Public
exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate input
    if (!email || !password) {
      return res.status(400).json({ 
        success: false, 
        message: 'Please provide email and password' 
      });
    }

    // Check for user (include password)
    const user = await User.findOne({ email }).select('+password');
    
    if (!user) {
      return res.status(401).json({ 
        success: false, 
        message: 'Invalid credentials' 
      });
    }

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    
    if (!isMatch) {
      return res.status(401).json({ 
        success: false, 
        message: 'Invalid credentials' 
      });
    }

    // Create token
    const token = jwt.sign(
      { id: user._id }, 
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRE }
    );

    res.json({
      success: true,
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });

  } catch (error) {
    res.status(500).json({ 
      success: false, 
      message: error.message 
    });
  }
};

// @desc    Get current logged in user
// @route   GET /api/users/me
// @access  Private
exports.getMe = async (req, res) => {
  try {
    const user = await User.findById(req.user.id);

    res.json({
      success: true,
      data: user
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      message: error.message 
    });
  }
};

// @desc    Get all users
// @route   GET /api/users
// @access  Private/Admin
exports.getAllUsers = async (req, res) => {
  try {
    const users = await User.find().select('-password');

    res.json({
      success: true,
      count: users.length,
      data: users
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      message: error.message 
    });
  }
};

// @desc    Update user
// @route   PUT /api/users/:id
// @access  Private
exports.updateUser = async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(
      req.params.id,
      req.body,
      {
        new: true,
        runValidators: true
      }
    );

    if (!user) {
      return res.status(404).json({ 
        success: false, 
        message: 'User not found' 
      });
    }

    res.json({
      success: true,
      data: user
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      message: error.message 
    });
  }
};

// @desc    Delete user
// @route   DELETE /api/users/:id
// @access  Private/Admin
exports.deleteUser = async (req, res) => {
  try {
    const user = await User.findByIdAndDelete(req.params.id);

    if (!user) {
      return res.status(404).json({ 
        success: false, 
        message: 'User not found' 
      });
    }

    res.json({
      success: true,
      message: 'User deleted successfully'
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      message: error.message 
    });
  }
};
```

**Post Controller:**
```javascript
// controllers/postController.js
const Post = require('../models/Post');

// @desc    Get all posts
// @route   GET /api/posts
// @access  Public
exports.getAllPosts = async (req, res) => {
  try {
    // Pagination
    const page = parseInt(req.query.page, 10) || 1;
    const limit = parseInt(req.query.limit, 10) || 10;
    const startIndex = (page - 1) * limit;

    // Filtering
    const queryObj = { ...req.query };
    const excludeFields = ['page', 'limit', 'sort'];
    excludeFields.forEach(el => delete queryObj[el]);

    let query = Post.find(queryObj)
      .populate('author', 'name email')
      .skip(startIndex)
      .limit(limit);

    // Sorting
    if (req.query.sort) {
      const sortBy = req.query.sort.split(',').join(' ');
      query = query.sort(sortBy);
    } else {
      query = query.sort('-createdAt');
    }

    const posts = await query;
    const total = await Post.countDocuments();

    res.json({
      success: true,
      count: posts.length,
      total,
      page,
      pages: Math.ceil(total / limit),
      data: posts
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      message: error.message 
    });
  }
};

// @desc    Get single post
// @route   GET /api/posts/:id
// @access  Public
exports.getPost = async (req, res) => {
  try {
    const post = await Post.findById(req.params.id)
      .populate('author', 'name email')
      .populate('comments.user', 'name');

    if (!post) {
      return res.status(404).json({ 
        success: false, 
        message: 'Post not found' 
      });
    }

    res.json({
      success: true,
      data: post
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      message: error.message 
    });
  }
};

// @desc    Create post
// @route   POST /api/posts
// @access  Private
exports.createPost = async (req, res) => {
  try {
    req.body.author = req.user.id;

    const post = await Post.create(req.body);

    res.status(201).json({
      success: true,
      data: post
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      message: error.message 
    });
  }
};

// @desc    Update post
// @route   PUT /api/posts/:id
// @access  Private
exports.updatePost = async (req, res) => {
  try {
    let post = await Post.findById(req.params.id);

    if (!post) {
      return res.status(404).json({ 
        success: false, 
        message: 'Post not found' 
      });
    }

    // Check ownership
    if (post.author.toString() !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ 
        success: false, 
        message: 'Not authorized to update this post' 
      });
    }

    post = await Post.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
      runValidators: true
    });

    res.json({
      success: true,
      data: post
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      message: error.message 
    });
  }
};

// @desc    Delete post
// @route   DELETE /api/posts/:id
// @access  Private
exports.deletePost = async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);

    if (!post) {
      return res.status(404).json({ 
        success: false, 
        message: 'Post not found' 
      });
    }

    // Check ownership
    if (post.author.toString() !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ 
        success: false, 
        message: 'Not authorized to delete this post' 
      });
    }

    await post.deleteOne();

    res.json({
      success: true,
      message: 'Post deleted successfully'
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      message: error.message 
    });
  }
};

// @desc    Like post
// @route   PUT /api/posts/:id/like
// @access  Private
exports.likePost = async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);

    if (!post) {
      return res.status(404).json({ 
        success: false, 
        message: 'Post not found' 
      });
    }

    // Check if already liked
    if (post.likes.includes(req.user.id)) {
      // Unlike
      post.likes = post.likes.filter(
        like => like.toString() !== req.user.id
      );
    } else {
      // Like
      post.likes.push(req.user.id);
    }

    await post.save();

    res.json({
      success: true,
      data: post
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      message: error.message 
    });
  }
};

// @desc    Add comment
// @route   POST /api/posts/:id/comments
// @access  Private
exports.addComment = async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);

    if (!post) {
      return res.status(404).json({ 
        success: false, 
        message: 'Post not found' 
      });
    }

    const newComment = {
      user: req.user.id,
      text: req.body.text
    };

    post.comments.unshift(newComment);
    await post.save();

    res.json({
      success: true,
      data: post.comments
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      message: error.message 
    });
  }
};
```

### Routes

**User Routes:**
```javascript
// routes/userRoutes.js
const express = require('express');
const router = express.Router();
const {
  register,
  login,
  getMe,
  getAllUsers,
  updateUser,
  deleteUser
} = require('../controllers/userController');

const { protect, authorize } = require('../middleware/auth');

router.post('/register', register);
router.post('/login', login);
router.get('/me', protect, getMe);
router.get('/', protect, authorize('admin'), getAllUsers);
router.put('/:id', protect, updateUser);
router.delete('/:id', protect, authorize('admin'), deleteUser);

module.exports = router;
```

**Post Routes:**
```javascript
// routes/postRoutes.js
const express = require('express');
const router = express.Router();
const {
  getAllPosts,
  getPost,
  createPost,
  updatePost,
  deletePost,
  likePost,
  addComment
} = require('../controllers/postController');

const { protect } = require('../middleware/auth');

router.route('/')
  .get(getAllPosts)
  .post(protect, createPost);

router.route('/:id')
  .get(getPost)
  .put(protect, updatePost)
  .delete(protect, deletePost);

router.put('/:id/like', protect, likePost);
router.post('/:id/comments', protect, addComment);

module.exports = router;
```

### Middleware

**Authentication Middleware:**
```javascript
// middleware/auth.js
const jwt = require('jsonwebtoken');
const User = require('../models/User');

// Protect routes
exports.protect = async (req, res, next) => {
  let token;

  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer')
  ) {
    token = req.headers.authorization.split(' ')[1];
  }

  if (!token) {
    return res.status(401).json({ 
      success: false, 
      message: 'Not authorized to access this route' 
    });
  }

  try {
    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    req.user = await User.findById(decoded.id);

    if (!req.user) {
      return res.status(401).json({ 
        success: false, 
        message: 'User not found' 
      });
    }

    next();
  } catch (error) {
    return res.status(401).json({ 
      success: false, 
      message: 'Not authorized to access this route' 
    });
  }
};

// Grant access to specific roles
exports.authorize = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ 
        success: false, 
        message: `User role ${req.user.role} is not authorized to access this route` 
      });
    }
    next();
  };
};
```

**Error Handler Middleware:**
```javascript
// middleware/errorHandler.js
const errorHandler = (err, req, res, next) => {
  let error = { ...err };
  error.message = err.message;

  // Log to console for dev
  console.log(err);

  // Mongoose bad ObjectId
  if (err.name === 'CastError') {
    const message = 'Resource not found';
    error = { message, statusCode: 404 };
  }

  // Mongoose duplicate key
  if (err.code === 11000) {
    const message = 'Duplicate field value entered';
    error = { message, statusCode: 400 };
  }

  // Mongoose validation error
  if (err.name === 'ValidationError') {
    const message = Object.values(err.errors).map(val => val.message);
    error = { message, statusCode: 400 };
  }

  res.status(error.statusCode || 500).json({
    success: false,
    message: error.message || 'Server Error'
  });
};

module.exports = errorHandler;
```

---

## 5. REACT.JS - FRONTEND

### Create React App

```bash
# Navigate to project root
cd ..

# Create React app
npx create-react-app frontend
cd frontend

# Install dependencies
npm install axios react-router-dom
npm install @reduxjs/toolkit react-redux
npm install react-toastify
npm install bootstrap react-bootstrap
# OR
npm install @mui/material @emotion/react @emotion/styled
```

### Project Structure
```
frontend/
├── public/
├── src/
│   ├── components/
│   │   ├── common/
│   │   │   ├── Header.js
│   │   │   ├── Footer.js
│   │   │   └── Spinner.js
│   │   ├── posts/
│   │   │   ├── PostList.js
│   │   │   ├── PostItem.js
│   │   │   ├── PostForm.js
│   │   │   └── PostDetail.js
│   │   └── auth/
│   │       ├── Login.js
│   │       └── Register.js
│   ├── pages/
│   │   ├── Home.js
│   │   ├── Dashboard.js
│   │   └── Profile.js
│   ├── redux/
│   │   ├── store.js
│   │   ├── slices/
│   │   │   ├── authSlice.js
│   │   │   └── postSlice.js
│   ├── services/
│   │   ├── api.js
│   │   ├── authService.js
│   │   └── postService.js
│   ├── utils/
│   │   └── helpers.js
│   ├── App.js
│   ├── App.css
│   └── index.js
└── package.json
```

### API Configuration

```javascript
// src/services/api.js
import axios from 'axios';

const API_URL = 'http://localhost:5000/api';

const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json'
  }
});

// Request interceptor
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('token');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

export default api;
```

### Services

**Auth Service:**
```javascript
// src/services/authService.js
import api from './api';

const register = async (userData) => {
  const response = await api.post('/users/register', userData);
  if (response.data.token) {
    localStorage.setItem('token', response.data.token);
    localStorage.setItem('user', JSON.stringify(response.data.user));
  }
  return response.data;
};

const login = async (userData) => {
  const response = await api.post('/users/login', userData);
  if (response.data.token) {
    localStorage.setItem('token', response.data.token);
    localStorage.setItem('user', JSON.stringify(response.data.user));
  }
  return response.data;
};

const logout = () => {
  localStorage.removeItem('token');
  localStorage.removeItem('user');
};

const getCurrentUser = () => {
  return JSON.parse(localStorage.getItem('user'));
};

const authService = {
  register,
  login,
  logout,
  getCurrentUser
};

export default authService;
```

**Post Service:**
```javascript
// src/services/postService.js
import api from './api';

const getAllPosts = async (params) => {
  const response = await api.get('/posts', { params });
  return response.data;
};

const getPost = async (id) => {
  const response = await api.get(`/posts/${id}`);
  return response.data;
};

const createPost = async (postData) => {
  const response = await api.post('/posts', postData);
  return response.data;
};

const updatePost = async (id, postData) => {
  const response = await api.put(`/posts/${id}`, postData);
  return response.data;
};

const deletePost = async (id) => {
  const response = await api.delete(`/posts/${id}`);
  return response.data;
};

const likePost = async (id) => {
  const response = await api.put(`/posts/${id}/like`);
  return response.data;
};

const addComment = async (id, commentData) => {
  const response = await api.post(`/posts/${id}/comments`, commentData);
  return response.data;
};

const postService = {
  getAllPosts,
  getPost,
  createPost,
  updatePost,
  deletePost,
  likePost,
  addComment
};

export default postService;
```

### Redux Setup

**Store Configuration:**
```javascript
// src/redux/store.js
import { configureStore } from '@reduxjs/toolkit';
import authReducer from './slices/authSlice';
import postReducer from './slices/postSlice';

export const store = configureStore({
  reducer: {
    auth: authReducer,
    posts: postReducer
  }
});
```

**Auth Slice:**
```javascript
// src/redux/slices/authSlice.js
import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import authService from '../../services/authService';

const user = authService.getCurrentUser();

const initialState = {
  user: user || null,
  isLoading: false,
  isSuccess: false,
  isError: false,
  message: ''
};

// Register user
export const register = createAsyncThunk(
  'auth/register',
  async (userData, thunkAPI) => {
    try {
      return await authService.register(userData);
    } catch (error) {
      const message = error.response?.data?.message || error.message;
      return thunkAPI.rejectWithValue(message);
    }
  }
);

// Login user
export const login = createAsyncThunk(
  'auth/login',
  async (userData, thunkAPI) => {
    try {
      return await authService.login(userData);
    } catch (error) {
      const message = error.response?.data?.message || error.message;
      return thunkAPI.rejectWithValue(message);
    }
  }
);

// Logout user
export const logout = createAsyncThunk('auth/logout', async () => {
  authService.logout();
});

const authSlice = createSlice({
  name: 'auth',
  initialState,
  reducers: {
    reset: (state) => {
      state.isLoading = false;
      state.isSuccess = false;
      state.isError = false;
      state.message = '';
    }
  },
  extraReducers: (builder) => {
    builder
      // Register
      .addCase(register.pending, (state) => {
        state.isLoading = true;
      })
      .addCase(register.fulfilled, (state, action) => {
        state.isLoading = false;
        state.isSuccess = true;
        state.user = action.payload.user;
      })
      .addCase(register.rejected, (state, action) => {
        state.isLoading = false;
        state.isError = true;
        state.message = action.payload;
        state.user = null;
      })
      // Login
      .addCase(login.pending, (state) => {
        state.isLoading = true;
      })
      .addCase(login.fulfilled, (state, action) => {
        state.isLoading = false;
        state.isSuccess = true;
        state.user = action.payload.user;
      })
      .addCase(login.rejected, (state, action) => {
        state.isLoading = false;
        state.isError = true;
        state.message = action.payload;
        state.user = null;
      })
      // Logout
      .addCase(logout.fulfilled, (state) => {
        state.user = null;
      });
  }
});

export const { reset } = authSlice.actions;
export default authSlice.reducer;
```

**Post Slice:**
```javascript
// src/redux/slices/postSlice.js
import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import postService from '../../services/postService';

const initialState = {
  posts: [],
  post: null,
  isLoading: false,
  isSuccess: false,
  isError: false,
  message: '',
  total: 0,
  page: 1,
  pages: 1
};

// Get all posts
export const getPosts = createAsyncThunk(
  'posts/getAll',
  async (params, thunkAPI) => {
    try {
      return await postService.getAllPosts(params);
    } catch (error) {
      const message = error.response?.data?.message || error.message;
      return thunkAPI.rejectWithValue(message);
    }
  }
);

// Get single post
export const getPost = createAsyncThunk(
  'posts/getOne',
  async (id, thunkAPI) => {
    try {
      return await postService.getPost(id);
    } catch (error) {
      const message = error.response?.data?.message || error.message;
      return thunkAPI.rejectWithValue(message);
    }
  }
);

// Create post
export const createPost = createAsyncThunk(
  'posts/create',
  async (postData, thunkAPI) => {
    try {
      return await postService.createPost(postData);
    } catch (error) {
      const message = error.response?.data?.message || error.message;
      return thunkAPI.rejectWithValue(message);
    }
  }
);

// Update post
export const updatePost = createAsyncThunk(
  'posts/update',
  async ({ id, postData }, thunkAPI) => {
    try {
      return await postService.updatePost(id, postData);
    } catch (error) {
      const message = error.response?.data?.message || error.message;
      return thunkAPI.rejectWithValue(message);
    }
  }
);

// Delete post
export const deletePost = createAsyncThunk(
  'posts/delete',
  async (id, thunkAPI) => {
    try {
      await postService.deletePost(id);
      return id;
    } catch (error) {
      const message = error.response?.data?.message || error.message;
      return thunkAPI.rejectWithValue(message);
    }
  }
);

// Like post
export const likePost = createAsyncThunk(
  'posts/like',
  async (id, thunkAPI) => {
    try {
      return await postService.likePost(id);
    } catch (error) {
      const message = error.response?.data?.message || error.message;
      return thunkAPI.rejectWithValue(message);
    }
  }
);

const postSlice = createSlice({
  name: 'posts',
  initialState,
  reducers: {
    reset: (state) => {
      state.isLoading = false;
      state.isSuccess = false;
      state.isError = false;
      state.message = '';
    }
  },
  extraReducers: (builder) => {
    builder
      // Get all posts
      .addCase(getPosts.pending, (state) => {
        state.isLoading = true;
      })
      .addCase(getPosts.fulfilled, (state, action) => {
        state.isLoading = false;
        state.isSuccess = true;
        state.posts = action.payload.data;
        state.total = action.payload.total;
        state.page = action.payload.page;
        state.pages = action.payload.pages;
      })
      .addCase(getPosts.rejected, (state, action) => {
        state.isLoading = false;
        state.isError = true;
        state.message = action.payload;
      })
      // Get single post
      .addCase(getPost.pending, (state) => {
        state.isLoading = true;
      })
      .addCase(getPost.fulfilled, (state, action) => {
        state.isLoading = false;
        state.isSuccess = true;
        state.post = action.payload.data;
      })
      .addCase(getPost.rejected, (state, action) => {
        state.isLoading = false;
        state.isError = true;
        state.message = action.payload;
      })
      // Create post
      .addCase(createPost.pending, (state) => {
        state.isLoading = true;
      })
      .addCase(createPost.fulfilled, (state, action) => {
        state.isLoading = false;
        state.isSuccess = true;
        state.posts.unshift(action.payload.data);
      })
      .addCase(createPost.rejected, (state, action) => {
        state.isLoading = false;
        state.isError = true;
        state.message = action.payload;
      })
      // Update post
      .addCase(updatePost.fulfilled, (state, action) => {
        state.isLoading = false;
        state.isSuccess = true;
        const index = state.posts.findIndex(
          post => post._id === action.payload.data._id
        );
        if (index !== -1) {
          state.posts[index] = action.payload.data;
        }
      })
      // Delete post
      .addCase(deletePost.fulfilled, (state, action) => {
        state.isLoading = false;
        state.isSuccess = true;
        state.posts = state.posts.filter(
          post => post._id !== action.payload
        );
      })
      // Like post
      .addCase(likePost.fulfilled, (state, action) => {
        const index = state.posts.findIndex(
          post => post._id === action.payload.data._id
        );
        if (index !== -1) {
          state.posts[index] = action.payload.data;
        }
        if (state.post?._id === action.payload.data._id) {
          state.post = action.payload.data;
        }
      });
  }
});

export const { reset } = postSlice.actions;
export default postSlice.reducer;
```

### React Components

**App.js:**
```javascript
// src/App.js
import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { ToastContainer } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';

import Header from './components/common/Header';
import Footer from './components/common/Footer';
import Home from './pages/Home';
import Login from './components/auth/Login';
import Register from './components/auth/Register';
import Dashboard from './pages/Dashboard';
import Profile from './pages/Profile';
import PostDetail from './components/posts/PostDetail';
import PrivateRoute from './components/common/PrivateRoute';

function App() {
  return (
    <Router>
      <div className="App">
        <Header />
        <main className="container my-4">
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/login" element={<Login />} />
            <Route path="/register" element={<Register />} />
            <Route path="/posts/:id" element={<PostDetail />} />
            
            {/* Private Routes */}
            <Route path="/dashboard" element={
              <PrivateRoute>
                <Dashboard />
              </PrivateRoute>
            } />
            <Route path="/profile" element={
              <PrivateRoute>
                <Profile />
              </PrivateRoute>
            } />
          </Routes>
        </main>
        <Footer />
        <ToastContainer />
      </div>
    </Router>
  );
}

export default App;
```

**Index.js:**
```javascript
// src/index.js
import React from 'react';
import ReactDOM from 'react-dom/client';
import { Provider } from 'react-redux';
import { store } from './redux/store';
import App from './App';
import 'bootstrap/dist/css/bootstrap.min.css';
import './index.css';

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <React.StrictMode>
    <Provider store={store}>
      <App />
    </Provider>
  </React.StrictMode>
);
```

**Header Component:**
```javascript
// src/components/common/Header.js
import React from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useSelector, useDispatch } from 'react-redux';
import { logout } from '../../redux/slices/authSlice';
import { Navbar, Nav, Container, Button } from 'react-bootstrap';

const Header = () => {
  const navigate = useNavigate();
  const dispatch = useDispatch();
  const { user } = useSelector((state) => state.auth);

  const handleLogout = () => {
    dispatch(logout());
    navigate('/login');
  };

  return (
    <Navbar bg="dark" variant="dark" expand="lg">
      <Container>
        <Navbar.Brand as={Link} to="/">
          MERN App
        </Navbar.Brand>
        <Navbar.Toggle aria-controls="basic-navbar-nav" />
        <Navbar.Collapse id="basic-navbar-nav">
          <Nav className="me-auto">
            <Nav.Link as={Link} to="/">Home</Nav.Link>
            {user && (
              <Nav.Link as={Link} to="/dashboard">Dashboard</Nav.Link>
            )}
          </Nav>
          <Nav>
            {user ? (
              <>
                <Nav.Link as={Link} to="/profile">
                  {user.name}
                </Nav.Link>
                <Button 
                  variant="outline-light" 
                  size="sm" 
                  onClick={handleLogout}
                >
                  Logout
                </Button>
              </>
            ) : (
              <>
                <Nav.Link as={Link} to="/login">Login</Nav.Link>
                <Nav.Link as={Link} to="/register">Register</Nav.Link>
              </>
            )}
          </Nav>
        </Navbar.Collapse>
      </Container>
    </Navbar>
  );
};

export default Header;
```

**Login Component:**
```javascript
// src/components/auth/Login.js
import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useSelector, useDispatch } from 'react-redux';
import { login, reset } from '../../redux/slices/authSlice';
import { toast } from 'react-toastify';
import { Form, Button, Card } from 'react-bootstrap';

const Login = () => {
  const [formData, setFormData] = useState({
    email: '',
    password: ''
  });

  const { email, password } = formData;

  const navigate = useNavigate();
  const dispatch = useDispatch();

  const { user, isLoading, isError, isSuccess, message } = useSelector(
    (state) => state.auth
  );

  useEffect(() => {
    if (isError) {
      toast.error(message);
    }

    if (isSuccess || user) {
      navigate('/dashboard');
    }

    dispatch(reset());
  }, [user, isError, isSuccess, message, navigate, dispatch]);

  const onChange = (e) => {
    setFormData((prevState) => ({
      ...prevState,
      [e.target.name]: e.target.value
    }));
  };

  const onSubmit = (e) => {
    e.preventDefault();

    const userData = {
      email,
      password
    };

    dispatch(login(userData));
  };

  if (isLoading) {
    return <div>Loading...</div>;
  }

  return (
    <div className="row justify-content-center">
      <div className="col-md-6">
        <Card>
          <Card.Body>
            <h2 className="text-center mb-4">Login</h2>
            <Form onSubmit={onSubmit}>
              <Form.Group className="mb-3">
                <Form.Label>Email</Form.Label>
                <Form.Control
                  type="email"
                  name="email"
                  value={email}
                  onChange={onChange}
                  placeholder="Enter email"
                  required
                />
              </Form.Group>

              <Form.Group className="mb-3">
                <Form.Label>Password</Form.Label>
                <Form.Control
                  type="password"
                  name="password"
                  value={password}
                  onChange={onChange}
                  placeholder="Enter password"
                  required
                />
              </Form.Group>

              <Button variant="primary" type="submit" className="w-100">
                Login
              </Button>
            </Form>
          </Card.Body>
        </Card>
      </div>
    </div>
  );
};

export default Login;
```

**Register Component:**
```javascript
// src/components/auth/Register.js
import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useSelector, useDispatch } from 'react-redux';
import { register, reset } from '../../redux/slices/authSlice';
import { toast } from 'react-toastify';
import { Form, Button, Card } from 'react-bootstrap';

const Register = () => {
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    password: '',
    confirmPassword: ''
  });

  const { name, email, password, confirmPassword } = formData;

  const navigate = useNavigate();
  const dispatch = useDispatch();

  const { user, isLoading, isError, isSuccess, message } = useSelector(
    (state) => state.auth
  );

  useEffect(() => {
    if (isError) {
      toast.error(message);
    }

    if (isSuccess || user) {
      navigate('/dashboard');
    }

    dispatch(reset());
  }, [user, isError, isSuccess, message, navigate, dispatch]);

  const onChange = (e) => {
    setFormData((prevState) => ({
      ...prevState,
      [e.target.name]: e.target.value
    }));
  };

  const onSubmit = (e) => {
    e.preventDefault();

    if (password !== confirmPassword) {
      toast.error('Passwords do not match');
      return;
    }

    const userData = {
      name,
      email,
      password
    };

    dispatch(register(userData));
  };

  if (isLoading) {
    return <div>Loading...</div>;
  }

  return (
    <div className="row justify-content-center">
      <div className="col-md-6">
        <Card>
          <Card.Body>
            <h2 className="text-center mb-4">Register</h2>
            <Form onSubmit={onSubmit}>
              <Form.Group className="mb-3">
                <Form.Label>Name</Form.Label>
                <Form.Control
                  type="text"
                  name="name"
                  value={name}
                  onChange={onChange}
                  placeholder="Enter name"
                  required
                />
              </Form.Group>

              <Form.Group className="mb-3">
                <Form.Label>Email</Form.Label>
                <Form.Control
                  type="email"
                  name="email"
                  value={email}
                  onChange={onChange}
                  placeholder="Enter email"
                  required
                />
              </Form.Group>

              <Form.Group className="mb-3">
                <Form.Label>Password</Form.Label>
                <Form.Control
                  type="password"
                  name="password"
                  value={password}
                  onChange={onChange}
                  placeholder="Enter password"
                  required
                />
              </Form.Group>

              <Form.Group className="mb-3">
                <Form.Label>Confirm Password</Form.Label>
                <Form.Control
                  type="password"
                  name="confirmPassword"
                  value={confirmPassword}
                  onChange={onChange}
                  placeholder="Confirm password"
                  required
                />
              </Form.Group>

              <Button variant="primary" type="submit" className="w-100">
                Register
              </Button>
            </Form>
          </Card.Body>
        </Card>
      </div>
    </div>
  );
};

export default Register;
```

**PostList Component:**
```javascript
// src/components/posts/PostList.js
import React, { useEffect } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { getPosts } from '../../redux/slices/postSlice';
import PostItem from './PostItem';
import { Row, Col, Spinner } from 'react-bootstrap';

const PostList = () => {
  const dispatch = useDispatch();
  const { posts, isLoading, isError, message } = useSelector(
    (state) => state.posts
  );

  useEffect(() => {
    dispatch(getPosts());
  }, [dispatch]);

  if (isLoading) {
    return (
      <div className="text-center">
        <Spinner animation="border" />
      </div>
    );
  }

  if (isError) {
    return <div className="alert alert-danger">{message}</div>;
  }

  return (
    <div>
      <h2 className="mb-4">Latest Posts</h2>
      <Row>
        {posts.map((post) => (
          <Col key={post._id} md={6} lg={4} className="mb-4">
            <PostItem post={post} />
          </Col>
        ))}
      </Row>
      {posts.length === 0 && (
        <p className="text-center">No posts found</p>
      )}
    </div>
  );
};

export default PostList;
```

**PostItem Component:**
```javascript
// src/components/posts/PostItem.js
import React from 'react';
import { Link } from 'react-router-dom';
import { useDispatch, useSelector } from 'react-redux';
import { likePost, deletePost } from '../../redux/slices/postSlice';
import { Card, Button, Badge } from 'react-bootstrap';
import { toast } from 'react-toastify';

const PostItem = ({ post }) => {
  const dispatch = useDispatch();
  const { user } = useSelector((state) => state.auth);

  const handleLike = () => {
    dispatch(likePost(post._id));
  };

  const handleDelete = () => {
    if (window.confirm('Are you sure you want to delete this post?')) {
      dispatch(deletePost(post._id));
      toast.success('Post deleted successfully');
    }
  };

  const isOwner = user && post.author._id === user.id;

  return (
    <Card>
      <Card.Body>
        <Card.Title>{post.title}</Card.Title>
        <Card.Subtitle className="mb-2 text-muted">
          By {post.author.name}
        </Card.Subtitle>
        <Card.Text>
          {post.content.substring(0, 100)}...
        </Card.Text>
        <div className="mb-2">
          {post.tags.map((tag, index) => (
            <Badge key={index} bg="secondary" className="me-1">
              {tag}
            </Badge>
          ))}
        </div>
        <div className="d-flex justify-content-between align-items-center">
          <div>
            <Button 
              variant="outline-primary" 
              size="sm" 
              onClick={handleLike}
              disabled={!user}
            >
              👍 {post.likes.length}
            </Button>
            <span className="ms-2">💬 {post.comments.length}</span>
          </div>
          <div>
            <Link to={`/posts/${post._id}`}>
              <Button variant="info" size="sm">View</Button>
            </Link>
            {isOwner && (
              <Button 
                variant="danger" 
                size="sm" 
                className="ms-2"
                onClick={handleDelete}
              >
                Delete
              </Button>
            )}
          </div>
        </div>
      </Card.Body>
      <Card.Footer className="text-muted">
        {new Date(post.createdAt).toLocaleDateString()}
      </Card.Footer>
    </Card>
  );
};

export default PostItem;
```

**PostForm Component:**
```javascript
// src/components/posts/PostForm.js
import React, { useState } from 'react';
import { useDispatch } from 'react-redux';
import { createPost } from '../../redux/slices/postSlice';
import { Form, Button, Card } from 'react-bootstrap';
import { toast } from 'react-toastify';

const PostForm = () => {
  const [formData, setFormData] = useState({
    title: '',
    content: '',
    tags: ''
  });

  const { title, content, tags } = formData;
  const dispatch = useDispatch();

  const onChange = (e) => {
    setFormData((prevState) => ({
      ...prevState,
      [e.target.name]: e.target.value
    }));
  };

  const onSubmit = (e) => {
    e.preventDefault();

    const postData = {
      title,
      content,
      tags: tags.split(',').map(tag => tag.trim()),
      status: 'published'
    };

    dispatch(createPost(postData));
    
    // Reset form
    setFormData({
      title: '',
      content: '',
      tags: ''
    });

    toast.success('Post created successfully');
  };

  return (
    <Card className="mb-4">
      <Card.Body>
        <h3>Create New Post</h3>
        <Form onSubmit={onSubmit}>
          <Form.Group className="mb-3">
            <Form.Label>Title</Form.Label>
            <Form.Control
              type="text"
              name="title"
              value={title}
              onChange={onChange}
              placeholder="Enter post title"
              required
            />
          </Form.Group>

          <Form.Group className="mb-3">
            <Form.Label>Content</Form.Label>
            <Form.Control
              as="textarea"
              rows={5}
              name="content"
              value={content}
              onChange={onChange}
              placeholder="Enter post content"
              required
            />
          </Form.Group>

          <Form.Group className="mb-3">
            <Form.Label>Tags (comma separated)</Form.Label>
            <Form.Control
              type="text"
              name="tags"
              value={tags}
              onChange={onChange}
              placeholder="javascript, react, mongodb"
            />
          </Form.Group>

          <Button variant="primary" type="submit">
            Create Post
          </Button>
        </Form>
      </Card.Body>
    </Card>
  );
};

export default PostForm;
```

**PostDetail Component:**
```javascript
// src/components/posts/PostDetail.js
import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { useDispatch, useSelector } from 'react-redux';
import { getPost, likePost } from '../../redux/slices/postSlice';
import postService from '../../services/postService';
import { Card, Button, Form, ListGroup, Spinner, Badge } from 'react-bootstrap';
import { toast } from 'react-toastify';

const PostDetail = () => {
  const { id } = useParams();
  const dispatch = useDispatch();
  const { post, isLoading } = useSelector((state) => state.posts);
  const { user } = useSelector((state) => state.auth);
  
  const [comment, setComment] = useState('');

  useEffect(() => {
    dispatch(getPost(id));
  }, [dispatch, id]);

  const handleLike = () => {
    dispatch(likePost(id));
  };

  const handleComment = async (e) => {
    e.preventDefault();
    try {
      await postService.addComment(id, { text: comment });
      setComment('');
      dispatch(getPost(id)); // Refresh post
      toast.success('Comment added');
    } catch (error) {
      toast.error('Failed to add comment');
    }
  };

  if (isLoading || !post) {
    return (
      <div className="text-center">
        <Spinner animation="border" />
      </div>
    );
  }

  return (
    <div>
      <Card className="mb-4">
        <Card.Body>
          <h1>{post.title}</h1>
          <p className="text-muted">
            By {post.author.name} | {new Date(post.createdAt).toLocaleString()}
          </p>
          <div className="mb-3">
            {post.tags.map((tag, index) => (
              <Badge key={index} bg="secondary" className="me-1">
                {tag}
              </Badge>
            ))}
          </div>
          <Card.Text style={{ whiteSpace: 'pre-wrap' }}>
            {post.content}
          </Card.Text>
          <Button 
            variant="outline-primary" 
            onClick={handleLike}
            disabled={!user}
          >
            👍 Like ({post.likes.length})
          </Button>
        </Card.Body>
      </Card>

      <Card>
        <Card.Header>
          <h4>Comments ({post.comments.length})</h4>
        </Card.Header>
        <Card.Body>
          {user && (
            <Form onSubmit={handleComment} className="mb-4">
              <Form.Group>
                <Form.Control
                  as="textarea"
                  rows={3}
                  value={comment}
                  onChange={(e) => setComment(e.target.value)}
                  placeholder="Write a comment..."
                  required
                />
              </Form.Group>
              <Button type="submit" className="mt-2">
                Add Comment
              </Button>
            </Form>
          )}

          <ListGroup variant="flush">
            {post.comments.map((comment) => (
              <ListGroup.Item key={comment._id}>
                <strong>{comment.user.name}</strong>
                <span className="text-muted ms-2">
                  {new Date(comment.date).toLocaleString()}
                </span>
                <p className="mb-0 mt-2">{comment.text}</p>
              </ListGroup.Item>
            ))}
          </ListGroup>

          {post.comments.length === 0 && !user && (
            <p className="text-muted">No comments yet. Login to add one.</p>
          )}
        </Card.Body>
      </Card>
    </div>
  );
};

export default PostDetail;
```

**PrivateRoute Component:**
```javascript
// src/components/common/PrivateRoute.js
import { Navigate } from 'react-router-dom';
import { useSelector } from 'react-redux';

const PrivateRoute = ({ children }) => {
  const { user } = useSelector((state) => state.auth);

  return user ? children : <Navigate to="/login" />;
};

export default PrivateRoute;
```

**Dashboard Page:**
```javascript
// src/pages/Dashboard.js
import React from 'react';
import PostForm from '../components/posts/PostForm';
import PostList from '../components/posts/PostList';

const Dashboard = () => {
  return (
    <div>
      <h1 className="mb-4">Dashboard</h1>
      <PostForm />
      <PostList />
    </div>
  );
};

export default Dashboard;
```

**Home Page:**
```javascript
// src/pages/Home.js
import React from 'react';
import PostList from '../components/posts/PostList';
import { useSelector } from 'react-redux';
import { Link } from 'react-router-dom';
import { Button } from 'react-bootstrap';

const Home = () => {
  const { user } = useSelector((state) => state.auth);

  return (
    <div>
      <div className="jumbotron bg-light p-5 rounded mb-4">
        <h1>Welcome to MERN Blog</h1>
        <p>A full-stack application built with MongoDB, Express, React, and Node.js</p>
        {!user && (
          <div>
            <Link to="/register">
              <Button variant="primary" className="me-2">Get Started</Button>
            </Link>
            <Link to="/login">
              <Button variant="outline-primary">Login</Button>
            </Link>
          </div>
        )}
      </div>
      <PostList />
    </div>
  );
};

export default Home;
```

---

## 6. CONNECTING FRONTEND & BACKEND

### Enable CORS in Backend
Already included in server.js, but here's detailed configuration:

```javascript
// backend/server.js - CORS configuration
const corsOptions = {
  origin: ['http://localhost:3000', 'http://localhost:3001'],
  credentials: true,
  optionSuccessStatus: 200
};

app.use(cors(corsOptions));
```

### Proxy Configuration (Alternative)
Add to frontend package.json:

```json
{
  "proxy": "http://localhost:5000"
}
```

Then update API calls:
```javascript
// Instead of: http://localhost:5000/api/users
// Use: /api/users
```

---

## 7. AUTHENTICATION & AUTHORIZATION

### Password Hashing with bcrypt
```javascript
// In User model - add pre-save middleware
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) {
    next();
  }
  
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
});

// Method to compare passwords
userSchema.methods.matchPassword = async function(enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};
```

### JWT Token Generation
```javascript
// models/User.js - Add method
userSchema.methods.getSignedJwtToken = function() {
  return jwt.sign({ id: this._id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRE
  });
};
```

### Protected Routes Example
```javascript
// Use in routes
router.get('/protected', protect, (req, res) => {
  res.json({ message: 'Access granted', user: req.user });
});

// Multiple roles
router.delete('/admin-only', protect, authorize('admin'), (req, res) => {
  res.json({ message: 'Admin access granted' });
});
```

---

## 8. ADVANCED TOPICS

### File Upload with Multer
```bash
npm install multer
```

```javascript
// middleware/upload.js
const multer = require('multer');
const path = require('path');

const storage = multer.diskStorage({
  destination: function(req, file, cb) {
    cb(null, 'uploads/');
  },
  filename: function(req, file, cb) {
    cb(null, `${Date.now()}-${file.originalname}`);
  }
});

const fileFilter = (req, file, cb) => {
  const allowedTypes = /jpeg|jpg|png|gif/;
  const extname = allowedTypes.test(
    path.extname(file.originalname).toLowerCase()
  );
  const mimetype = allowedTypes.test(file.mimetype);

  if (extname && mimetype) {
    cb(null, true);
  } else {
    cb(new Error('Only images are allowed'));
  }
};

const upload = multer({
  storage: storage,
  limits: { fileSize: 1024 * 1024 * 5 }, // 5MB
  fileFilter: fileFilter
});

module.exports = upload;
```

```javascript
// Use in route
const upload = require('../middleware/upload');

router.post('/upload', protect, upload.single('image'), (req, res) => {
  res.json({
    success: true,
    file: req.file.filename
  });
});
```

### Pagination Implementation
```javascript
// middleware/pagination.js
const pagination = (model) => async (req, res, next) => {
  const page = parseInt(req.query.page, 10) || 1;
  const limit = parseInt(req.query.limit, 10) || 10;
  const startIndex = (page - 1) * limit;
  const endIndex = page * limit;
  const total = await model.countDocuments();

  const results = {};

  if (endIndex < total) {
    results.next = {
      page: page + 1,
      limit: limit
    };
  }

  if (startIndex > 0) {
    results.previous = {
      page: page - 1,
      limit: limit
    };
  }

  results.data = await model.find().limit(limit).skip(startIndex);
  results.total = total;
  results.pages = Math.ceil(total / limit);

  res.paginatedResults = results;
  next();
};

module.exports = pagination;
```

### Search Functionality
```javascript
// controllers/postController.js - Add search method
exports.searchPosts = async (req, res) => {
  try {
    const { keyword } = req.query;

    const posts = await Post.find({
      $text: { $search: keyword }
    }).populate('author', 'name email');

    res.json({
      success: true,
      count: posts.length,
      data: posts
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      message: error.message 
    });
  }
};

// Route
router.get('/search', searchPosts);
```

### Email with Nodemailer
```bash
npm install nodemailer
```

```javascript
// utils/sendEmail.js
const nodemailer = require('nodemailer');

const sendEmail = async (options) => {
  const transporter = nodemailer.createTransporter({
    host: process.env.SMTP_HOST,
    port: process.env.SMTP_PORT,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS
    }
  });

  const message = {
    from: `${process.env.FROM_NAME} <${process.env.FROM_EMAIL}>`,
    to: options.email,
    subject: options.subject,
    text: options.message
  };

  await transporter.sendMail(message);
};

module.exports = sendEmail;
```

### Input Validation
```javascript
// routes/userRoutes.js
const { body, validationResult } = require('express-validator');

router.post('/register', [
  body('name').trim().isLength({ min: 2 }).escape(),
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 6 })
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  // Continue with registration
});
```

---

## 9. DEPLOYMENT

### Prepare for Production

**Backend - Environment Variables:**
```env
# .env.production
NODE_ENV=production
PORT=5000
MONGO_URI=your_mongodb_atlas_connection_string
JWT_SECRET=your_production_secret
```

**Frontend - Build:**
```bash
cd frontend
npm run build
```

**Serve Frontend from Backend:**
```javascript
// backend/server.js
const path = require('path');

// Serve static assets in production
if (process.env.NODE_ENV === 'production') {
  app.use(express.static(path.join(__dirname, '../frontend/build')));

  app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/build', 'index.html'));
  });
}
```

### MongoDB Atlas Setup
1. Go to mongodb.com/cloud/atlas
2. Create free cluster
3. Create database user
4. Whitelist IP (0.0.0.0/0 for all)
5. Get connection string
6. Update MONGO_URI in .env

### Deploy to Heroku

```bash
# Install Heroku CLI
# Login
heroku login

# Create app
heroku create your-app-name

# Set environment variables
heroku config:set NODE_ENV=production
heroku config:set MONGO_URI=your_mongodb_uri
heroku config:set JWT_SECRET=your_secret

# Deploy
git add .
git commit -m "Ready for deployment"
git push heroku main

# Open app
heroku open
```

**Procfile:**
```
web: node backend/server.js
```

**package.json scripts:**
```json
{
  "scripts": {
    "start": "node backend/server.js",
    "server": "nodemon backend/server.js",
    "client": "npm start --prefix frontend",
    "dev": "concurrently \"npm run server\" \"npm run client\"",
    "build": "npm install && npm install --prefix frontend && npm run build --prefix frontend",
    "heroku-postbuild": "NPM_CONFIG_PRODUCTION=false npm install --prefix frontend && npm run build --prefix frontend"
  }
}
```

### Deploy to Vercel (Frontend) + Render (Backend)

**Frontend (Vercel):**
```bash
# Install Vercel CLI
npm i -g vercel

# Deploy
cd frontend
vercel
```

**Backend (Render):**
1. Push code to GitHub
2. Go to render.com
3. Create new Web Service
4. Connect repository
5. Add environment variables
6. Deploy

---

## 10. BEST PRACTICES

### Code Organization
✅ Separate concerns (MVC pattern)
✅ Use environment variables
✅ Create reusable components
✅ Implement error handling
✅ Add input validation

### Security
✅ Use HTTPS in production
✅ Implement rate limiting
✅ Sanitize user input
✅ Use helmet for security headers
✅ Store passwords hashed
✅ Implement JWT properly
✅ Validate on both client and server

### Performance
✅ Use pagination
✅ Implement caching
✅ Optimize database queries
✅ Use indexes in MongoDB
✅ Minimize bundle size
✅ Lazy load components
✅ Use React.memo for optimization

### Code Quality
✅ Use ESLint
✅ Use Prettier for formatting
✅ Write meaningful comments
✅ Follow naming conventions
✅ Keep functions small and focused
✅ Use async/await instead of callbacks

### Testing (Bonus)
```bash
# Backend testing
npm install --save-dev jest supertest

# Frontend testing
npm install --save-dev @testing-library/react @testing-library/jest-dom
```

---

## COMPLETE PROJECT CHECKLIST

### Backend ✅
- [ ] MongoDB connection
- [ ] User model with validation
- [ ] Post model with relationships
- [ ] Authentication (JWT)
- [ ] Authorization (roles)
- [ ] CRUD operations
- [ ] Error handling
- [ ] Input validation
- [ ] File upload
- [ ] Email functionality

### Frontend ✅
- [ ] React Router setup
- [ ] Redux state management
- [ ] Authentication pages
- [ ] Protected routes
- [ ] CRUD operations UI
- [ ] Form validation
- [ ] Toast notifications
- [ ] Responsive design
- [ ] Loading states
- [ ] Error handling

### Deployment ✅
- [ ] Environment variables
- [ ] Production build
- [ ] Database hosted
- [ ] Application deployed
- [ ] HTTPS enabled

---

## SAMPLE PROJECT TIMELINE

**Week 1-2: Backend**
- Setup Node.js + Express
- MongoDB models
- Authentication
- CRUD APIs

**Week 3-4: Frontend**
- React setup
- Components
- Redux integration
- API integration

**Week 5: Integration & Testing**
- Connect frontend/backend
- Test all features
- Fix bugs

**Week 6: Deployment**
- Prepare for production
- Deploy
- Final testing

---

## ADDITIONAL RESOURCES

### Documentation
- MongoDB: https://docs.mongodb.com/
- Express: https://expressjs.com/
- React: https://react.dev/
- Node.js: https://nodejs.org/docs/

### Learning
- FreeCodeCamp
- Traversy Media (YouTube)
- The Net Ninja (YouTube)
- MDN Web Docs

### Tools
- VS Code
- Postman
- MongoDB Compass
- Git/GitHub
- Chrome DevTools

---

This comprehensive guide covers everything your students need to build a complete MERN stack application. You can copy this content into a Word document and add more examples or modify sections based on your teaching needs!
