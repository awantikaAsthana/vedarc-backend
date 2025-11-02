const express = require('express');
const connectDb = require('./config/database');
const dotenv = require('dotenv');
dotenv.config();
const cors = require('cors');
const helmet = require('helmet');

// const errorHandler = require('./middleware/errorHandler');


// Import Routes
const userRoutes = require('./routes/userRoutes');
//const postRoutes = require('./routes/postRoutes');



// Load environment variables



// Connect to MongoDB
connectDb();

const app = express();

// Middleware
app.use(express.json()); // body parser
app.use(express.urlencoded({ extended: true }));
app.use(cors());
app.use(helmet());// for secuirity

// Routes  ---->
app.use('/api/users', userRoutes);
//app.use('/api/posts', postRoutes);

app.use ("/", (req, res) => {
    res.send ("Vedarc Backend API is running");
});

//app.use(errorHandler);

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});



