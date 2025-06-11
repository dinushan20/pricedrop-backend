require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const nodemailer = require('nodemailer');

const app = express();

// Enhanced CORS Configuration
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

app.options('*', cors()); // Enable pre-flight for all routes
app.use(express.json());

// Health Check
app.get('/', (req, res) => {
  res.json({ status: 'API is running', timestamp: new Date() });
});

// MongoDB Connection
const PORT = process.env.PORT || 3000;
// Update your MongoDB connection with better error handling
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  retryWrites: true,
  w: 'majority'
})
.then(() => console.log('MongoDB connected successfully'))
.catch(err => {
  console.error('MongoDB connection error:', err);
  process.exit(1); // Exit if DB connection fails
});

// Models
// User Model with enhanced validation
const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
    validate: {
      validator: (email) => {
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
      },
      message: 'Invalid email format'
    }
  },
  password: {
    type: String,
    required: true,
    minlength: 8
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Product Model with validation
const productSchema = new mongoose.Schema({
  productName: {
    type: String,
    required: true,
    trim: true
  },
  productUrl: {
    type: String,
    required: true,
    trim: true
  },
  currentPrice: {
    type: Number,
    required: true,
    min: 0
  },
  targetPrice: {
    type: Number,
    required: true,
    min: 0
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

const User = mongoose.model('User', userSchema);
const Product = mongoose.model('Product', productSchema);

// Auth Middleware
const authenticate = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) throw new Error('Authentication required');
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded._id);
    if (!user) throw new Error('User not found');
    
    req.user = user;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Please authenticate' });
  }
};

// Registration Endpoint (Updated)
app.post('/register', async (req, res) => {
  try {
    console.log('Registration attempt:', req.body); // Log incoming request
    
    const { email, password } = req.body;

    // Validate input
    if (!email || !password) {
      console.log('Missing fields');
      return res.status(400).json({ 
        success: false,
        error: 'Email and password are required',
        code: 'MISSING_FIELDS'
      });
    }

    // Check for existing user
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      console.log('Email already exists');
      return res.status(409).json({ 
        success: false,
        error: 'Email already registered',
        code: 'EMAIL_EXISTS'
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    console.log('Password hashed successfully');

    // Create user
    const user = new User({
      email,
      password: hashedPassword
    });
    
    await user.save();
    console.log('User saved to database:', user);

    // Generate token
    const token = jwt.sign(
      { _id: user._id },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    console.log('Registration successful');
    res.status(201).json({
      success: true,
      user: {
        id: user._id,
        email: user.email
      },
      token
    });

  } catch (error) {
    console.error('Registration error:', error);
    
    // Handle duplicate key error
    if (error.code === 11000) {
      return res.status(409).json({
        success: false,
        error: 'Email already registered',
        code: 'EMAIL_EXISTS'
      });
    }
    
    res.status(500).json({
      success: false,
      error: 'Registration failed',
      code: 'SERVER_ERROR',
      details: error.message
    });
  }
});


// Login Endpoint
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ 
        error: 'Invalid credentials',
        code: 'AUTH_ERROR'
      });
    }

    const token = jwt.sign(
      { _id: user._id },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({ 
      user: { id: user._id, email: user.email },
      token 
    });

  } catch (err) {
    res.status(500).json({ 
      error: 'Login failed',
      code: 'SERVER_ERROR'
    });
  }
});

// Product Endpoints
app.get('/products', authenticate, async (req, res) => {
  try {
    const products = await Product.find({ userId: req.user._id });
    res.json(products);
  } catch (err) {
    res.status(500).json({ 
      error: 'Failed to fetch products',
      code: 'SERVER_ERROR'
    });
  }
});

app.post('/track-product', authenticate, async (req, res) => {
  try {
    const product = new Product({
      ...req.body,
      userId: req.user._id
    });
    await product.save();
    res.status(201).json(product);
  } catch (err) {
    res.status(500).json({ 
      error: 'Failed to track product',
      code: 'SERVER_ERROR'
    });
  }
});

// Start Server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// Error Handling
process.on('unhandledRejection', (err) => {
  console.error('Unhandled rejection:', err);
});

process.on('uncaughtException', (err) => {
  console.error('Uncaught exception:', err);
});