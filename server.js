require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();

// Enhanced CORS Configuration
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

app.use(express.json());

// MongoDB Connection with Robust Error Handling
const MAX_RETRIES = 3;
let retryCount = 0;

const connectDB = async () => {
  try {
    console.log(`Attempting MongoDB connection (attempt ${retryCount + 1})...`);

    // Log the raw value
    console.log("MONGODB_URI:", process.env.MONGODB_URI);

    await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      serverSelectionTimeoutMS: 10000,
      socketTimeoutMS: 45000,
      maxPoolSize: 10,
      retryWrites: true,
      retryReads: true
    });

    console.log('MongoDB connected successfully');
    retryCount = 0;
  } catch (err) {
    console.error('MongoDB connection error:', err.message);
    
    if (retryCount < MAX_RETRIES) {
      retryCount++;
      console.log(`Retrying connection in 5 seconds... (${retryCount}/${MAX_RETRIES})`);
      setTimeout(connectDB, 5000);
    } else {
      console.error('Max retries reached. Exiting...');
      process.exit(1);
    }
  }
};


// Connection event handlers
mongoose.connection.on('connected', () => {
  console.log('Mongoose connected to DB');
  app.emit('dbReady'); // Emit event when DB is ready
});

mongoose.connection.on('error', (err) => {
  console.error('Mongoose connection error:', err);
});

mongoose.connection.on('disconnected', () => {
  console.log('Mongoose disconnected');
});

// Health Check Endpoint
app.get('/health', async (req, res) => {
  try {
    // Test DB connection
    await mongoose.connection.db.admin().ping();
    
    res.json({
      status: 'OK',
      dbStatus: 'connected',
      uptime: process.uptime(),
      timestamp: new Date()
    });
  } catch (err) {
    res.status(503).json({
      status: 'Service Unavailable',
      dbStatus: 'disconnected',
      error: err.message
    });
  }
});

// Models
const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
    match: [/^[^\s@]+@[^\s@]+\.[^\s@]+$/, 'Invalid email format']
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

const productSchema = new mongoose.Schema({
  productName: String,
  productUrl: String,
  currentPrice: Number,
  targetPrice: Number,
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
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
    if (!token) return res.status(401).json({ error: 'Authentication required' });
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded._id);
    if (!user) return res.status(401).json({ error: 'User not found' });
    
    req.user = user;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Please authenticate' });
  }
};

// Registration Endpoint
app.post('/register', async (req, res) => {
  try {
    // Check DB connection first
    if (mongoose.connection.readyState !== 1) {
      return res.status(503).json({ 
        success: false,
        error: 'Database unavailable',
        code: 'DB_UNAVAILABLE' 
      });
    }

    const { email, password } = req.body;

    // Validate input
    if (!email || !password) {
      return res.status(400).json({ 
        success: false,
        error: 'Email and password are required',
        code: 'MISSING_FIELDS'
      });
    }

    // Check for existing user
    const existingUser = await User.findOne({ email }).maxTimeMS(10000);
    if (existingUser) {
      return res.status(409).json({ 
        success: false,
        error: 'Email already registered',
        code: 'EMAIL_EXISTS'
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const user = new User({ email, password: hashedPassword });
    await user.save();

    // Generate token
    const token = jwt.sign(
      { _id: user._id },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.status(201).json({
      success: true,
      user: { id: user._id, email: user.email },
      token
    });

  } catch (error) {
    console.error('Registration error:', error);
    
    if (error.code === 11000) {
      return res.status(409).json({
        success: false,
        error: 'Email already registered',
        code: 'EMAIL_EXISTS'
      });
    }
    
    if (error.name === 'MongooseError') {
      return res.status(503).json({
        success: false,
        error: 'Database operation timed out',
        code: 'DB_TIMEOUT'
      });
    }
    
    res.status(500).json({
      success: false,
      error: 'Registration failed',
      code: 'SERVER_ERROR'
    });
  }
});

// Login Endpoint
app.post('/login', async (req, res) => {
  try {
    // Check DB connection
    if (mongoose.connection.readyState !== 1) {
      return res.status(503).json({ error: 'Database unavailable' });
    }

    const { email, password } = req.body;
    const user = await User.findOne({ email }).maxTimeMS(10000);
    
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
    console.error('Login error:', err);
    res.status(500).json({ 
      error: 'Login failed',
      code: 'SERVER_ERROR'
    });
  }
});

// Product Endpoints
app.get('/products', authenticate, async (req, res) => {
  try {
    const products = await Product.find({ userId: req.user._id }).maxTimeMS(10000);
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

// Error Handling Middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ 
    error: 'Internal server error',
    code: 'INTERNAL_ERROR'
  });
});

const PORT = process.env.PORT || 3000;
app.on('dbReady', () => {
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
});

// Initial connection attempt
connectDB();