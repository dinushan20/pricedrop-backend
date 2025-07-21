require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const cheerio = require('cheerio');
const axios = require('axios');

const app = express();

// Enhanced CORS Configuration
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 1000,
  message: { error: 'Too many requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(limiter);
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Request logging middleware
app.use((req, res, next) => {
  const start = Date.now();
  const originalSend = res.send;
  
  res.send = function(data) {
    const duration = Date.now() - start;
    console.log(`${req.method} ${req.path} - ${res.statusCode} (${duration}ms)`);
    originalSend.call(this, data);
  };
  
  next();
});

// MongoDB Connection
const MAX_RETRIES = 3;
let retryCount = 0;
let isConnected = false;

const connectDB = async () => {
  try {
    console.log(`🔄 Attempting MongoDB connection (attempt ${retryCount + 1}/${MAX_RETRIES})`);

    if (!process.env.MONGODB_URI) {
      throw new Error('MONGODB_URI environment variable is not set');
    }

    const options = {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      serverSelectionTimeoutMS: 10000,
      socketTimeoutMS: 45000,
      maxPoolSize: 10,
      retryWrites: true,
      retryReads: true,
      connectTimeoutMS: 30000,
      heartbeatFrequencyMS: 10000,
      maxIdleTimeMS: 30000
    };

    await mongoose.connect(process.env.MONGODB_URI, options);
    
    console.log('✅ MongoDB connected successfully');
    isConnected = true;
    retryCount = 0;
    
    await mongoose.connection.db.admin().ping();
    console.log('✅ MongoDB ping successful');
    
  } catch (err) {
    console.error('❌ MongoDB connection error:', err.message);
    isConnected = false;
    
    if (retryCount < MAX_RETRIES) {
      retryCount++;
      const delay = Math.min(1000 * Math.pow(2, retryCount), 30000);
      console.log(`⏳ Retrying connection in ${delay/1000} seconds... (${retryCount}/${MAX_RETRIES})`);
      setTimeout(connectDB, delay);
    } else {
      console.error('💥 Max retries reached. Server will continue without database.');
    }
  }
};

// Connection event handlers
mongoose.connection.on('connected', () => {
  console.log('🟢 Mongoose connected to DB');
  isConnected = true;
});

mongoose.connection.on('error', (err) => {
  console.error('🔴 Mongoose connection error:', err);
  isConnected = false;
});

mongoose.connection.on('disconnected', () => {
  console.log('🟡 Mongoose disconnected');
  isConnected = false;
  
  setTimeout(() => {
    if (!isConnected && retryCount === 0) {
      console.log('🔄 Attempting to reconnect...');
      connectDB();
    }
  }, 5000);
});

// Database health check middleware
const checkDBConnection = (req, res, next) => {
  if (!isConnected || mongoose.connection.readyState !== 1) {
    return res.status(503).json({
      success: false,
      error: 'Database temporarily unavailable',
      code: 'DB_UNAVAILABLE',
      timestamp: new Date().toISOString()
    });
  }
  next();
};

// Health Check Endpoint
app.get('/health', async (req, res) => {
  const healthCheck = {
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV || 'development',
    version: process.env.npm_package_version || '1.0.0'
  };

  try {
    if (isConnected && mongoose.connection.readyState === 1) {
      await mongoose.connection.db.admin().ping();
      healthCheck.database = {
        status: 'connected',
        readyState: mongoose.connection.readyState,
        host: mongoose.connection.host,
        name: mongoose.connection.name
      };
    } else {
      healthCheck.database = {
        status: 'disconnected',
        readyState: mongoose.connection.readyState
      };
    }

    if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
      healthCheck.email = { status: 'configured' };
    } else {
      healthCheck.email = { status: 'not_configured' };
    }

    res.status(isConnected ? 200 : 503).json(healthCheck);
  } catch (err) {
    healthCheck.database = {
      status: 'error',
      error: err.message
    };
    res.status(503).json(healthCheck);
  }
});

// Email transporter
let transporter = null;

const initializeEmailTransporter = () => {
  try {
    if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
      transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
          user: process.env.EMAIL_USER,
          pass: process.env.EMAIL_PASS
        },
        pool: true,
        maxConnections: 5,
        maxMessages: 100,
        rateLimit: 14
      });

      transporter.verify((error, success) => {
        if (error) {
          console.error('❌ Email configuration error:', error);
          transporter = null;
        } else {
          console.log('✅ Email service ready');
        }
      });
    } else {
      console.warn('⚠️ Email credentials not configured');
    }
  } catch (error) {
    console.error('❌ Email transporter initialization failed:', error);
    transporter = null;
  }
};

// SERVER-SIDE PRICE SCRAPING SYSTEM
const serverScrapers = {
  'hm.com': async (html, url) => {
    const $ = cheerio.load(html);
    try {
      const title = $('.product-item-headline').text().trim() || 
                   $('.ProductName-module--productItemHeadline__3Gzt1').text().trim() ||
                   $('h1[data-testid="product-name"]').text().trim() ||
                   $('h1').first().text().trim();
      
      let price = null;
      const priceSelectors = ['.price-value', '.ProductPrice-module--price__1PZ8p', '[data-testid="price-value"]'];
      
      for (const selector of priceSelectors) {
        const priceText = $(selector).text().replace(/[€$£¥₹]/g, '').replace(/[,\s]/g, '').trim();
        const priceMatch = priceText.match(/(\d+(?:[.,]\d{2})?)/);
        if (priceMatch) {
          price = parseFloat(priceMatch[1].replace(',', '.'));
          break;
        }
      }
      
      const image = $('.product-detail-main-image').attr('src') || 
                   $('meta[property="og:image"]').attr('content');
      
      return { title: title || null, price: price || null, image: image || null, store: 'H&M' };
    } catch (e) {
      console.error('H&M server scraper error:', e);
      return { title: null, price: null, image: null, store: 'H&M' };
    }
  },

  'zara.com': async (html, url) => {
    const $ = cheerio.load(html);
    try {
      const title = $('.product-detail-info__header-name').text().trim() ||
                   $('.product-detail-info__name').text().trim() ||
                   $('h1[data-testid="product-name"]').text().trim();
      
      let price = null;
      const priceSelectors = ['.money-amount__main', '.price-amount .money-amount__main'];
      
      for (const selector of priceSelectors) {
        const priceText = $(selector).text().replace(/\s/g, '').replace(/EUR|€|\$/g, '').replace(',', '.');
        const priceMatch = priceText.match(/(\d+(?:\.\d{2})?)/);
        if (priceMatch) {
          price = parseFloat(priceMatch[1]);
          break;
        }
      }
      
      const image = $('.media-image__image').attr('src') || 
                   $('meta[property="og:image"]').attr('content');
      
      return { title: title || null, price: price || null, image: image || null, store: 'Zara' };
    } catch (e) {
      console.error('Zara server scraper error:', e);
      return { title: null, price: null, image: null, store: 'Zara' };
    }
  },

  'mediamarkt.': async (html, url) => {
    const $ = cheerio.load(html);
    try {
      const title = $('h1[data-test="product-title"]').text().trim() ||
                   $('h1.pdp-product-name').text().trim() ||
                   $('h1').first().text().trim();
      
      let price = null;
      const whole = $('[data-test="branded-price-whole-value"]').text().replace(/[,\s]/g, '').trim();
      const decimal = $('[data-test="branded-price-decimal-value"]').text().trim();
      
      if (whole && decimal) {
        price = parseFloat(`${whole}.${decimal}`);
      }
      
      const image = $('img[itemprop="image"]').attr('src') || 
                   $('meta[property="og:image"]').attr('content');
      
      return { title: title || null, price: price || null, image: image || null, store: 'MediaMarkt' };
    } catch (e) {
      console.error('MediaMarkt server scraper error:', e);
      return { title: null, price: null, image: null, store: 'MediaMarkt' };
    }
  },

  'amazon.': async (html, url) => {
    const $ = cheerio.load(html);
    try {
      const title = $('#productTitle').text().trim() ||
                   $('.product-title').text().trim();
      
      let price = null;
      const priceSelectors = ['.a-price-whole', '.a-offscreen', '#price_inside_buybox'];
      
      for (const selector of priceSelectors) {
        const priceText = $(selector).text().replace(/[€$£,\s]/g, '').trim();
        const priceMatch = priceText.match(/(\d+(?:\.\d{2})?)/);
        if (priceMatch) {
          price = parseFloat(priceMatch[1]);
          break;
        }
      }
      
      const image = $('#landingImage').attr('src') || 
                   $('meta[property="og:image"]').attr('content');
      
      return { title: title || null, price: price || null, image: image || null, store: 'Amazon' };
    } catch (e) {
      console.error('Amazon server scraper error:', e);
      return { title: null, price: null, image: null, store: 'Amazon' };
    }
  },

  'zalando.': async (html, url) => {
    const $ = cheerio.load(html);
    try {
      const title = $('[data-testid="product-name"]').text().trim() ||
                   $('.product-title').text().trim();
      
      let price = null;
      const priceSelectors = ['[data-testid="price"]', '.price-current', '.product-price'];
      
      for (const selector of priceSelectors) {
        const priceText = $(selector).text().replace(/[€$£,\s]/g, '').trim();
        const priceMatch = priceText.match(/(\d+(?:\.\d{2})?)/);
        if (priceMatch) {
          price = parseFloat(priceMatch[1]);
          break;
        }
      }
      
      const image = $('[data-testid="product-image"]').attr('src') || 
                   $('meta[property="og:image"]').attr('content');
      
      return { title: title || null, price: price || null, image: image || null, store: 'Zalando' };
    } catch (e) {
      console.error('Zalando server scraper error:', e);
      return { title: null, price: null, image: null, store: 'Zalando' };
    }
  }
};

// Fallback scraper
const serverFallbackScraper = async (html, url) => {
  const $ = cheerio.load(html);
  try {
    const title = $("meta[property='og:title']").attr('content') ||
                 $("title").text() ||
                 $("h1").first().text() || "";
    
    let price = null;
    $('script[type="application/ld+json"]').each((i, script) => {
      try {
        const data = JSON.parse($(script).html());
        const items = Array.isArray(data) ? data : [data];
        
        for (const item of items) {
          if (item['@type'] === 'Product' && item.offers) {
            const offers = Array.isArray(item.offers) ? item.offers : [item.offers];
            for (const offer of offers) {
              if (offer.price) {
                price = parseFloat(offer.price);
                return false;
              }
            }
          }
        }
      } catch (e) {}
    });
    
    if (!price) {
      const priceSelectors = [
        '[class*="price"]:not([class*="strike"]):not([class*="old"])',
        '[itemprop="price"]',
        '[data-price]'
      ];
      
      for (const selector of priceSelectors) {
        const priceText = $(selector).first().text().replace(/[^0-9.,]/g, '').trim();
        const priceMatch = priceText.match(/(\d+(?:[.,]\d{2})?)/);
        if (priceMatch) {
          price = parseFloat(priceMatch[1].replace(',', '.'));
          if (price > 0.01 && price < 999999) break;
        }
      }
    }
    
    const image = $("meta[property='og:image']").attr('content') ||
                 $("img").first().attr('src') || "";
    
    const store = new URL(url).hostname.replace('www.', '').split('.')[0];
    
    return { title: title.trim() || null, price: price || null, image: image || null, store: store || null };
  } catch (e) {
    console.error('Fallback server scraper error:', e);
    return { title: null, price: null, image: null, store: null };
  }
};

// Main server-side price checking function
async function checkProductPriceServer(productUrl) {
  try {
    console.log(`🔍 Server checking price for: ${productUrl}`);
    
    const headers = {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
      'Accept-Language': 'en-US,en;q=0.5',
      'Accept-Encoding': 'gzip, deflate, br',
      'DNT': '1',
      'Connection': 'keep-alive',
      'Upgrade-Insecure-Requests': '1',
    };

    const response = await axios.get(productUrl, {
      headers,
      timeout: 30000,
      maxRedirects: 5,
      validateStatus: (status) => status < 400
    });

    if (!response.data) {
      throw new Error('No content received');
    }

    const html = response.data;
    const domain = new URL(productUrl).hostname.replace('www.', '');
    
    let productInfo = null;
    for (const [key, scraper] of Object.entries(serverScrapers)) {
      if (domain.includes(key)) {
        console.log(`📦 Using ${key} server scraper`);
        productInfo = await scraper(html, productUrl);
        if (productInfo.price) break;
      }
    }
    
    if (!productInfo || !productInfo.price) {
      console.log('📦 Using fallback server scraper');
      productInfo = await serverFallbackScraper(html, productUrl);
    }
    
    if (productInfo.price) {
      productInfo.price = parseFloat(productInfo.price);
      if (isNaN(productInfo.price) || productInfo.price <= 0) {
        productInfo.price = null;
      }
    }
    
    console.log(`✅ Server price check result:`, productInfo);
    return productInfo;
    
  } catch (error) {
    console.error(`❌ Server price check failed for ${productUrl}:`, error.message);
    return { title: null, price: null, image: null, store: null, error: error.message };
  }
}

// Models
const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    trim: true,
    lowercase: true,
    match: [/^[^\s@]+@[^\s@]+\.[^\s@]+$/, 'Please enter a valid email'],
    index: true
  },
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: [8, 'Password must be at least 8 characters long']
  },
  createdAt: {
    type: Date,
    default: Date.now,
    index: true
  },
  lastLogin: {
    type: Date,
    default: Date.now
  },
  isActive: {
    type: Boolean,
    default: true
  }
});

const productSchema = new mongoose.Schema({
  productName: {
    type: String,
    required: [true, 'Product name is required'],
    trim: true,
    maxlength: [200, 'Product name too long']
  },
  productUrl: {
    type: String,
    required: [true, 'Product URL is required'],
    trim: true,
    validate: {
      validator: function(v) {
        return /^https?:\/\/.+/.test(v);
      },
      message: 'Please enter a valid URL'
    }
  },
  currentPrice: {
    type: Number,
    required: [true, 'Current price is required'],
    min: [0.01, 'Price must be greater than 0']
  },
  targetPrice: {
    type: Number,
    required: [true, 'Target price is required'],
    min: [0.01, 'Price must be greater than 0']
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  productImage: {
    type: String,
    trim: true
  },
  notificationSent: {
    type: Boolean,
    default: false,
    index: true
  },
  lastChecked: {
    type: Date,
    default: Date.now,
    index: true
  },
  createdAt: {
    type: Date,
    default: Date.now,
    index: true
  },
  isActive: {
    type: Boolean,
    default: true,
    index: true
  },
  checkCount: {
    type: Number,
    default: 0
  },
  store: {
    type: String,
    trim: true
  }
});

const priceHistorySchema = new mongoose.Schema({
  productId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Product',
    required: true,
    index: true
  },
  price: {
    type: Number,
    required: true,
    min: 0.01
  },
  date: {
    type: Date,
    default: Date.now,
    index: true
  }
});

const User = mongoose.model('User', userSchema);
const Product = mongoose.model('Product', productSchema);
const PriceHistory = mongoose.model('PriceHistory', priceHistorySchema);

// Auth Middleware
const authenticate = async (req, res, next) => {
  try {
    const authHeader = req.header('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ 
        success: false,
        error: 'Authentication required',
        code: 'AUTH_REQUIRED'
      });
    }
    
    const token = authHeader.replace('Bearer ', '');
    
    if (!process.env.JWT_SECRET) {
      return res.status(500).json({
        success: false,
        error: 'Server configuration error',
        code: 'CONFIG_ERROR'
      });
    }
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded._id).select('-password');
    
    if (!user || !user.isActive) {
      return res.status(401).json({ 
        success: false,
        error: 'Invalid or expired token',
        code: 'INVALID_TOKEN'
      });
    }
    
    req.user = user;
    next();
  } catch (err) {
    if (err.name === 'JsonWebTokenError') {
      return res.status(401).json({
        success: false,
        error: 'Invalid token format',
        code: 'INVALID_TOKEN'
      });
    } else if (err.name === 'TokenExpiredError') {
      return res.status(401).json({
        success: false,
        error: 'Token expired',
        code: 'TOKEN_EXPIRED'
      });
    }
    
    console.error('Authentication error:', err);
    res.status(401).json({ 
      success: false,
      error: 'Authentication failed',
      code: 'AUTH_FAILED'
    });
  }
};

// Auth Endpoints
app.post('/register', checkDBConnection, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ 
        success: false,
        error: 'Email and password are required',
        code: 'MISSING_FIELDS'
      });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({
        success: false,
        error: 'Please enter a valid email address',
        code: 'INVALID_EMAIL'
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        success: false,
        error: 'Password must be at least 8 characters long',
        code: 'WEAK_PASSWORD'
      });
    }

    const existingUser = await User.findOne({ email: email.toLowerCase() })
      .maxTimeMS(10000)
      .lean();
      
    if (existingUser) {
      return res.status(409).json({ 
        success: false,
        error: 'Email already registered',
        code: 'EMAIL_EXISTS'
      });
    }

    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const user = new User({ 
      email: email.toLowerCase(), 
      password: hashedPassword 
    });
    
    await user.save();

    const token = jwt.sign(
      { _id: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '30d' }
    );

    await User.findByIdAndUpdate(user._id, { lastLogin: new Date() });

    res.status(201).json({
      success: true,
      message: 'Account created successfully',
      user: { 
        id: user._id, 
        email: user.email,
        createdAt: user.createdAt
      },
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
    
    res.status(500).json({
      success: false,
      error: 'Registration failed',
      code: 'SERVER_ERROR'
    });
  }
});

app.post('/login', checkDBConnection, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        error: 'Email and password are required',
        code: 'MISSING_FIELDS'
      });
    }

    const user = await User.findOne({ 
      email: email.toLowerCase(),
      isActive: true 
    }).maxTimeMS(10000);
    
    if (!user) {
      return res.status(401).json({ 
        success: false,
        error: 'Invalid email or password',
        code: 'INVALID_CREDENTIALS'
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ 
        success: false,
        error: 'Invalid email or password',
        code: 'INVALID_CREDENTIALS'
      });
    }

    const token = jwt.sign(
      { _id: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '30d' }
    );

    await User.findByIdAndUpdate(user._id, { lastLogin: new Date() });

    res.json({ 
      success: true,
      message: 'Login successful',
      user: { 
        id: user._id, 
        email: user.email,
        lastLogin: new Date()
      },
      token 
    });

  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Login failed',
      code: 'SERVER_ERROR'
    });
  }
});

// Server-side price checking endpoint
app.post('/check-price', authenticate, async (req, res) => {
  try {
    const { url } = req.body;
    
    if (!url) {
      return res.status(400).json({
        success: false,
        error: 'URL is required',
        code: 'MISSING_URL'
      });
    }
    
    try {
      new URL(url);
    } catch (e) {
      return res.status(400).json({
        success: false,
        error: 'Invalid URL format',
        code: 'INVALID_URL'
      });
    }
    
    const productInfo = await checkProductPriceServer(url);
    
    res.json({
      success: true,
      data: productInfo
    });
    
  } catch (error) {
    console.error('Price check endpoint error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to check price',
      code: 'SERVER_ERROR'
    });
  }
});

// Product Endpoints
app.get('/products', authenticate, checkDBConnection, async (req, res) => {
  try {
    const products = await Product.find({ 
      userId: req.user._id,
      isActive: true 
    })
    .sort({ createdAt: -1 })
    .maxTimeMS(10000)
    .lean();
    
    res.json(products);
  } catch (err) {
    console.error('Get products error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Failed to fetch products',
      code: 'SERVER_ERROR'
    });
  }
});

app.get('/products/sorted', authenticate, checkDBConnection, async (req, res) => {
  try {
    const products = await Product.find({ 
      userId: req.user._id,
      isActive: true 
    })
    .maxTimeMS(10000)
    .lean();
    
    const sortedProducts = products.sort((a, b) => {
      const aReached = a.currentPrice <= a.targetPrice;
      const bReached = b.currentPrice <= b.targetPrice;
      
      if (aReached && !bReached) return -1;
      if (!aReached && bReached) return 1;
      
      const aDrop = (a.currentPrice - a.targetPrice) / a.targetPrice;
      const bDrop = (b.currentPrice - b.targetPrice) / b.targetPrice;
      return aDrop - bDrop;
    });
    
    res.json(sortedProducts);
  } catch (err) {
    console.error('Get sorted products error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Failed to fetch products',
      code: 'SERVER_ERROR'
    });
  }
});

app.post('/track-product', authenticate, checkDBConnection, async (req, res) => {
  try {
    const { productName, productUrl, productImage, currentPrice, targetPrice, store } = req.body;

    if (!productName || !productUrl || !currentPrice || !targetPrice) {
      return res.status(400).json({
        success: false,
        error: 'Missing required fields',
        code: 'MISSING_FIELDS'
      });
    }

    if (currentPrice <= 0 || targetPrice <= 0) {
      return res.status(400).json({
        success: false,
        error: 'Prices must be greater than 0',
        code: 'INVALID_PRICE'
      });
    }

    if (targetPrice >= currentPrice) {
      return res.status(400).json({
        success: false,
        error: 'Target price must be lower than current price',
        code: 'INVALID_TARGET'
      });
    }

    const existingProduct = await Product.findOne({
      userId: req.user._id,
      productUrl: productUrl,
      isActive: true
    });

    if (existingProduct) {
      return res.status(409).json({
        success: false,
        error: 'You are already tracking this product',
        code: 'ALREADY_TRACKING'
      });
    }

    const userProductCount = await Product.countDocuments({
      userId: req.user._id,
      isActive: true
    });

    if (userProductCount >= 100) {
      return res.status(429).json({
        success: false,
        error: 'Product tracking limit reached (100 products)',
        code: 'LIMIT_EXCEEDED'
      });
    }

    const product = new Product({
      productName: productName.trim(),
      productUrl: productUrl.trim(),
      productImage: productImage?.trim(),
      currentPrice: parseFloat(currentPrice),
      targetPrice: parseFloat(targetPrice),
      store: store?.trim(),
      userId: req.user._id
    });

    await product.save();

    const priceHistory = new PriceHistory({
      productId: product._id,
      price: product.currentPrice
    });
    await priceHistory.save();

    res.status(201).json({
      success: true,
      message: 'Product tracking started',
      product: {
        id: product._id,
        productName: product.productName,
        currentPrice: product.currentPrice,
        targetPrice: product.targetPrice,
        createdAt: product.createdAt
      }
    });
  } catch (err) {
    console.error('Track product error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Failed to track product',
      code: 'SERVER_ERROR'
    });
  }
});

// Email service
app.post('/send-price-alert', authenticate, async (req, res) => {
  try {
    if (!transporter) {
      return res.status(503).json({
        success: false,
        error: 'Email service not available',
        code: 'EMAIL_UNAVAILABLE'
      });
    }

    const { to, subject, text, html } = req.body;

    if (!to || !subject) {
      return res.status(400).json({
        success: false,
        error: 'Email address and subject are required',
        code: 'MISSING_FIELDS'
      });
    }

    const mailOptions = {
      from: `"Price Tracker" <${process.env.EMAIL_USER}>`,
      to,
      subject,
      text,
      html: html || text,
      priority: 'high'
    };

    await transporter.sendMail(mailOptions);
    
    res.json({ 
      success: true,
      message: 'Email sent successfully'
    });
  } catch (error) {
    console.error('Email sending error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to send email',
      code: 'EMAIL_FAILED'
    });
  }
});

app.get('/products/pending-notifications', authenticate, checkDBConnection, async (req, res) => {
  try {
    const products = await Product.aggregate([
      {
        $match: {
          userId: req.user._id,
          isActive: true,
          notificationSent: false,
          $expr: { $lte: ['$currentPrice', '$targetPrice'] }
        }
      },
      {
        $sort: { createdAt: -1 }
      }
    ]);
    
    res.json(products);
  } catch (err) {
    console.error('Get pending notifications error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Failed to fetch pending notifications',
      code: 'SERVER_ERROR'
    });
  }
});

app.patch('/product/:id', authenticate, checkDBConnection, async (req, res) => {
  try {
    const { id } = req.params;
    const updateData = { ...req.body };

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid product ID',
        code: 'INVALID_ID'
      });
    }

    updateData.lastChecked = new Date();
    
    const product = await Product.findOneAndUpdate(
      { _id: id, userId: req.user._id, isActive: true },
      updateData,
      { new: true, runValidators: true }
    );

    if (!product) {
      return res.status(404).json({
        success: false,
        error: 'Product not found',
        code: 'NOT_FOUND'
      });
    }

    res.json(product);
  } catch (err) {
    console.error('Update product error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Failed to update product',
      code: 'SERVER_ERROR'
    });
  }
});

app.delete('/product/:id', authenticate, checkDBConnection, async (req, res) => {
  try {
    const { id } = req.params;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid product ID',
        code: 'INVALID_ID'
      });
    }

    const product = await Product.findOneAndUpdate(
      { _id: id, userId: req.user._id },
      { isActive: false },
      { new: true }
    );

    if (!product) {
      return res.status(404).json({ 
        success: false,
        error: 'Product not found',
        code: 'NOT_FOUND'
      });
    }

    await PriceHistory.deleteMany({ productId: id });

    res.json({ 
      success: true,
      message: 'Product tracking stopped'
    });
  } catch (err) {
    console.error('Delete product error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Failed to delete product',
      code: 'SERVER_ERROR'
    });
  }
});

app.post('/price-history', authenticate, checkDBConnection, async (req, res) => {
  try {
    const { productId, price } = req.body;

    if (!productId || !price) {
      return res.status(400).json({
        success: false,
        error: 'Product ID and price are required',
        code: 'MISSING_FIELDS'
      });
    }

    const product = await Product.findOne({
      _id: productId,
      userId: req.user._id,
      isActive: true
    });

    if (!product) {
      return res.status(404).json({
        success: false,
        error: 'Product not found',
        code: 'NOT_FOUND'
      });
    }

    const history = new PriceHistory({
      productId,
      price: parseFloat(price)
    });
    
    await history.save();
    
    res.status(201).json(history);
  } catch (err) {
    console.error('Save price history error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Failed to save price history',
      code: 'SERVER_ERROR'
    });
  }
});

app.get('/price-history/:productId', authenticate, checkDBConnection, async (req, res) => {
  try {
    const { productId } = req.params;

    const product = await Product.findOne({
      _id: productId,
      userId: req.user._id
    });

    if (!product) {
      return res.status(404).json({
        success: false,
        error: 'Product not found',
        code: 'NOT_FOUND'
      });
    }

    const history = await PriceHistory.find({ productId })
      .sort({ date: -1 })
      .limit(100)
      .lean();
      
    res.json(history);
  } catch (err) {
    console.error('Get price history error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Failed to fetch price history',
      code: 'SERVER_ERROR'
    });
  }
});

// BACKGROUND PRICE CHECKING SYSTEM
async function performBackgroundPriceChecks() {
  try {
    const products = await Product.find({ 
      isActive: true,
      lastChecked: { $lt: new Date(Date.now() - 8 * 60 * 1000) }
    }).limit(50);
    
    console.log(`🔄 Background checking ${products.length} products server-side`);
    
    for (const product of products) {
      try {
        const result = await checkProductPriceServer(product.productUrl);
        
        if (result.price && !result.error) {
          const oldPrice = product.currentPrice;
          const newPrice = result.price;
          const priceChanged = Math.abs(oldPrice - newPrice) > 0.01;
          const targetReached = newPrice <= product.targetPrice;
          
          await Product.findByIdAndUpdate(product._id, {
            currentPrice: newPrice,
            lastChecked: new Date(),
            $inc: { checkCount: 1 }
          });
          
          if (priceChanged) {
            await PriceHistory.create({
              productId: product._id,
              price: newPrice
            });
            
            console.log(`💰 Price updated for ${product.productName}: €${oldPrice} → €${newPrice}`);
          }
          
          if (targetReached && !product.notificationSent) {
            const user = await User.findById(product.userId);
            if (user && transporter) {
              try {
                await transporter.sendMail({
                  from: `"Price Tracker" <${process.env.EMAIL_USER}>`,
                  to: user.email,
                  subject: `🎯 Price Alert: ${product.productName}`,
                  html: `
                    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                      <h2 style="color: #10b981;">🎉 Your target price has been reached!</h2>
                      <p><strong>${product.productName}</strong></p>
                      <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;">
                        <p style="margin: 5px 0;"><strong>Current Price:</strong> <span style="color: #10b981; font-size: 18px; font-weight: bold;">€${newPrice.toFixed(2)}</span></p>
                        <p style="margin: 5px 0;"><strong>Your Target:</strong> €${product.targetPrice.toFixed(2)}</p>
                        <p style="margin: 5px 0;"><strong>You save:</strong> <span style="color: #10b981;">€${(product.targetPrice - newPrice).toFixed(2)}</span></p>
                      </div>
                      <p><a href="${product.productUrl}" style="background: #4f46e5; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">View Product</a></p>
                      <p style="color: #6b7280; font-size: 14px;">Happy shopping! 🛍️</p>
                    </div>
                  `
                });
                
                console.log(`📧 Email sent to ${user.email} for ${product.productName}`);
              } catch (emailError) {
                console.error('Email sending error:', emailError);
              }
            }
            
            await Product.findByIdAndUpdate(product._id, { notificationSent: true });
          }
        } else {
          console.warn(`⚠️ Failed to get price for ${product.productName}: ${result.error || 'Unknown error'}`);
          
          await Product.findByIdAndUpdate(product._id, {
            lastChecked: new Date(),
            $inc: { checkCount: 1 }
          });
        }
        
        await new Promise(resolve => setTimeout(resolve, 3000));
        
      } catch (error) {
        console.error(`Error checking ${product.productName}:`, error);
      }
    }
    
    console.log(`✅ Background price check completed for ${products.length} products`);
    
  } catch (error) {
    console.error('Background price check error:', error);
  }
}

// Error Handling
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  
  const isDevelopment = process.env.NODE_ENV === 'development';
  
  res.status(err.status || 500).json({ 
    success: false,
    error: isDevelopment ? err.message : 'Internal server error',
    code: 'INTERNAL_ERROR',
    ...(isDevelopment && { stack: err.stack })
  });
});

app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    error: 'Endpoint not found',
    code: 'NOT_FOUND',
    path: req.originalUrl
  });
});

// Server startup
const PORT = process.env.PORT || 3000;

const startServer = () => {
  app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`⏰ Started at: ${new Date().toISOString()}`);
    console.log(`🔍 Server-side price checking enabled!`);
  });
};

const initialize = async () => {
  try {
    initializeEmailTransporter();
    startServer();
    await connectDB();
    
    console.log('🎉 Application initialization completed');
    
    setTimeout(() => {
      console.log('🚀 Starting background price checking system...');
      performBackgroundPriceChecks();
      setInterval(performBackgroundPriceChecks, 15 * 60 * 1000);
    }, 2 * 60 * 1000);
    
  } catch (error) {
    console.error('💥 Application initialization failed:', error);
    process.exit(1);
  }
};

initialize();

module.exports = { 
  checkProductPriceServer, 
  performBackgroundPriceChecks,
  app 
};