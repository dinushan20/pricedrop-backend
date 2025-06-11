require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');

const app = express();
app.use(cors());
app.use(express.json());

// Global CORS Headers Middleware
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
  next();
});

// Test route
app.get('/', (req, res) => {
  res.send('PriceDrop Backend is running');
});

const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGODB_URI;

// MongoDB connection
mongoose.connect(MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('MongoDB connected successfully'))
.catch(err => console.error('MongoDB connection error:', err));

// Nodemailer setup
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// User Schema
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);

// Price History Schema
const priceHistorySchema = new mongoose.Schema({
  productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' },
  price: Number,
  createdAt: { type: Date, default: Date.now }
});
const PriceHistory = mongoose.model('PriceHistory', priceHistorySchema);

// Product Schema
const productSchema = new mongoose.Schema({
  productName: { type: String, required: true },
  productUrl: { type: String, required: true },
  productImage: String,
  currentPrice: { type: Number, required: true },
  targetPrice: { type: Number, required: true },
  createdAt: { type: Date, default: Date.now },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  similarProducts: [
    {
      productId: mongoose.Schema.Types.ObjectId,
      price: Number,
      url: String
    }
  ]
});
const Product = mongoose.model('Product', productSchema);

// Authentication Middleware
const authenticate = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded._id);
    if (!user) throw new Error();
    req.user = user;
    req.token = token;
    next();
  } catch (e) {
    res.status(401).send({ error: 'Please authenticate.' });
  }
};

// User Registration
app.post('/register', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ error: 'Email already in use' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ email, password: hashedPassword });
    await user.save();

    const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

    res.status(201).json({
      user: { email: user.email, id: user._id },
      token
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed. Please try again.' });
  }
});

// User Login
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) throw new Error('Invalid login credentials');

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) throw new Error('Invalid login credentials');

    const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET);
    res.send({ user, token });
  } catch (error) {
    res.status(400).send({ error: error.message });
  }
});

// GET all products for a user
app.get('/products', authenticate, async (req, res) => {
  try {
    const products = await Product.find({ userId: req.user._id }).sort({ createdAt: -1 });
    res.json(products);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching products', error: error.message });
  }
});

// POST: track a new product
app.post('/track-product', authenticate, async (req, res) => {
  try {
    const { productUrl, productName, productImage, currentPrice, targetPrice } = req.body;

    const similarProducts = await Product.find({
      productName: { $regex: productName, $options: 'i' },
      userId: { $ne: req.user._id }
    }).sort({ currentPrice: 1 }).limit(3);

    const product = new Product({
      productName,
      productUrl,
      productImage,
      currentPrice,
      targetPrice,
      userId: req.user._id,
      similarProducts: similarProducts.map(p => ({
        productId: p._id,
        price: p.currentPrice,
        url: p.productUrl
      }))
    });

    await product.save();

    await new PriceHistory({
      productId: product._id,
      price: currentPrice
    }).save();

    res.status(201).json({ product, similarProducts });
  } catch (error) {
    res.status(500).json({ message: 'Error tracking product', error: error.message });
  }
});

// GET: compare prices for a product
app.get('/compare-prices/:productId', authenticate, async (req, res) => {
  try {
    const product = await Product.findById(req.params.productId);
    if (!product) return res.status(404).json({ message: 'Product not found' });

    const similarProducts = await Product.find({
      productName: { $regex: product.productName, $options: 'i' },
      userId: { $ne: req.user._id }
    }).sort({ currentPrice: 1 }).limit(3);

    res.json(similarProducts);
  } catch (error) {
    res.status(500).json({ message: 'Error comparing prices', error: error.message });
  }
});

// PATCH: update product price & notify if target reached
app.patch('/product/:id', authenticate, async (req, res) => {
  try {
    const { currentPrice } = req.body;
    const product = await Product.findById(req.params.id);
    if (!product) return res.status(404).json({ message: 'Product not found' });

    if (product.userId.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: 'Unauthorized' });
    }

    product.currentPrice = currentPrice;
    await product.save();

    await new PriceHistory({
      productId: product._id,
      price: currentPrice
    }).save();

    if (currentPrice <= product.targetPrice) {
      const user = await User.findById(req.user._id);
      await transporter.sendMail({
        to: user.email,
        subject: `🎉 Price Target Reached for ${product.productName}`,
        html: `
          <h2>Your price target has been reached!</h2>
          <p>${product.productName} is now at €${currentPrice} (your target: €${product.targetPrice})</p>
          <p><a href="${product.productUrl}">Click here to view the product</a></p>
        `
      });
    }

    res.json(product);
  } catch (error) {
    res.status(500).json({ message: 'Error updating product', error: error.message });
  }
});

// DELETE product
app.delete('/product/:id', authenticate, async (req, res, next) => {
  try {
    const deleted = await Product.findOneAndDelete({
      _id: req.params.id,
      userId: req.user._id
    });
    if (!deleted) {
      return res.status(404).json({ message: 'Product not found or unauthorized' });
    }
    res.json({ message: 'Product deleted successfully' });
  } catch (error) {
    next(error);
  }
});

// Error middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Something broke!' });
});

// Server listener
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// Process error handlers
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});
