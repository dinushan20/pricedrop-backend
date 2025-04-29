const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const app = express();

app.use(cors());

// Handle unexpected errors
process.on('uncaughtException', (err) => {
  console.error('Unhandled Error:', err);
});
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection:', reason);
});

const PORT = process.env.PORT || 3000;

// MongoDB Connection
const MONGO_URI = "mongodb+srv://dinushanpricedrop:manuja123@pricedrop.2ngimi2.mongodb.net/?retryWrites=true&w=majority&appName=pricedrop";

mongoose.connect(MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('MongoDB connected'))
.catch((err) => console.error('MongoDB connection error:', err));

// Product Schema
const productSchema = new mongoose.Schema({
  productUrl: String,
  productName: String,
  price: Number,
  createdAt: { type: Date, default: Date.now }
});

const Product = mongoose.model('Product', productSchema);

app.use(express.json());

// Test Route
app.get('/', (req, res) => {
  res.status(200).send('PriceDrop App Backend is Working Now with MongoDB!');
});

// Track Product Route
app.post('/track-product', async (req, res) => {
  const { productUrl, productName, price } = req.body;

  if (!productUrl || !productName || !price) {
    return res.status(400).json({ message: 'Missing required fields.' });
  }

  try {
    const newProduct = new Product({ productUrl, productName, price });
    await newProduct.save();
    res.status(201).json({
      message: 'Product saved to database successfully',
      productUrl,
      productName,
      price
    });
  } catch (error) {
    console.error('Error saving product:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});
