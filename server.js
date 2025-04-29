const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const app = express();

app.use(cors());
app.use(express.json());

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
  productImage: String, // ✅ added field
  price: Number,
  createdAt: { type: Date, default: Date.now }
});

const Product = mongoose.model('Product', productSchema);

// Routes

// GET all products
app.get('/products', async (req, res) => {
  try {
    const products = await Product.find().sort({ createdAt: -1 });
    res.json(products);
  } catch (error) {
    console.error('Error fetching products:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// POST: track a new product
app.post('/track-product', async (req, res) => {
  const { productUrl, productName, productImage, price } = req.body;

  if (!productUrl || !productName || !price) {
    return res.status(400).json({ message: 'Missing required fields.' });
  }

  try {
    const newProduct = new Product({ productUrl, productName, productImage, price });
    await newProduct.save();
    res.status(201).json({
      message: 'Product saved to database successfully',
      productUrl,
      productName,
      productImage,
      price
    });
  } catch (error) {
    console.error('Error saving product:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// DELETE: remove product by ID
app.delete('/product/:id', async (req, res) => {
  try {
    await Product.findByIdAndDelete(req.params.id);
    res.json({ message: 'Product deleted' });
  } catch (error) {
    console.error('Delete failed:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});
