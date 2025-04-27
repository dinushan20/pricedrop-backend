process.on('uncaughtException', (err) => {
  console.error('Unhandled Error:', err);
});
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection:', reason);
});

const express = require('express');
const app = express();

// Important: Choreo requires listening on 0.0.0.0
const PORT = process.env.PORT || 3000;

app.use(express.json());

// Test route
app.get('/', (req, res) => {
  res.status(200).send('PriceDrop App Backend is Working Now');
});

// Track Product route
app.post('/track-product', (req, res) => {
  const { productUrl, productName, price } = req.body;
  if (!productUrl || !productName || !price) {
    return res.status(400).json({ message: 'Missing required fields.' });
  }

  res.status(201).json({
    message: 'Product tracked successfully',
    productUrl,
    productName,
    price
  });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});
