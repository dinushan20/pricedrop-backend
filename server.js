const express = require('express');
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

// Root route
app.get('/', (req, res) => {
  res.send('PriceDrop App Backend is now Working!');
});

// Track product route
app.post('/track-product', (req, res) => {
  const { productUrl, productName, price } = req.body;
  res.status(201).json({
    message: 'Product tracked successfully!',
    productUrl,
    productName,
    price
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server started successfully on port ${PORT}`);
});
