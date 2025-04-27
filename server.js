const express = require('express');
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

// Test route
app.get('/', (req, res) => {
  res.send('PriceDrop App Backend Working!');
});

// Example route to track product
app.post('/track-product', (req, res) => {
  const { productUrl, productName, price } = req.body;
  // Just dummy response for now
  res.status(201).json({ message: 'Product tracked successfully!', productUrl, productName, price });
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
