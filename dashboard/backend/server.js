'use strict';

const express = require('express');
const path = require('path');
const PORT = process.env.PORT || 3000;

const app = express();

// Serve static files from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));

// Basic route for the root
app.get('/', (req, res) => {
  res.send('Welcome to the Amnii-WAF Node.js server!');
});

// Example API endpoint
app.get('/api/health', (req, res) => {
  res.json({ status: 'healthy', version: '1.0.0' });
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
