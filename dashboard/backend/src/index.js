const express = require('express');
const app = express();
const port = 3000;
const authRoutes = require('./routes/authRoutes');
const landingRoutes = require('./routes/landing');

app.use('/auth', authRoutes);
app.use('/', landingRoutes);

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}/`);
});
