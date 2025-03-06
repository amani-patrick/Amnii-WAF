const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('../config/db');

let users = [];
const register = async (req, res) => {
  const { company_name,password, email} = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ company_name, password: hashedPassword, email });
  res.status(201).json({ message: 'User registered successfully' });
};
const login = async (req, res) => {
  const { email, password } = req.body;
  const user = users.find((user) => user.email === email);
  if (!user) {
    return res.status(401).json({ message: 'Invalid username or password' });
  }
  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    return res.status(401).json({ message: 'Invalid username or password' });
  }
  const token = jwt.sign({ userId: user.id }, 'secret');
  res.json({ token });
};

module.exports = { register,login };
