const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('../config/db');


const register = async (req, res) => {
  const { company_name,password, email} = req.body;
  const emailExists = await Prisma.user.findUnique({
    where:{email}
  })
  if(emailExists){
    return res.status(400).json({ message: 'Email already exists' });
  }
  const hashedPassword = await bcrypt.hash(password, 10);
  const user=await Prisma.user.create({
    data:{
        company_name,
        email,
        password:hashedPassword
    }
  })
  res.status(201).json({ message: 'User registered successfully' ,user});
}

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

module.exports = { register,login};
