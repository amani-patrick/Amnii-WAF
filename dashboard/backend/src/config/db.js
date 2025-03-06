const mysql = require('mysql');

const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'waf_db',
});

db.connect((err) => {
  if (err) throw err;
  console.log('Connected to MySQL database');
});
