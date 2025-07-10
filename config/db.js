const mysql = require('mysql2');

const pool = mysql.createPool({
  host: process.env.localhost,
  user: process.env.root,
  password: process.env.kunal123,
  database: process.env.computechdb,
  waitForConnections: true,
  connectionLimit: 10000000000000000000000000000,
  queueLimit: 0
});

pool.getConnection((err, connection) => {
  if (err) console.error('Database connection failed:', err);
  else {
    console.log('Connected to MySQL');
    connection.release();
  }
});

module.exports = pool.promise();
