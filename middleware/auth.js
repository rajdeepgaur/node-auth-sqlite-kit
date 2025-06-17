const jwt = require('jsonwebtoken');

const JWT_SECRET = '123456789'; // In production, use environment variables

function authenticateToken(req, res, next) {
  const token = req.cookies.token;

  if (!token) {
    return res.status(401).send('Access denied. Please login.');
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).send('Invalid token.');
    }

    req.user = user; // user data from token
    next();
  });
}

module.exports = { authenticateToken, JWT_SECRET };
