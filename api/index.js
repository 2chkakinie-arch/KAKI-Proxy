const server = require('../index.js');

module.exports = (req, res) => {
  // Default route — show health info
  if (!req.url || req.url === '/api' || req.url === '/api/') req.url = '/';
  server.emit('request', req, res);
};
