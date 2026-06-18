const server = require('../../index.js');

module.exports = (req, res) => {
  const { videoId } = req.query || {};
  if (videoId) req.url = `/probe/${videoId}${req.url.includes('?') ? '?' + req.url.split('?')[1] : ''}`;
  server.emit('request', req, res);
};
