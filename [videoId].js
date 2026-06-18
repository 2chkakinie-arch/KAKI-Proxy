// Vercel Serverless function — delegates to the main server's request handler
const server = require('../../index.js');

module.exports = (req, res) => {
  // Rewrite path so the central router matches /stream/:videoId
  // Vercel passes /api/stream/[videoId]; we need /stream/:videoId
  const { videoId } = req.query || {};
  if (videoId) req.url = `/stream/${videoId}${req.url.includes('?') ? '?' + req.url.split('?')[1] : ''}`;
  server.emit('request', req, res);
};
