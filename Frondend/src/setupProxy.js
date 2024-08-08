const { createProxyMiddleware } = require('http-proxy-middleware');

module.exports = function(app) {
  app.use(
    '/dev',
    createProxyMiddleware({
      target: 'https://z3ehzglkde.execute-api.us-east-1.amazonaws.com',
      changeOrigin: true,
    })
  );
};
