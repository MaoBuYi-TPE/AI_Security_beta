// Executes in the locked Juice Shop image, without changing its router defaults.
const express = require('/juice-shop/node_modules/express');
const app = express();
app.use((request, response, next) => {
  response.on('finish', () => process.stdout.write(JSON.stringify({
    kind: 'request', time: Date.now() / 1000, method: request.method,
    target: request.originalUrl, path: request.path,
    peer: request.socket.remoteAddress, route: request.route?.path || null,
    parameters: request.params, status: response.statusCode
  }) + '\n'));
  next();
});
for (const path of ['/a/:x', '/a/:x/:y', '/users/v1/:username', '/ready']) {
  app.get(path, (request, response) => response.json({
    route: request.route.path, parameters: request.params
  }));
}
process.stdout.write(JSON.stringify({
  kind: 'versions', express: require('/juice-shop/node_modules/express/package.json').version,
  'path-to-regexp': require('/juice-shop/node_modules/path-to-regexp/package.json').version
}) + '\n');
app.listen(8080, '0.0.0.0');
