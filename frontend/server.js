// CHAKRAVYUH - Frontend placeholder
const http = require("http");

const server = http.createServer((req, res) => {
  res.writeHead(200, { "Content-Type": "text/html" });
  res.end("<h1>CHAKRAVYUH</h1><p>Frontend placeholder</p>");
});

server.listen(3000, () => {
  console.log("Frontend listening on port 3000");
});
