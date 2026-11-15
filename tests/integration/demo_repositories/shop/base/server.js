"use strict";
const http = require("http");
const { decodeAction } = require("react-server-dom-webpack");

const products = [
  { id: "batik-tulis", name: "Batik tulis, Solo", price: 450000 },
  { id: "batik-cap", name: "Batik cap, Pekalongan", price: 180000 },
];

function page(response, status, body) {
  response.statusCode = status;
  response.setHeader("Content-Type", "text/html; charset=utf-8");
  response.end(`<!doctype html><html><head><title>Toko Batik</title></head><body><h1>Toko Batik</h1>${body}</body></html>`);
}

http.createServer((request, response) => {
  // Add to cart and checkout are server actions, posted as action bodies.
  if (request.method === "POST" && request.url === "/action") {
    let body = "";
    request.on("data", (chunk) => { body += chunk; });
    request.on("end", () => {
      try { response.end(String(decodeAction(body))); }
      catch (error) { response.statusCode = 400; response.end("refused"); }
    });
    return;
  }
  if (request.method === "GET" && request.url === "/") {
    const items = products.map((p) => `<li>${p.name}: Rp ${p.price.toLocaleString("id-ID")}</li>`).join("");
    return page(response, 200, `<ul>${items}</ul>`);
  }
  page(response, 404, "<p>Not found</p>");
}).listen(Number(process.env.PORT) || 8080);
