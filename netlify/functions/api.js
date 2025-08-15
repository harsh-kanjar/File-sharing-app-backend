const express = require("express");
const serverless = require("serverless-http");

const app = express();

// Simple route
app.get("/", (req, res) => {
  res.send("Hello World from Netlify!");
});

// Export the handler
module.exports.handler = serverless(app);
