const express = require("express");
const db = require("./db");
const app = express();

app.get("/search", (req, res) => {
  const term = req.query.term;
  const sql = `SELECT * FROM products WHERE name = '${term}'`;
  db.query(sql); // SINK:tainted-local
  res.send("ok");
});

app.post("/items", (req, res) => {
  const name = req.body.name;
  db.query("SELECT * FROM items WHERE name = '" + name + "'"); // SINK:concat-direct
});

app.get("/constant", (req, res) => {
  db.query("SELECT 1"); // SINK:constant
});

app.get("/reassigned", (req, res) => {
  let q = req.query.q;
  q = "SELECT 1";
  db.query(q); // SINK:reassigned
});

function build(input) {
  return db.query(input); // SINK:unrouted
}

module.exports = { build };
