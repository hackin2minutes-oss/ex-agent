const express = require('express');
const _ = require('lodash');

const app = express();
app.use(express.json());

app.post('/settings', (req, res) => {
  const defaults = { theme: 'light' };
  // Request body merged into defaults with lodash: the vulnerable call.
  res.json(_.defaultsDeep(req.body, defaults));
});

module.exports = app;
