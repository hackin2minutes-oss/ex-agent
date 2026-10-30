const express = require('express');
const _ = require('lodash');

const app = express();
app.use(express.json());

app.post('/settings', (req, res) => {
  const defaults = { theme: 'light' };
  // Only the request's own keys are copied; no defaultsDeep call on request data.
  res.json({ ...defaults, ..._.pick(req.body, ['theme']) });
});

module.exports = app;
