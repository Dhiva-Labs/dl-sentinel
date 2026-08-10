'use strict';

const cors = require('cors');
const express = require('express');

const app = express();

app.use(
  cors({
    origin: '*',
    credentials: true,
  }),
);

module.exports = app;
