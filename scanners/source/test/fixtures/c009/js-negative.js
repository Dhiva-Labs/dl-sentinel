'use strict';

const cors = require('cors');
const express = require('express');

const app = express();

const allowedOrigins = ['https://app.example.invalid'];

app.use(
  cors({
    origin: allowedOrigins,
    credentials: true,
  }),
);

module.exports = app;
