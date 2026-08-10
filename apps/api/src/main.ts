#!/usr/bin/env node
/**
 * Bin entry for the DL Sentinel API server. Binds the configured port and
 * starts serving. Configuration comes entirely from the environment
 * (SENTINEL_API_TOKEN, SENTINEL_SCAN_ROOT, SENTINEL_DATA_DIR, PORT, rate-limit
 * and body-size vars); see docs/architecture.md and docs/api.md.
 */
import { startServer } from './server.js';

startServer();
