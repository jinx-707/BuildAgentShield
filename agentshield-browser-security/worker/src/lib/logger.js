import pino from "pino";

import { config } from "../config.js";

export const logger = pino({
  level: config.logLevel,
  base: {
    service: config.serviceName,
    version: config.version,
  },
  timestamp: pino.stdTimeFunctions.isoTime,
  formatters: {
    level(label) {
      return { level: label };
    },
  },
  redact: {
    paths: [
      "req.headers.authorization",
      "req.headers.cookie",
      "res.headers.set-cookie",
    ],
    censor: "[redacted]",
  },
});
