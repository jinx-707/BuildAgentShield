import { config } from "../config.js";

const LEVELS = { debug: 10, info: 20, warn: 30, error: 40 };

function emit(level, event, fields = {}) {
  if ((LEVELS[level] ?? 20) < (LEVELS[config.logLevel] ?? 20)) {
    return;
  }
  const record = {
    timestamp: new Date().toISOString(),
    level,
    service: config.serviceName,
    version: config.version,
    event,
    ...fields,
  };
  const line = JSON.stringify(record);
  if (level === "error") {
    process.stderr.write(`${line}\n`);
  } else {
    process.stdout.write(`${line}\n`);
  }
}

export const logger = {
  debug: (event, fields) => emit("debug", event, fields),
  info: (event, fields) => emit("info", event, fields),
  warn: (event, fields) => emit("warn", event, fields),
  error: (event, fields) => emit("error", event, fields),
};
