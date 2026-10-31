import { config } from "./config.js";
import { logger } from "./lib/logger.js";
import {
  computePolicyFingerprint,
  createEgressPolicy,
  validatePolicyConfig,
} from "./lib/policy.js";
import { createEgressProxy, createProxyHealthServer } from "./lib/proxy.js";

validatePolicyConfig(
  {
    allowedDomains: config.allowedDomains,
    defaultDomainPolicy: config.defaultDomainPolicy,
  },
  { environment: process.env.NODE_ENV || process.env.ENVIRONMENT || "development" },
);

const policyFingerprint = computePolicyFingerprint({
  allowedDomains: config.allowedDomains,
  blockedDomains: config.blockedDomains,
  defaultDomainPolicy: config.defaultDomainPolicy,
  allowedPorts: config.allowedPorts,
});

const policy = createEgressPolicy({
  allowedDomains: config.allowedDomains,
  blockedDomains: config.blockedDomains,
  defaultDomainPolicy: config.defaultDomainPolicy,
  allowedPorts: config.allowedPorts,
  allowPrivateNetworks: config.allowPrivateNetworks,
  dnsTimeoutMs: config.dnsTimeoutMs,
});

const proxy = createEgressProxy({
  policy,
  authToken: config.authToken,
  connectTimeoutMs: config.connectTimeoutMs,
});

const health = createProxyHealthServer({ policy, version: config.version });

proxy.listen(config.port, config.host, () => {
  logger.info("egress_proxy_started", {
    host: config.host,
    port: config.port,
    default_domain_policy: config.defaultDomainPolicy,
    allow_private_networks: config.allowPrivateNetworks,
    auth_required: Boolean(config.authToken),
    policy_fingerprint: policyFingerprint,
  });
});

health.listen(config.healthPort, config.healthHost, () => {
  logger.info("egress_health_started", {
    host: config.healthHost,
    port: config.healthPort,
  });
});

proxy.on("error", (error) => {
  logger.error("egress_proxy_error", { message: error.message });
  process.exitCode = 1;
});

health.on("error", (error) => {
  logger.error("egress_health_error", { message: error.message });
  process.exitCode = 1;
});

let shuttingDown = false;

function shutdown(signal) {
  if (shuttingDown) {
    return;
  }
  shuttingDown = true;
  logger.info("egress_proxy_shutdown_started", { signal });

  const forceExit = setTimeout(() => {
    logger.error("egress_proxy_shutdown_forced");
    process.exit(1);
  }, 10000);
  forceExit.unref();

  proxy.close(() => {
    health.close(() => {
      logger.info("egress_proxy_stopped");
      process.exit(0);
    });
  });
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
