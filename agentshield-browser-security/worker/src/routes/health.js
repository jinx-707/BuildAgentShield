import { Router } from "express";

import { config } from "../config.js";
import { checkBrowserReadiness, closeExpiredContexts } from "../lib/browser.js";
import { EgressProxyError, getEgressHealthSnapshot } from "../lib/egress.js";

const router = Router();

function healthPayload(status, checks, detail) {
  return {
    status,
    service: config.serviceName,
    version: config.version,
    checks,
    ...(detail ? { detail } : {}),
  };
}

function liveHandler(req, res) {
  res.json(healthPayload("ok", { process: "ok" }));
}

router.get("/", liveHandler);
router.get("/live", liveHandler);

router.get("/ready", async (req, res) => {
  try {
    await closeExpiredContexts();
    const readiness = await checkBrowserReadiness();
    const checks = { browser: "ok" };
    if (readiness.egress.required) {
      checks.egress_proxy = "ok";
    }
    res.json(healthPayload("ok", checks));
  } catch (error) {
    req.log.warn({ err: error }, "browser_readiness_check_failed");

    if (error instanceof EgressProxyError) {
      res
        .status(503)
        .json(
          healthPayload(
            "degraded",
            {
              browser: "unknown",
              egress_proxy: getEgressHealthSnapshot().status,
            },
            "required egress proxy is not ready",
          ),
        );
      return;
    }

    res
      .status(503)
      .json(
        healthPayload(
          "degraded",
          { browser: "unavailable" },
          "browser is not ready",
        ),
      );
  }
});

export default router;
