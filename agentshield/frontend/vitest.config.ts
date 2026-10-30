import { defineConfig } from "vitest/config"

export default defineConfig({
  test: {
    include: ["agentshield/frontend/src/**/*.test.ts"],
    environment: "node",
  },
})
