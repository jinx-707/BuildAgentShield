import { defineConfig } from "@playwright/test"

export default defineConfig({
  testDir: "./tests",
  outputDir: "/tmp/agentshield-playwright",
  use: {
    baseURL:
      process.env.AGENTSHIELD_PREVIEW_URL ||
      `http://127.0.0.1:${process.env.PORT || 3000}`,
    headless: true,
  },
})
