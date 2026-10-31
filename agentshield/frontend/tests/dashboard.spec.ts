import { test, expect } from "@playwright/test"

test("dashboard and attack simulator work without a backend", async ({
  page,
}) => {
  const errors: string[] = []
  page.on("pageerror", (error) => errors.push(error.message))
  await page.setViewportSize({ width: 1440, height: 1100 })
  await page.goto("/")
  await expect(
    page.getByRole("heading", { name: "Security overview" }),
  ).toBeVisible()
  await expect(page.locator(".metric-card")).toHaveCount(4)
  await page.screenshot({
    path: "/tmp/agentshield-overview.png",
    fullPage: true,
  })
  await page
    .getByRole("button", { name: "Open attack simulator", exact: true })
    .click()
  await page.getByRole("button", { name: "Run all scenarios" }).click()
  await expect(page.getByText("Passed", { exact: true })).toHaveCount(10, {
    timeout: 15000,
  })
  await expect(page.getByText("Failed", { exact: true })).toHaveCount(0)
  await expect(page.getByText("Executed: no", { exact: true })).toHaveCount(10)
  expect(errors).toEqual([])
})

test("agent lifecycle, approval review, filtering, and demo login", async ({
  page,
}) => {
  await page.goto("/")
  await page
    .locator("nav")
    .getByRole("button", { name: "Agents", exact: true })
    .click()
  await page.getByRole("button", { name: "Create agent", exact: true }).click()
  await page.getByLabel("Agent name", { exact: true }).fill("test-agent")
  await page
    .getByRole("button", { name: "Create demo agent", exact: true })
    .click()
  await expect(
    page.getByRole("heading", { name: "Demo identity ready" }),
  ).toBeVisible()
  await page.getByRole("button", { name: "Done", exact: true }).click()
  await expect(page.getByText("test-agent", { exact: true })).toBeVisible()
  const row = page.getByRole("row").filter({ hasText: "test-agent" })
  await row.getByRole("button", { name: "Disable", exact: true }).click()
  await page
    .getByRole("button", { name: "Confirm disable", exact: true })
    .click()
  await expect(row.getByText("Disabled", { exact: true })).toBeVisible()
  await page
    .locator("nav")
    .getByRole("button", { name: /Approval Queue/ })
    .click()
  await page
    .getByRole("button", { name: "Review request", exact: true })
    .first()
    .click()
  await page
    .getByPlaceholder("Add context for your decision...")
    .fill("Safe demo review")
  await page
    .getByRole("button", { name: "Approve demo request", exact: true })
    .click()
  await page.getByRole("button", { name: "Approved 1", exact: true }).click()
  await expect(
    page.getByText("Send quarterly report to external recipient", {
      exact: true,
    }),
  ).toBeVisible()
  await page
    .locator("nav")
    .getByRole("button", { name: "Audit Logs", exact: true })
    .click()
  await page.getByLabel("Search audit events").fill("Demo human review")
  await expect(page.locator("tbody tr")).toHaveCount(1)
  await page
    .getByRole("button", { name: "Open account menu", exact: true })
    .click()
  await page
    .getByRole("button", { name: "Sign out of demo", exact: true })
    .click()
  await page.getByLabel("Password", { exact: true }).fill("demo-password")
  await page
    .getByRole("button", { name: "Enter demo workspace", exact: true })
    .click()
  await expect(page.locator(".sidebar")).toBeVisible()
})

test("mobile layout and navigation fit the viewport", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await page.goto("/")
  await expect(
    page.getByRole("heading", { name: "Security overview" }),
  ).toBeVisible()
  await page.screenshot({ path: "/tmp/agentshield-mobile.png", fullPage: true })
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true)
  await page
    .getByRole("button", { name: "Open navigation", exact: true })
    .click()
  await page
    .locator("nav")
    .getByRole("button", { name: "Agents", exact: true })
    .click()
  await expect(
    page.getByRole("heading", { name: "Agents", exact: true }),
  ).toBeVisible()
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true)
})

test("permissions, policies, quarantine, settings, and workspace search", async ({
  page,
}) => {
  await page.goto("/")
  await page
    .locator("nav")
    .getByRole("button", { name: "Capabilities & Permissions" })
    .click()
  const documents = page.getByRole("switch", {
    name: "Enable Documents",
    exact: true,
  })
  await expect(documents).toHaveAttribute("aria-checked", "true")
  await documents.click()
  await expect(documents).toHaveAttribute("aria-checked", "false")
  await page
    .getByRole("button", { name: "Configure scope & restrictions" })
    .first()
    .click()
  await page.getByLabel("Resource scope").fill("/workspace/research/**")
  await page.getByRole("button", { name: "Save restrictions" }).click()
  await page
    .getByRole("button", { name: "Configure scope & restrictions" })
    .first()
    .click()
  await expect(page.getByLabel("Resource scope")).toHaveValue(
    "/workspace/research/**",
  )
  await page.getByRole("button", { name: "Close dialog" }).click()
  await page
    .locator("nav")
    .getByRole("button", { name: "Policy Manager" })
    .click()
  await page.getByRole("button", { name: "New policy", exact: true }).click()
  await page.getByLabel("Policy name").fill("Demo test policy")
  await page
    .getByLabel("Description", { exact: true })
    .fill("A draft used by the browser test")
  await page.getByLabel("Rule definition").fill("DENY when testing")
  await page.getByRole("button", { name: "Create draft" }).click()
  const policy = page
    .locator(".policy-card")
    .filter({ hasText: "Demo test policy" })
  await expect(policy.getByText("Inactive", { exact: true })).toBeVisible()
  await policy.getByRole("button", { name: "View policy" }).click()
  await page
    .getByRole("button", { name: "Activate policy", exact: true })
    .click()
  await expect(policy.getByText("Active", { exact: true })).toBeVisible()
  await page
    .locator(".sidebar")
    .getByRole("button", { name: /Quarantine/ })
    .click()
  await expect(page.locator(".quarantine-row")).toHaveCount(3)
  await page
    .locator(".quarantine-row")
    .first()
    .getByRole("button", { name: "Delete" })
    .click()
  await expect(page.locator(".quarantine-row")).toHaveCount(2)
  await page
    .locator(".sidebar")
    .getByRole("button", { name: "Settings", exact: true })
    .click()
  await page
    .getByLabel("Workspace name", { exact: true })
    .fill("Research workspace")
  await page.getByRole("button", { name: "Save preferences" }).click()
  await expect(page.locator(".workspace-switch")).toContainText(
    "Research workspace",
  )
  await page.getByRole("button", { name: /Search anything/ }).click()
  await page
    .getByPlaceholder("Search pages, agents, policies...")
    .fill("Attack Simulator")
  await page
    .locator(".search-results")
    .getByRole("button", { name: /Attack Simulator/ })
    .click()
  await expect(
    page.getByRole("heading", { name: "Attack Simulator", exact: true }),
  ).toBeVisible()
})
