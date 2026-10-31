/**
 * B1 — deterministic, bounded text extraction from an already-loaded page.
 *
 * The extractor runs entirely inside the page and returns plain text plus
 * structured records. Raw HTML never leaves the browser. Hidden content is
 * excluded by design: it is a common prompt-injection and credential-exfiltration
 * vector, so it is dropped and reported rather than silently included.
 */

import { config } from "../config.js";
import { truncateUtf8 } from "./content.js";

function collectPageData({
  maxLinks,
  maxLists,
  maxTables,
  maxTextChars,
}) {
function normalizeText(value) {
  return String(value ?? "")
    .replace(/[\u200b-\u200d\u2060\ufeff]/g, "")
    .replace(/[ \t\f\v]+/g, " ")
    .replace(/ *\n */g, "\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

function clampString(value, limit = 2000) {
  if (typeof value !== "string") {
    return "";
  }
  return normalizeText(value).slice(0, limit);
}

function httpUrl(value) {
  if (typeof value !== "string" || value.length > 4096) {
    return null;
  }
  try {
    const url = new URL(value);
    return url.protocol === "http:" || url.protocol === "https:"
      ? url.href
      : null;
  } catch {
    return null;
  }
}

  const BLOCK_TAGS = new Set([
    "address", "article", "aside", "blockquote", "br", "dd", "div", "dl",
    "dt", "fieldset", "figcaption", "figure", "footer", "form", "h1", "h2",
    "h3", "h4", "h5", "h6", "header", "hr", "li", "main", "nav", "ol", "p",
    "pre", "section", "table", "tbody", "td", "tfoot", "th", "thead", "tr",
    "ul",
  ]);
  const SKIP_TAGS = new Set([
    "script", "style", "noscript", "template", "svg", "canvas", "iframe",
    "object", "embed",
  ]);
  const HIDDEN_SELECTOR = [
    "[hidden]",
    "[inert]",
    '[aria-hidden="true"]',
  ].join(",");

  const hiddenCache = new WeakMap();

  function isHidden(element) {
    if (hiddenCache.has(element)) {
      return hiddenCache.get(element);
    }
    let hidden = false;
    let current = element;
    while (current && current.nodeType === Node.ELEMENT_NODE) {
      if (current.matches(HIDDEN_SELECTOR)) {
        hidden = true;
        break;
      }
      try {
        const style = window.getComputedStyle(current);
        if (
          style.display === "none" ||
          style.visibility === "hidden" ||
          style.visibility === "collapse" ||
          style.opacity === "0" ||
          style.contentVisibility === "hidden"
        ) {
          hidden = true;
          break;
        }
      } catch {
        /* keep walking */
      }
      current = current.parentElement;
    }
    hiddenCache.set(element, hidden);
    return hidden;
  }

  function visibleText(element, limit) {
    const parts = [];
    const walk = (node) => {
      if (node.nodeType === Node.TEXT_NODE) {
        if (node.nodeValue) {
          parts.push(node.nodeValue);
        }
        return;
      }
      if (node.nodeType !== Node.ELEMENT_NODE) {
        return;
      }
      const tag = node.tagName.toLowerCase();
      if (SKIP_TAGS.has(tag) || isHidden(node)) {
        return;
      }
      for (const child of node.childNodes) {
        walk(child);
      }
    };
    walk(element);
    return clampString(parts.join(" "), limit);
  }

  const root = document.body || document.documentElement;
  const textParts = [];
  let hiddenElementCount = 0;
  let textChars = 0;
  let textDomTruncated = false;

  function collectText(node) {
    if (textDomTruncated) {
      return;
    }
    if (node.nodeType === Node.TEXT_NODE) {
      const value = node.nodeValue;
      if (value) {
        textParts.push(value);
        textChars += value.length;
        if (textChars >= maxTextChars) {
          textDomTruncated = true;
        }
      }
      return;
    }
    if (node.nodeType !== Node.ELEMENT_NODE) {
      return;
    }
    const tag = node.tagName.toLowerCase();
    if (SKIP_TAGS.has(tag)) {
      return;
    }
    if (isHidden(node)) {
      hiddenElementCount += 1;
      return;
    }
    const block = BLOCK_TAGS.has(tag);
    if (block) {
      textParts.push("\n");
    }
    for (const child of node.childNodes) {
      collectText(child);
      if (textDomTruncated) {
        break;
      }
    }
    if (block) {
      textParts.push("\n");
    }
  }

  if (root) {
    collectText(root);
  }

  let rawText = normalizeText(textParts.join(""));
  if (textDomTruncated) {
    rawText = rawText.slice(0, maxTextChars);
  }

  const links = [];
  let linksTotal = 0;
  for (const anchor of document.querySelectorAll("a[href]")) {
    if (isHidden(anchor)) {
      continue;
    }
    const url = httpUrl(anchor.href);
    if (!url) {
      continue;
    }
    linksTotal += 1;
    if (links.length < maxLinks) {
      links.push({
        text: visibleText(anchor, 1000),
        url,
        rel: clampString(anchor.getAttribute("rel"), 255) || null,
      });
    }
  }

  const lists = [];
  let listsTotal = 0;
  let listItemsTruncated = false;
  for (const list of document.querySelectorAll("ul, ol")) {
    if (isHidden(list)) {
      continue;
    }
    listsTotal += 1;
    if (lists.length >= maxLists) {
      continue;
    }
    const items = [];
    for (const child of list.children) {
      if (child.tagName.toLowerCase() !== "li" || isHidden(child)) {
        continue;
      }
      if (items.length >= 50) {
        listItemsTruncated = true;
        break;
      }
      items.push(visibleText(child, 2000));
    }
    if (items.length > 0) {
      lists.push({ ordered: list.tagName.toLowerCase() === "ol", items });
    }
  }

  const tables = [];
  let tablesTotal = 0;
  let tableRowsTruncated = false;
  for (const table of document.querySelectorAll("table")) {
    if (isHidden(table)) {
      continue;
    }
    tablesTotal += 1;
    if (tables.length >= maxTables) {
      continue;
    }
    const caption = table.querySelector("caption");
    const headers = [];
    let headerCells = table.querySelectorAll("thead th");
    if (headerCells.length === 0) {
      headerCells = table.querySelectorAll("tr:first-child th");
    }
    for (const cell of headerCells) {
      if (headers.length >= 20) {
        break;
      }
      headers.push(visibleText(cell, 500));
    }
    const rows = [];
    let rowNodes = table.querySelectorAll("tbody tr");
    if (rowNodes.length === 0) {
      rowNodes = table.querySelectorAll("tr");
    }
    for (const row of rowNodes) {
      if (isHidden(row)) {
        continue;
      }
      if (row.querySelector("th") && !row.querySelector("td")) {
        continue;
      }
      if (rows.length >= 100) {
        tableRowsTruncated = true;
        break;
      }
      const cells = [];
      for (const cell of row.querySelectorAll("th, td")) {
        if (cells.length >= 20) {
          break;
        }
        cells.push(visibleText(cell, 1000));
      }
      if (cells.length > 0) {
        rows.push(cells);
      }
    }
    tables.push({
      caption: caption ? visibleText(caption, 500) || null : null,
      headers,
      rows,
    });
  }

  const description = document.querySelector('meta[name="description"]');
  const siteName = document.querySelector('meta[property="og:site_name"]');
  const canonical = document.querySelector('link[rel="canonical"]');

  return {
    metadata: {
      title: clampString(document.title, 1000),
      url: location.href,
      description: description
        ? clampString(description.getAttribute("content"), 2000) || null
        : null,
      canonical_url: canonical ? httpUrl(canonical.href) : null,
      site_name: siteName
        ? clampString(siteName.getAttribute("content"), 500) || null
        : null,
      language: clampString(document.documentElement.lang, 64) || null,
    },
    text: rawText,
    textDomTruncated,
    links,
    linksTotal,
    lists,
    listsTotal,
    listItemsTruncated,
    tables,
    tablesTotal,
    tableRowsTruncated,
    hiddenContentExcluded: hiddenElementCount > 0,
    hiddenElementCount,
  };
}

export async function extractPage(page) {
  const startedAt = Date.now();
  const maxLinks = config.maxExtractionLinks;
  const maxLists = 100;
  const maxTables = 50;

  const raw = await page.evaluate(collectPageData, {
    maxLinks: maxLinks + 1,
    maxLists: maxLists + 1,
    maxTables: maxTables + 1,
    maxTextChars: Math.max(config.maxExtractionTextBytes * 2, 4096),
  });

  const { content: text, truncated: textTruncated } = truncateUtf8(
    raw.text,
    config.maxExtractionTextBytes,
  );

  return {
    metadata: raw.metadata,
    text,
    text_truncated: textTruncated || raw.textDomTruncated,
    links: raw.links.slice(0, maxLinks),
    links_truncated: raw.linksTotal > maxLinks,
    lists: raw.lists.slice(0, maxLists),
    lists_truncated: raw.listsTotal > maxLists || raw.listItemsTruncated,
    tables: raw.tables.slice(0, maxTables),
    tables_truncated: raw.tablesTotal > maxTables || raw.tableRowsTruncated,
    hidden_content_excluded: raw.hiddenContentExcluded,
    hidden_element_count: raw.hiddenElementCount,
    elapsed_ms: Date.now() - startedAt,
  };
}
