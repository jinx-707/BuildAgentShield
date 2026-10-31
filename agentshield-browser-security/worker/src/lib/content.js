export function truncateUtf8(value, maxBytes) {
  const buffer = Buffer.from(value, "utf8");
  if (buffer.length <= maxBytes) {
    return { content: value, truncated: false };
  }

  return {
    content: buffer.subarray(0, maxBytes).toString("utf8"),
    truncated: true,
  };
}
