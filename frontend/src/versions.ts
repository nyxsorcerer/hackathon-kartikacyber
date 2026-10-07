/** Saved analyses carry either version strings or structured version evidence. */
export function versionLabels(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.map((item: unknown) => {
    if (typeof item === "string") return item;
    if (typeof item !== "object" || item === null) return "Unknown";
    const fields: Record<string, unknown> = Object.fromEntries(
      Object.entries(item),
    );
    const range = fields.range || fields.version_constraint || fields.version;
    return typeof range === "string"
      ? `${typeof fields.product === "string" ? `${fields.product} ` : ""}${range}`
      : JSON.stringify(item);
  });
}
