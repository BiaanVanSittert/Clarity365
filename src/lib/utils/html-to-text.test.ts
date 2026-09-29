import { describe, it, expect } from "vitest";
import { htmlToPlainText } from "./html-to-text";

describe("htmlToPlainText", () => {
  it("converts a numbered <ol><li> list into readable bullet lines", () => {
    const html = "<ol> <li>Step one.</li> <li>Step two.</li> </ol>";
    expect(htmlToPlainText(html)).toBe("• Step one.\n• Step two.");
  });

  it("strips inline formatting tags while keeping their text", () => {
    const html = "Set <em>Users can request admin consent</em> to <strong>Yes</strong>.";
    expect(htmlToPlainText(html)).toBe("Set Users can request admin consent to Yes.");
  });

  it("decodes common HTML entities", () => {
    expect(htmlToPlainText("Fish &amp; chips &quot;done&quot;")).toBe('Fish & chips "done"');
  });

  it("decodes smart quotes and dashes, confirmed live in a real control's remediation text", () => {
    expect(htmlToPlainText("set the status to &ldquo;Resolved through alternate mitigation&rdquo;.")).toBe(
      'set the status to "Resolved through alternate mitigation".'
    );
    expect(htmlToPlainText("It&rsquo;s done &mdash; verified.")).toBe("It's done — verified.");
  });

  it("returns an empty string for missing input", () => {
    expect(htmlToPlainText(undefined)).toBe("");
    expect(htmlToPlainText(null)).toBe("");
    expect(htmlToPlainText("")).toBe("");
  });

  it("handles plain text with no markup unchanged", () => {
    expect(htmlToPlainText("None.")).toBe("None.");
  });
});
