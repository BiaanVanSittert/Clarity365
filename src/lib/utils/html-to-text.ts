// Converts the simple HTML Microsoft Graph returns in secureScoreControlProfile's
// remediation/remediationImpact fields (confirmed live: <p>, <ol>/<li>, <em>, <strong>,
// <a>, <br>) into readable plain text. JSX text interpolation never renders markup -
// it escapes it - so without this, a control's remediation steps show up as literal
// "<ol> <li>..." on screen. Deliberately not dangerouslySetInnerHTML: plain text is
// simpler and sidesteps needing a sanitizer for content this app doesn't author.
export function htmlToPlainText(html: string | undefined | null): string {
  if (!html) return "";
  return html
    .replace(/<li[^>]*>/gi, "\n• ")
    .replace(/<\/(p|div|ol|ul)>/gi, "\n")
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<[^>]+>/g, "")
    .replace(/&nbsp;/gi, " ")
    .replace(/&ldquo;|&rdquo;/gi, '"')
    .replace(/&lsquo;|&rsquo;|&#39;/gi, "'")
    .replace(/&mdash;/gi, "—")
    .replace(/&ndash;/gi, "–")
    .replace(/&quot;/gi, '"')
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
    .join("\n");
}
