/**
 * Capitalizes the first letter of each sentence.
 *
 * @param text - The input text to process.
 * @returns The text with capitalized sentences.
 */
export function capitalizeSentences(text: string): string {
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

/**
 * Normalizes multiple spaces to a single space.
 *
 * @param text - The input text to process.
 * @returns The text with normalized spacing.
 */
export function fixSpacing(text: string): string {
  return text.replace(/\s+/g, " ").trim();
}

/**
 * Ensures the text ends with proper punctuation.
 *
 * @param text - The input text to process.
 * @returns The text ending with punctuation.
 */
export function applyPunctuation(text: string): string {
  let result = text;
  if (!result.endsWith(".") && !result.endsWith("!") && !result.endsWith("?")) {
    result += ".";
  }
  return result;
}

/**
 * Applies all text formatting rules.
 *
 * @param text - The input text to format.
 * @returns The formatted text.
 */
export function formatText(text: string): string {
  let result = fixSpacing(text);
  result = capitalizeSentences(result);
  result = applyPunctuation(result);
  return result;
}
