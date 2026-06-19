#!/usr/bin/env node
import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const SKILL_DIRS = [
  'fabricio-skills',
  'vercel-skills',
  'blastum-skills',
  'tech-leads-skills',
  'hoodini-skills',
  'skills'
];

const stats = {
  total: 0,
  scanned: 0,
  clean: 0,
  findings: 0,
  errors: 0,
  byCategory: {},
  bySeverity: {},
  topPatterns: {},
  topFiles: [],
  avgRiskScore: 0,
  maxRiskScore: 0,
  skillDetails: []
};

function findSkills() {
  const skills = [];
  for (const dir of SKILL_DIRS) {
    const fullDir = path.join(__dirname, dir);
    if (!fs.existsSync(fullDir)) continue;
    const found = execSync(`find "${fullDir}" -name "SKILL.md" 2>/dev/null || true`)
      .toString()
      .split('\n')
      .filter(Boolean);
    skills.push(...found);
  }
  return skills;
}

function scanSkill(skillPath) {
  try {
    const cliPath = path.join(__dirname, '../../src/cli.ts');
    const result = execSync(
      `npx tsx "${cliPath}" "${skillPath}" --json --exit-zero`,
      { encoding: 'utf8', stdio: 'pipe', cwd: path.join(__dirname, '../..') }
    );
    return JSON.parse(result);
  } catch (err) {
    // Exit code 1 means findings, not error. Try parse output anyway.
    if (err.stdout) {
      try {
        return JSON.parse(err.stdout);
      } catch {}
    }
    return null;
  }
}

console.log('🔍 Comprehensive SkillsGuard Real-World Test Suite\n');
console.log('='.repeat(70));

const skills = findSkills();
stats.total = skills.length;
console.log(`\nFound ${skills.length} skills across ${SKILL_DIRS.length} sources\n`);

let totalRisk = 0;

skills.forEach((skillPath, idx) => {
  const relPath = path.relative(__dirname, skillPath);
  const name = path.basename(path.dirname(skillPath));
  process.stdout.write(`[${idx + 1}/${skills.length}] ${name.padEnd(35)} `);
  
  const scan = scanSkill(skillPath);
  
  if (!scan) {
    stats.errors++;
    console.log('❌ ERROR');
    return;
  }
  
  stats.scanned++;
  const riskScore = scan.riskScore?.score || 0;
  totalRisk += riskScore;
  
  if (riskScore > stats.maxRiskScore) {
    stats.maxRiskScore = riskScore;
  }
  
  if (scan.findings.length === 0) {
    stats.clean++;
    console.log('✅ clean');
    return;
  }
  
  stats.findings++;
  console.log(`⚠️  ${scan.findings.length} findings (risk: ${riskScore})`);
  
  // Track per-skill details
  stats.skillDetails.push({
    name,
    path: relPath,
    findings: scan.findings.length,
    riskScore,
    categories: [...new Set(scan.findings.map(f => f.category))],
    severities: [...new Set(scan.findings.map(f => f.severity))]
  });
  
  scan.findings.forEach(f => {
    stats.byCategory[f.category] = (stats.byCategory[f.category] || 0) + 1;
    stats.bySeverity[f.severity] = (stats.bySeverity[f.severity] || 0) + 1;
    stats.topPatterns[f.pattern] = (stats.topPatterns[f.pattern] || 0) + 1;
  });
});

stats.avgRiskScore = stats.scanned > 0 ? (totalRisk / stats.scanned).toFixed(2) : 0;

// Sort skills by findings count
stats.topFiles = stats.skillDetails
  .sort((a, b) => b.findings - a.findings)
  .slice(0, 10);

console.log('\n' + '='.repeat(70));
console.log('📊 TEST RESULTS\n');

console.log('Overview:');
console.log(`  Total skills:      ${stats.total}`);
console.log(`  Successfully scanned: ${stats.scanned}`);
console.log(`  Clean:             ${stats.clean} (${((stats.clean/stats.scanned)*100).toFixed(1)}%)`);
console.log(`  With findings:     ${stats.findings} (${((stats.findings/stats.scanned)*100).toFixed(1)}%)`);
console.log(`  Scan errors:       ${stats.errors}`);

console.log('\nRisk Metrics:');
console.log(`  Average risk score: ${stats.avgRiskScore}`);
console.log(`  Maximum risk score: ${stats.maxRiskScore}`);

console.log('\n📦 Findings by Category:');
Object.entries(stats.byCategory)
  .sort((a, b) => b[1] - a[1])
  .forEach(([cat, count]) => {
    const pct = ((count / stats.scanned) * 100).toFixed(1);
    console.log(`  ${cat.padEnd(30)} ${count.toString().padStart(4)} (${pct}%)`);
  });

console.log('\n⚠️  Findings by Severity:');
const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
severityOrder.forEach(sev => {
  const count = stats.bySeverity[sev] || 0;
  if (count > 0) {
    const pct = ((count / stats.scanned) * 100).toFixed(1);
    console.log(`  ${sev.padEnd(10)} ${count.toString().padStart(4)} (${pct}%)`);
  }
});

console.log('\n🔥 Top 10 Detection Patterns:');
Object.entries(stats.topPatterns)
  .sort((a, b) => b[1] - a[1])
  .slice(0, 10)
  .forEach(([pat, count], i) => {
    console.log(`  ${(i+1).toString().padStart(2)}. ${pat.padEnd(45)} ${count}`);
  });

console.log('\n🎯 Top 10 Skills with Most Findings:');
stats.topFiles.forEach((skill, i) => {
  console.log(`  ${(i+1).toString().padStart(2)}. ${skill.name.padEnd(35)} ${skill.findings} findings (risk: ${skill.riskScore})`);
  console.log(`      Categories: ${skill.categories.join(', ')}`);
});

// Analysis & Insights
console.log('\n💡 INSIGHTS & RECOMMENDATIONS\n');

const cleanRate = (stats.clean / stats.scanned) * 100;
if (cleanRate > 80) {
  console.log('✅ High quality: >80% of skills are clean');
} else if (cleanRate > 50) {
  console.log('⚠️  Moderate quality: 50-80% of skills are clean');
} else {
  console.log('🚨 Low quality: <50% of skills are clean - needs attention');
}

const topCategory = Object.entries(stats.byCategory).sort((a, b) => b[1] - a[1])[0];
if (topCategory) {
  console.log(`\n🔍 Most common issue: ${topCategory[0]} (${topCategory[1]} occurrences)`);
  console.log('   → Recommendation: Add detection rule improvements for this category');
}

const criticalCount = stats.bySeverity['CRITICAL'] || 0;
const highCount = stats.bySeverity['HIGH'] || 0;
if (criticalCount + highCount > 0) {
  console.log(`\n⚠️  High-severity findings: ${criticalCount} CRITICAL, ${highCount} HIGH`);
  console.log('   → Recommendation: Review high-severity rules for false positives');
}

if (stats.avgRiskScore > 30) {
  console.log(`\n📈 Average risk score is ${stats.avgRiskScore} (>30)`);
  console.log('   → Recommendation: Consider adjusting risk scoring weights');
}

console.log('\n' + '='.repeat(70));

const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
const outPath = path.join(__dirname, `test-results-${timestamp}.json`);
fs.writeFileSync(outPath, JSON.stringify(stats, null, 2));
console.log(`\n✅ Detailed results saved to ${path.basename(outPath)}`);
