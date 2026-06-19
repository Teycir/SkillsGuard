#!/usr/bin/env node
import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const SKILL_DIRS = [
  'fabricio-skills/skills',
  'vercel-skills/skills',
  'blastum-skills',
  'tech-leads-skills/skills',
  'hoodini-skills/skills'
];

const results = {
  total: 0,
  scanned: 0,
  clean: 0,
  findings: 0,
  errors: 0,
  byCategory: {},
  topPatterns: {}
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
      `npx tsx "${cliPath}" scan "${skillPath}" --json`,
      { encoding: 'utf8', stdio: 'pipe', cwd: path.join(__dirname, '../..') }
    );
    return JSON.parse(result);
  } catch (err) {
    return null;
  }
}

console.log('🔍 Scanning real-world skills...\n');

const skills = findSkills();
results.total = skills.length;
console.log(`Found ${skills.length} skills\n`);

skills.forEach((skillPath, idx) => {
  const name = path.basename(path.dirname(skillPath));
  process.stdout.write(`[${idx + 1}/${skills.length}] ${name}... `);
  
  const scan = scanSkill(skillPath);
  
  if (!scan) {
    results.errors++;
    console.log('ERROR');
    return;
  }
  
  results.scanned++;
  
  if (scan.findings.length === 0) {
    results.clean++;
    console.log('✓ clean');
    return;
  }
  
  results.findings++;
  console.log(`⚠ ${scan.findings.length} findings`);
  
  scan.findings.forEach(f => {
    results.byCategory[f.category] = (results.byCategory[f.category] || 0) + 1;
    results.topPatterns[f.pattern] = (results.topPatterns[f.pattern] || 0) + 1;
  });
});

console.log('\n' + '='.repeat(60));
console.log('📊 RESULTS\n');
console.log(`Total skills:      ${results.total}`);
console.log(`Scanned:           ${results.scanned}`);
console.log(`Clean:             ${results.clean} (${((results.clean/results.scanned)*100).toFixed(1)}%)`);
console.log(`With findings:     ${results.findings} (${((results.findings/results.scanned)*100).toFixed(1)}%)`);
console.log(`Errors:            ${results.errors}`);

console.log('\n📦 By Category:');
Object.entries(results.byCategory)
  .sort((a, b) => b[1] - a[1])
  .forEach(([cat, count]) => {
    console.log(`  ${cat.padEnd(20)} ${count}`);
  });

console.log('\n🔥 Top Patterns:');
Object.entries(results.topPatterns)
  .sort((a, b) => b[1] - a[1])
  .slice(0, 10)
  .forEach(([pat, count]) => {
    console.log(`  ${pat.padEnd(40)} ${count}`);
  });

const outPath = path.join(__dirname, 'test-results.json');
fs.writeFileSync(outPath, JSON.stringify(results, null, 2));
console.log(`\n✓ Results saved to ${outPath}`);
