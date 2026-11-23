/**
 * Sync frontend static files to public directory for Vercel deployment.
 * Supports `--check` mode (exits with code 1 if any file differs or is missing).
 * Cross-platform (Windows, macOS, Linux).
 */
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const srcDir = path.resolve(__dirname, '..', 'frontend');
const destDir = path.resolve(__dirname, '..', 'public');
const isCheckMode = process.argv.includes('--check');

const filesToCopy = [
  'index.html',
  'styles.css',
  'app.js',
  'ui-components.js',
  'graph-renderer.js',
];

function sha256File(filePath) {
  const buf = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(buf).digest('hex');
}

if (isCheckMode) {
  let mismatches = 0;
  for (const file of filesToCopy) {
    const srcPath = path.join(srcDir, file);
    const destPath = path.join(destDir, file);
    if (!fs.existsSync(srcPath)) {
      console.error(`[sync-public --check] MISSING source: ${srcPath}`);
      mismatches += 1;
      continue;
    }
    if (!fs.existsSync(destPath)) {
      console.error(`[sync-public --check] MISSING public target: ${destPath}`);
      mismatches += 1;
      continue;
    }
    const srcHash = sha256File(srcPath);
    const destHash = sha256File(destPath);
    if (srcHash !== destHash) {
      console.error(`[sync-public --check] OUT OF SYNC: frontend/${file} != public/${file}`);
      mismatches += 1;
    }
  }
  if (mismatches > 0) {
    console.error(`[sync-public --check] Failed: ${mismatches} file(s) out of sync. Run "npm run build".`);
    process.exit(1);
  }
  console.log('[sync-public --check] OK: All frontend/ and public/ assets match byte-for-byte.');
  process.exit(0);
}

if (!fs.existsSync(destDir)) {
  fs.mkdirSync(destDir, { recursive: true });
}

for (const file of filesToCopy) {
  const srcPath = path.join(srcDir, file);
  const destPath = path.join(destDir, file);
  if (fs.existsSync(srcPath)) {
    fs.copyFileSync(srcPath, destPath);
    console.log(`[sync-public] Copied: ${file} -> public/${file}`);
  } else {
    console.warn(`[sync-public] Warning: ${srcPath} does not exist.`);
  }
}

console.log('[sync-public] Static files synced successfully for Vercel.');
