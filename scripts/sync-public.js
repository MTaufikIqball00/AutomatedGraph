/**
 * Sync frontend static files to public directory for Vercel deployment.
 * Cross-platform (Windows, macOS, Linux).
 */
const fs = require('fs');
const path = require('path');

const srcDir = path.resolve(__dirname, '..', 'frontend');
const destDir = path.resolve(__dirname, '..', 'public');

if (!fs.existsSync(destDir)) {
  fs.mkdirSync(destDir, { recursive: true });
}

const filesToCopy = [
  'index.html',
  'styles.css',
  'app.js',
  'ui-components.js',
  'graph-renderer.js'
];

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
