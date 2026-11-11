/**
 * Cross-platform build script for Automated GraphRAG.
 * Compiles Tailwind CSS if tailwindcss/npx is available,
 * otherwise falls back gracefully to existing pre-compiled styles.css.
 * Then synchronizes static files to public/ for Vercel edge deployment.
 */
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const srcDir = path.resolve(__dirname, '..', 'frontend');
const destDir = path.resolve(__dirname, '..', 'public');
const inputCss = path.join(srcDir, 'input.css');
const outputCss = path.join(srcDir, 'styles.css');

console.log('[build] Starting Automated GraphRAG build process...');

// Step 1: Try compiling Tailwind CSS if input.css exists
if (fs.existsSync(inputCss)) {
  let compiled = false;

  try {
    console.log('[build] Attempting to compile Tailwind CSS with npx...');
    execSync(`npx tailwindcss -i "${inputCss}" -o "${outputCss}" --minify`, {
      stdio: 'inherit',
    });
    console.log('[build] Tailwind CSS compiled successfully via npx.');
    compiled = true;
  } catch (err) {
    console.warn('[build] Note: npx tailwindcss not available or exited with error.');
  }

  if (!compiled) {
    if (fs.existsSync(outputCss) && fs.statSync(outputCss).size > 0) {
      console.log('[build] Using pre-compiled production styles.css from repository.');
    } else {
      console.warn('[build] Warning: styles.css not found, creating minimal fallback.');
      fs.writeFileSync(outputCss, '/* Fallback styles */');
    }
  }
}

// Step 2: Sync static assets to public/
console.log('[build] Syncing assets to public/ directory for Vercel...');
if (!fs.existsSync(destDir)) {
  fs.mkdirSync(destDir, { recursive: true });
}

const filesToCopy = [
  'index.html',
  'styles.css',
  'app.js',
  'ui-components.js',
  'graph-renderer.js',
];

for (const file of filesToCopy) {
  const srcPath = path.join(srcDir, file);
  const destPath = path.join(destDir, file);
  if (fs.existsSync(srcPath)) {
    fs.copyFileSync(srcPath, destPath);
    console.log(`[build] Copied: ${file} -> public/${file}`);
  } else {
    console.warn(`[build] Warning: ${srcPath} does not exist.`);
  }
}

console.log('[build] Build completed successfully.');
