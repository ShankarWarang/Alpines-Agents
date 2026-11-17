#!/usr/bin/env node
/**
 * Extract circom circuit signal names directly from wasm binary.
 * circom wasms embed signal names as length-prefixed UTF-8 in a custom "name" section.
 *
 * Usage:
 *   node scripts/inspect-circuit.mjs <path-to.wasm>
 */

import { readFileSync } from 'fs';

const wasmPath = process.argv[2];
if (!wasmPath) {
  console.error('Usage: node scripts/inspect-circuit.mjs <path-to.wasm>');
  process.exit(1);
}

const buf = readFileSync(wasmPath);
const bytes = new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);

// --- Parse WebAssembly binary format ---
// Magic: 00 61 73 6d | Version: 01 00 00 00
// Then sections: [id: u8][size: u32 leb128][payload...]
// Custom section id = 0, name section starts with "name\0..."
// circom stores signal names in a custom section called "signal_map" or directly
// as exported function names or in the data section.

function readLeb128(arr, offset) {
  let result = 0, shift = 0;
  while (true) {
    const byte = arr[offset++];
    result |= (byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) break;
    shift += 7;
  }
  return { value: result, offset };
}

function readString(arr, offset) {
  const len = arr[offset++];
  const str = Buffer.from(arr.buffer, arr.byteOffset + offset, len).toString('utf8');
  return { value: str, offset: offset + len };
}

// Find all UTF-8 strings in the binary that look like circom signal names
// Strategy: scan every byte offset for valid identifier strings
const text = buf.toString('binary');
const signalPattern = /\b([a-zA-Z_][a-zA-Z0-9_]{0,50})\b/g;
const allWords = new Set();
let m;
while ((m = signalPattern.exec(text)) !== null) allWords.add(m[1]);

// Also extract from wasm export/import name section specifically
// Wasm custom sections (id=0) often contain name info
const signals = new Set();
let pos = 8; // skip magic + version
while (pos < bytes.length - 4) {
  const sectionId = bytes[pos++];
  const sizeResult = readLeb128(bytes, pos);
  const sectionSize = sizeResult.value;
  pos = sizeResult.offset;
  const sectionEnd = pos + sectionSize;

  if (sectionId === 0 && sectionSize > 4) {
    // Custom section - read name
    try {
      const nameResult = readString(bytes, pos);
      const sectionName = nameResult.value;
      if (sectionName.includes('signal') || sectionName === 'name') {
        // Parse content as strings
        let p = nameResult.offset;
        while (p < sectionEnd - 1) {
          try {
            const sr = readString(bytes, p);
            if (/^[a-z_][a-z0-9_]{1,40}$/.test(sr.value)) signals.add(sr.value);
            p = sr.offset;
          } catch { p++; }
        }
      }
    } catch {}
  }

  if (sectionId === 7) {
    // Export section - contains exported function names (witness calc signals exported)
    try {
      const countResult = readLeb128(bytes, pos);
      let p = countResult.offset;
      for (let i = 0; i < countResult.value && p < sectionEnd; i++) {
        const nameResult = readString(bytes, p);
        p = nameResult.offset;
        // Skip type byte + index leb128
        p++; // type
        const idxResult = readLeb128(bytes, p);
        p = idxResult.offset;
        if (/^[a-z_][a-z0-9_]{1,40}$/.test(nameResult.value)) {
          signals.add(nameResult.value);
        }
      }
    } catch {}
  }

  pos = sectionEnd;
}

// Score all found words for likelihood of being circuit inputs
const exclude = new Set([
  'wasm','module','memory','table','export','import','function','global','local',
  'block','loop','call','return','drop','select','unreachable','type','param',
  'result','mut','end','else','then','data','elem','offset','align','name',
  'custom','section','env','init','alloc','free','malloc','copy','move',
  'store','load','fn','in','is','as','by','to','of','at','on','set','get',
  'add','sub','mul','div','mod','and','or','xor','not','eq','ne','lt','gt',
  'le','ge','shl','shr','out','log','exp','pow','abs','min','max','new',
  'del','run','use','let','var','const','this','self','null','true','false',
  'main','test','size','len','pos','ptr','idx','buf','str','num','val',
  'tmp','aux','ctx','err','ret','res','msg','key','tag','sig','ver','rev',
  'read','write','seek','open','close','flush','sync','lock','unlock',
  'hash','base','node','root','leaf','left','right','tree','list','map',
  'args','argv','argc','path','file','dir','log2','fr','fq','fr_add',
  'fr_mul','fr_sub','fr_neg','fr_inv','fr_copy','fr_zero','fr_one',
]);

const scoreWord = (w) => {
  if (exclude.has(w)) return -100;
  if (w.length < 2 || w.length > 40) return -100;
  let sc = 0;
  if (/^(action|turn|balance|my_|opponent|strategy|match|round|total|score|commit|nonce|policy|stake|amount|player|state|move|choice|decision|approve|gate|recipient|deadline|min_|max_|proof|public|input|signal|value|from|rule|hash|vk|key|index|count)/.test(w)) sc += 15;
  if (/_/.test(w)) sc += 5;
  if (w.length >= 4 && w.length <= 25) sc += 3;
  if (/^[a-z]/.test(w)) sc += 2;
  if (signals.has(w)) sc += 20; // found in wasm sections
  return sc;
};

const ranked = [...allWords]
  .map(w => ({ w, sc: scoreWord(w) }))
  .filter(x => x.sc > 5)
  .sort((a, b) => b.sc - a.sc)
  .slice(0, 50);

console.log('\n=== Circuit Signal Inspector ===');
console.log('File:', wasmPath);
console.log('Size:', (buf.length / 1024).toFixed(1), 'KB\n');

if (signals.size > 0) {
  console.log('Found in wasm sections (high confidence):');
  [...signals].forEach(s => console.log('  *', s));
  console.log('');
}

console.log('Top-ranked candidates from binary scan:');
ranked.forEach(({ w, sc }) => console.log(`  [${sc}] ${w}`));

console.log('\nNext: paste top candidates into test-proof.mjs and run again.');
