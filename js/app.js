// ── Tab switching ──
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById('panel-' + tab.dataset.tab).classList.add('active');
  });
});

// ── Utility ──
function setStatus(id, msg, type = '') {
  const el = document.getElementById(id);
  el.textContent = msg;
  el.className = 'status-bar ' + type;
}

function copyText(text, btnId) {
  navigator.clipboard.writeText(text).then(() => {
    const btn = document.getElementById(btnId);
    const orig = btn.textContent;
    btn.textContent = 'copied!';
    setTimeout(() => { btn.textContent = orig; }, 1500);
  });
}

function downloadFile(content, filename) {
  const blob = new Blob([content], { type: 'text/plain' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function setupDrop(dropId, inputId, handler) {
  const zone  = document.getElementById(dropId);
  const input = document.getElementById(inputId);

  zone.addEventListener('dragover', e => { e.preventDefault(); zone.classList.add('drag-over'); });
  zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));
  zone.addEventListener('drop', e => {
    e.preventDefault();
    zone.classList.remove('drag-over');
    const file = e.dataTransfer.files[0];
    if (file) handler(file);
  });
  zone.addEventListener('click', (e) => {
    if (e.target.classList.contains('file-label')) return;
    input.click();
  });
  input.addEventListener('change', () => {
    if (input.files[0]) handler(input.files[0]);
  });
}

// ── SYMBOL EXTRACTOR ──
let lastSymbols = [];

setupDrop('drop-symbol', 'input-symbol', async (file) => {
  setStatus('status-symbol', `reading ${file.name}...`, 'info');
  try {
    const buf = await file.arrayBuffer();
    let elfBuf = buf;

    if (file.name.endsWith('.apk')) {
      setStatus('status-symbol', 'extracting libil2cpp.so from APK...', 'info');
      elfBuf = await extractSoFromApk(buf);
    }

    const parser  = new ELFParser(elfBuf);
    const symbols = parser.parse();
    lastSymbols   = symbols;

    renderSymbols();
    setStatus('status-symbol', `parsed ${symbols.length} symbols from ${file.name}`, 'ok');
  } catch (e) {
    setStatus('status-symbol', 'error: ' + e.message, 'error');
    console.error(e);
  }
});

function renderSymbols() {
  const filterIl2cpp = document.getElementById('sym-filter-il2cpp').checked;
  const showAddr     = document.getElementById('sym-show-addr').checked;
  const text         = formatSymbols(lastSymbols, filterIl2cpp, showAddr);
  const lines        = text.split('\n').filter(Boolean);

  document.getElementById('output-symbol').value = text;
  document.getElementById('sym-count').textContent = `${lines.length} symbols`;
  document.getElementById('output-symbol-wrap').classList.remove('hidden');
}

document.getElementById('sym-filter-il2cpp').addEventListener('change', () => { if (lastSymbols.length) renderSymbols(); });
document.getElementById('sym-show-addr').addEventListener('change',     () => { if (lastSymbols.length) renderSymbols(); });

document.getElementById('btn-copy-symbol').addEventListener('click', () => {
  copyText(document.getElementById('output-symbol').value, 'btn-copy-symbol');
});
document.getElementById('btn-dl-symbol').addEventListener('click', () => {
  downloadFile(document.getElementById('output-symbol').value, 'symbols.txt');
});

// ── METADATA DUMPER ──
let lastTypes = [];

setupDrop('drop-metadata', 'input-metadata', async (file) => {
  setStatus('status-metadata', `reading ${file.name}...`, 'info');
  try {
    const buf = await file.arrayBuffer();
    const { types, version } = await parseMetadata(buf, file.name);
    lastTypes = types;

    renderMetadata();
    setStatus('status-metadata', `il2cpp v${version} — ${types.length} type definitions`, 'ok');
  } catch (e) {
    setStatus('status-metadata', 'error: ' + e.message, 'error');
    console.error(e);
  }
});

function renderMetadata() {
  const format = document.getElementById('meta-format').value;
  let text = '';

  if (format === 'frida') text = generateFridaScript(lastTypes);
  else if (format === 'bnm') text = generateBnm(lastTypes);
  else                       text = generateDumpCs(lastTypes);

  const ext = format === 'frida' ? 'js' : format === 'bnm' ? 'hpp' : 'cs';
  document.getElementById('output-metadata').value = text;
  document.getElementById('meta-count').textContent = `${lastTypes.length} types`;
  document.getElementById('output-metadata-wrap').classList.remove('hidden');
  document.getElementById('btn-dl-meta').dataset.ext = ext;
}

document.getElementById('meta-format').addEventListener('change', () => { if (lastTypes.length) renderMetadata(); });

document.getElementById('btn-copy-meta').addEventListener('click', () => {
  copyText(document.getElementById('output-metadata').value, 'btn-copy-meta');
});
document.getElementById('btn-dl-meta').addEventListener('click', () => {
  const ext = document.getElementById('btn-dl-meta').dataset.ext || 'txt';
  const names = { js: 'frida_script.js', hpp: 'bnm_offsets.hpp', cs: 'dump.cs', txt: 'dump.txt' };
  downloadFile(document.getElementById('output-metadata').value, names[ext]);
});

// ── FRIDA BRIDGE EXTRACTOR ──
// Loads the real frida-il2cpp-bridge.js and prepends a config block

async function loadBridgeSource() {
  const res = await fetch('assets/frida-il2cpp-bridge.js');
  if (!res.ok) throw new Error('Could not load bridge source');
  return await res.text();
}

setupDrop('drop-frida', 'input-frida', async (file) => {
  setStatus('status-frida', `reading ${file.name}...`, 'info');
  try {
    const buf        = await file.arrayBuffer();
    const bridgeSrc  = await loadBridgeSource();
    let configBlock  = '';
    let count        = 0;

    if (file.name.endsWith('.json')) {
      const text    = new TextDecoder().decode(buf);
      const map     = JSON.parse(text);
      const entries = Array.isArray(map)
        ? map
        : Object.entries(map).map(([k, v]) => ({ name: k, offset: v }));

      count = entries.length;
      configBlock = buildConfigBlockFromEntries(entries, file.name);

    } else if (file.name.endsWith('.so')) {
      const parser  = new ELFParser(buf);
      const symbols = parser.parse();
      count         = symbols.length;
      configBlock   = buildConfigBlockFromSymbols(symbols, file.name);

    } else {
      throw new Error('Unsupported file type. Use symbolmap.json or libil2cpp.so');
    }

    // Config block MUST come after bridge source — Il2Cpp doesn't exist before that
    const output = bridgeSrc + '\n\n' + configBlock;

    document.getElementById('output-frida').value = output;
    document.getElementById('frida-count').textContent = `${count} symbols — ${(output.length / 1024).toFixed(1)} KB`;
    document.getElementById('output-frida-wrap').classList.remove('hidden');
    setStatus('status-frida', `bridge configured from ${file.name}`, 'ok');
  } catch (e) {
    setStatus('status-frida', 'error: ' + e.message, 'error');
    console.error(e);
  }
});

function buildConfigBlockFromEntries(entries, filename) {
  const lines = [
    '// ─────────────────────────────────────────────────────────',
    '// configured by Killa\'s Toolkit',
    `// source: ${filename} — ${entries.length} symbols`,
    '// usage:  frida -U -f <package> -l frida-il2cpp-bridge.js --no-pause',
    '// ─────────────────────────────────────────────────────────',
    '',
    '// Il2Cpp is now defined — safe to configure',
    'Il2Cpp.$config.moduleName = "libil2cpp.so";',
    '// Il2Cpp.$config.unityVersion = "2022.3.5f1"; // uncomment and set if auto-detect fails',
    '',
    '// Extracted symbol map:',
    'var symbolMap = {',
  ];

  for (const e of entries) {
    const name   = e.name || e.methodName || e.symbol || '';
    const offset = e.offset || e.rva || e.address || 0;
    if (!name) continue;
    const hexOff = typeof offset === 'number' ? `0x${offset.toString(16).padStart(8,'0')}` : String(offset);
    lines.push(`  "${name}": ptr(Module.getBaseAddress("libil2cpp.so")).add(${hexOff}),`);
  }

  lines.push('};', '');
  lines.push('Il2Cpp.perform(() => {');
  lines.push('  console.log("[*] il2cpp loaded — version: " + Il2Cpp.unityVersion);');
  lines.push('  console.log("[*] " + Object.keys(symbolMap).length + " symbols mapped");');
  lines.push('');
  lines.push('  // Hook example — replace with your target method name:');
  lines.push('  // var target = symbolMap["YourMethodName"];');
  lines.push('  // if (target) {');
  lines.push('  //   Interceptor.attach(target, {');
  lines.push('  //     onEnter(args) { console.log("[+] hooked!"); }');
  lines.push('  //   });');
  lines.push('  // }');
  lines.push('});');

  return lines.join('\n');
}

function buildConfigBlockFromSymbols(symbols, filename) {
  const il2cppExports = symbols.filter(s =>
    s.name.startsWith('il2cpp_') || s.name.startsWith('Il2Cpp')
  );

  const lines = [
    '// ─────────────────────────────────────────────────────────',
    '// configured by Killa\'s Toolkit',
    `// source: ${filename}`,
    `// il2cpp exports: ${il2cppExports.length} / ${symbols.length} total`,
    '// usage:  frida -U -f <package> -l frida-il2cpp-bridge.js --no-pause',
    '// ─────────────────────────────────────────────────────────',
    '',
    '// Il2Cpp is now defined — safe to configure',
    'Il2Cpp.$config.moduleName = "libil2cpp.so";',
    '// Il2Cpp.$config.unityVersion = "2022.3.5f1"; // uncomment and set if auto-detect fails',
    '',
  ];

  // Wire known il2cpp exports into $config.exports
  if (il2cppExports.length > 0) {
    lines.push('Il2Cpp.$config.exports = {');
    for (const s of il2cppExports) {
      const hex  = `0x${s.addr.toString(16).padStart(8, '0')}`;
      const safe = s.name.replace(/^il2cpp_/, '').replace(/[^a-zA-Z0-9_]/g, '_');
      lines.push(`  ${safe}: () => ptr("${hex}"), // ${s.name}`);
    }
    lines.push('};', '');
  }

  lines.push('Il2Cpp.perform(() => {');
  lines.push('  console.log("[*] il2cpp loaded — version: " + Il2Cpp.unityVersion);');
  lines.push('  console.log("[*] module base: " + Il2Cpp.module.base);');
  lines.push('');
  lines.push('  // Example — hook il2cpp_runtime_invoke to trace all managed calls:');
  lines.push('  // Il2Cpp.trace(Il2Cpp.domain.assemblies[0].image);');
  lines.push('});');

  return lines.join('\n');
}

document.getElementById('btn-copy-frida').addEventListener('click', () => {
  copyText(document.getElementById('output-frida').value, 'btn-copy-frida');
});
document.getElementById('btn-dl-frida').addEventListener('click', () => {
  downloadFile(document.getElementById('output-frida').value, 'frida-il2cpp-bridge.js');
});

// ── JS OBFUSCATOR ──
document.getElementById('btn-obfuscate').addEventListener('click', () => {
  const code = document.getElementById('js-input').value.trim();
  if (!code) {
    setStatus('status-obf', 'paste some javascript first', 'error');
    return;
  }
  try {
    const result = obfuscateJS(code);
    document.getElementById('output-obf').value = result;
    document.getElementById('output-obf-wrap').classList.remove('hidden');
    setStatus('status-obf', `obfuscated — ${result.length} bytes`, 'ok');
  } catch (e) {
    setStatus('status-obf', 'error: ' + e.message, 'error');
  }
});

document.getElementById('btn-copy-obf').addEventListener('click', () => {
  copyText(document.getElementById('output-obf').value, 'btn-copy-obf');
});
document.getElementById('btn-dl-obf').addEventListener('click', () => {
  downloadFile(document.getElementById('output-obf').value, 'obfuscated.js');
});
