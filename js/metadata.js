// Il2Cpp global-metadata.dat parser
// Supports versions 24–29

const IL2CPP_MAGIC = 0xFAB11BAF;

class MetadataParser {
  constructor(buffer) {
    this.buf  = buffer;
    this.view = new DataView(buffer);
  }

  u8(o)  { return this.view.getUint8(o); }
  i32(o) { return this.view.getInt32(o, true); }
  u32(o) { return this.view.getUint32(o, true); }
  u16(o) { return this.view.getUint16(o, true); }

  str(offset) {
    if (offset < 0 || offset >= this.buf.byteLength) return '';
    let s = '', i = offset;
    while (i < this.buf.byteLength) {
      const c = this.view.getUint8(i++);
      if (c === 0) break;
      s += String.fromCharCode(c);
    }
    return s;
  }

  validate() {
    const sanity = this.u32(0);
    if (sanity !== IL2CPP_MAGIC) throw new Error(`Bad magic: 0x${sanity.toString(16)} (expected 0xFAB11BAF)`);
    return this.i32(4); // version
  }

  parseHeader(version) {
    // Header layout for versions 24-29
    // Each field is offset (int32) + count (int32) = 8 bytes per section
    const h = {};
    let o = 8;

    const rd = (name) => {
      h[name + 'Offset'] = this.i32(o);
      h[name + 'Count']  = this.i32(o + 4);
      o += 8;
    };

    rd('stringLiteral');
    rd('stringLiteralData');
    rd('string');
    rd('events');
    rd('properties');
    rd('methods');
    rd('parameterDefaultValues');
    rd('fieldDefaultValues');
    rd('fieldAndParameterDefaultValueData');
    rd('fieldMarshaledSizes');
    rd('parameters');
    rd('fields');
    rd('genericParameters');
    rd('genericParameterConstraints');
    rd('genericContainers');
    rd('nestedTypes');
    rd('interfaces');
    rd('vtableMethods');
    rd('interfaceOffsets');
    rd('typeDefinitions');

    if (version >= 27) {
      rd('rgctxEntries');
      rd('images');
      rd('assemblies');
      rd('metadataUsageLists');
      rd('metadataUsagePairs');
      rd('fieldRefs');
      rd('referencedAssemblies');
      rd('attributeDataRange');
      rd('attributeData');
    } else {
      rd('rgctxEntries');
      rd('images');
      rd('assemblies');
      rd('metadataUsageLists');
      rd('metadataUsagePairs');
      rd('fieldRefs');
      rd('referencedAssemblies');
    }

    return h;
  }

  getStringAt(stringOffset, index) {
    return this.str(stringOffset + index);
  }

  parseTypeDefinitions(h, version) {
    const strOff  = h.stringOffset;
    const tdOff   = h.typeDefinitionsOffset;
    const tdCount = h.typeDefinitionsCount;
    const mOff    = h.methodsOffset;
    const fOff    = h.fieldsOffset;
    const pOff    = h.parametersOffset;

    // TypeDefinition struct size varies by version
    // v24-v26: ~96 bytes; v27+: ~104 bytes
    const TD_SIZE = version >= 27 ? 104 : 96;
    const M_SIZE  = version >= 27 ? 44 : 40;
    const F_SIZE  = 16;
    const P_SIZE  = 12;

    const typeCount = Math.floor(tdCount / TD_SIZE);
    const types = [];

    for (let i = 0; i < typeCount; i++) {
      const o = tdOff + i * TD_SIZE;
      if (o + TD_SIZE > this.buf.byteLength) break;

      const nameIdx   = this.i32(o);
      const nsIdx     = this.i32(o + 4);
      const methodStart = this.i32(o + (version >= 27 ? 56 : 52));
      const methodCount = this.u16(o + (version >= 27 ? 80 : 76));
      const fieldStart  = this.i32(o + (version >= 27 ? 52 : 48));
      const fieldCount  = this.u16(o + (version >= 27 ? 84 : 80));
      const flags       = this.u32(o + (version >= 27 ? 32 : 28));

      const name = this.getStringAt(strOff, nameIdx);
      const ns   = this.getStringAt(strOff, nsIdx);
      if (!name) continue;

      // Parse methods
      const methods = [];
      for (let m = 0; m < methodCount; m++) {
        const mo = mOff + (methodStart + m) * M_SIZE;
        if (mo + M_SIZE > this.buf.byteLength) break;
        const mNameIdx  = this.i32(mo);
        const mParamIdx = this.i32(mo + 8);
        const mParamCnt = this.u16(mo + (version >= 27 ? 32 : 28));
        const mFlags    = this.u16(mo + (version >= 27 ? 34 : 30));
        const mName     = this.getStringAt(strOff, mNameIdx);
        if (!mName) continue;

        const params = [];
        for (let p = 0; p < mParamCnt; p++) {
          const po = pOff + (mParamIdx + p) * P_SIZE;
          if (po + P_SIZE > this.buf.byteLength) break;
          const pNameIdx = this.i32(po);
          params.push(this.getStringAt(strOff, pNameIdx));
        }
        methods.push({ name: mName, params, flags: mFlags });
      }

      // Parse fields
      const fields = [];
      for (let f = 0; f < fieldCount; f++) {
        const fo = fOff + (fieldStart + f) * F_SIZE;
        if (fo + F_SIZE > this.buf.byteLength) break;
        const fNameIdx = this.i32(fo);
        const fName    = this.getStringAt(strOff, fNameIdx);
        if (fName) fields.push(fName);
      }

      types.push({ name, namespace: ns, methods, fields, flags });
    }

    return types;
  }
}

// ── Output formatters ──

function generateFridaScript(types) {
  const lines = [
    '// Generated by Killa\'s Toolkit',
    '// il2cpp Frida Script',
    '',
    'var il2cpp = Module.getBaseAddress("libil2cpp.so");',
    '',
    '// Helper',
    'function getRVA(offset) { return il2cpp.add(offset); }',
    '',
  ];

  for (const t of types) {
    const fullName = t.namespace ? `${t.namespace}.${t.name}` : t.name;
    lines.push(`// ── ${fullName} ──`);
    lines.push(`var klass_${sanitize(t.name)} = Il2Cpp.domain.assembly("Assembly-CSharp").image.class("${t.name}", "${t.namespace}");`);

    for (const m of t.methods) {
      const safeName = sanitize(m.name);
      lines.push(`var method_${sanitize(t.name)}_${safeName} = klass_${sanitize(t.name)}.method("${m.name}");`);
    }
    lines.push('');
  }

  lines.push('// Hook example:');
  lines.push('// method_MyClass_MyMethod.implementation = function(...args) {');
  lines.push('//   console.log("[*] Called MyClass.MyMethod");');
  lines.push('//   return this.method(...args);');
  lines.push('// };');

  return lines.join('\n');
}

function generateBnm(types) {
  const lines = [
    '// Generated by Killa\'s Toolkit',
    '// BNM Offsets',
    '#pragma once',
    '#include <BNM/UserSettings/GlobalSettings.hpp>',
    '',
  ];

  for (const t of types) {
    const fullName = t.namespace ? `${t.namespace}::${t.name}` : t.name;
    lines.push(`// ${fullName}`);
    for (const m of t.methods) {
      const params = m.params.join(', ');
      lines.push(`BNM::Method<void*> ${sanitize(t.name)}_${sanitize(m.name)}; // ${m.name}(${params})`);
    }
    lines.push('');
  }

  return lines.join('\n');
}

function generateDumpCs(types) {
  const lines = [
    '// Generated by Killa\'s Toolkit',
    '// il2cpp Dump.cs',
    '',
  ];

  for (const t of types) {
    const ns = t.namespace || 'Global';
    lines.push(`namespace ${ns} {`);

    const isEnum   = (t.flags & 0x20) !== 0;
    const isStruct = (t.flags & 0x18) === 0x18;
    const keyword  = isEnum ? 'enum' : isStruct ? 'struct' : 'class';

    lines.push(`  public ${keyword} ${t.name} {`);

    for (const f of t.fields) {
      lines.push(`    public object ${f}; // 0x?`);
    }
    if (t.fields.length > 0) lines.push('');

    for (const m of t.methods) {
      const visibility = (m.flags & 0x7) >= 6 ? 'public' : 'private';
      const isStatic   = (m.flags & 0x10) !== 0;
      const staticStr  = isStatic ? 'static ' : '';
      const params     = m.params.map((p, i) => `object param${i}`).join(', ');
      lines.push(`    ${visibility} ${staticStr}object ${m.name}(${params}) { } // RVA: 0x?`);
    }

    lines.push('  }');
    lines.push('}');
    lines.push('');
  }

  return lines.join('\n');
}

function sanitize(s) {
  return s.replace(/[^a-zA-Z0-9_]/g, '_').replace(/^(\d)/, '_$1');
}

// Parse .dat or pull from .apk then parse
async function parseMetadata(buffer, filename) {
  let dat = buffer;

  if (filename.endsWith('.apk')) {
    const zip     = await JSZip.loadAsync(buffer);
    const paths   = Object.keys(zip.files);
    const datPath = paths.find(p => p.endsWith('global-metadata.dat'));
    if (!datPath) throw new Error('global-metadata.dat not found inside APK');
    dat = await zip.files[datPath].async('arraybuffer');
  }

  const parser  = new MetadataParser(dat);
  const version = parser.validate();
  const header  = parser.parseHeader(version);
  const types   = parser.parseTypeDefinitions(header, version);

  return { types, version };
}
