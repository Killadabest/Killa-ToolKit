// ELF Parser — extracts exported symbols from libil2cpp.so
class ELFParser {
  constructor(buffer) {
    this.buf  = buffer;
    this.view = new DataView(buffer);
    this.le   = true;
    this.cls  = 0;
  }

  u8(o)  { return this.view.getUint8(o); }
  u16(o) { return this.view.getUint16(o, this.le); }
  u32(o) { return this.view.getUint32(o, this.le); }
  u64(o) {
    const lo = this.view.getUint32(o, this.le);
    const hi = this.view.getUint32(o + 4, this.le);
    return hi * 0x100000000 + lo;
  }

  str(offset) {
    let s = '', i = offset;
    while (i < this.buf.byteLength) {
      const c = this.view.getUint8(i++);
      if (c === 0) break;
      s += String.fromCharCode(c);
    }
    return s;
  }

  parse() {
    const magic = this.u32(0);
    if (magic !== 0x464C457F) throw new Error('Not a valid ELF binary');

    this.cls = this.u8(4);   // 1=32, 2=64
    this.le  = this.u8(5) === 1;

    return this.cls === 2 ? this._parse64() : this._parse32();
  }

  _parse64() {
    const shoff    = this.u64(40);
    const shentsize = this.u16(58);
    const shnum    = this.u16(60);
    const shstrndx = this.u16(62);

    const secs = [];
    for (let i = 0; i < shnum; i++) {
      const o = Number(shoff) + i * shentsize;
      secs.push({
        name_off:  this.u32(o),
        type:      this.u32(o + 4),
        addr:      this.u64(o + 16),
        offset:    Number(this.u64(o + 24)),
        size:      Number(this.u64(o + 32)),
        link:      this.u32(o + 40),
        entsize:   Number(this.u64(o + 56)),
      });
    }

    const shstrtab = secs[shstrndx];
    const secName  = (s) => this.str(shstrtab.offset + s.name_off);

    let dynsym = null, dynstr = null;
    for (const s of secs) {
      const n = secName(s);
      if (n === '.dynsym') dynsym = s;
      if (n === '.dynstr') dynstr = s;
    }
    if (!dynsym) { for (const s of secs) if (s.type === 11) { dynsym = s; break; } }
    if (dynsym && !dynstr) dynstr = secs[dynsym.link];
    if (!dynsym || !dynstr) throw new Error('No symbol table found in ELF');

    const symbols = [];
    const entSize = dynsym.entsize || 24;
    const count   = Math.floor(dynsym.size / entSize);

    for (let i = 1; i < count; i++) {
      const o    = dynsym.offset + i * entSize;
      const nameOff = this.u32(o);
      const info    = this.u8(o + 4);
      const shndx   = this.u16(o + 6);
      const addr    = this.u64(o + 8);
      const name    = this.str(dynstr.offset + nameOff);

      const bind = (info >> 4);  // 0=local,1=global,2=weak
      const type = (info & 0xf); // 0=notype,1=obj,2=func

      if (name && shndx !== 0 && (bind === 1 || bind === 2)) {
        symbols.push({ name, addr, bind, type });
      }
    }
    return symbols;
  }

  _parse32() {
    const shoff    = this.u32(32);
    const shentsize = this.u16(46);
    const shnum    = this.u16(48);
    const shstrndx = this.u16(50);

    const secs = [];
    for (let i = 0; i < shnum; i++) {
      const o = shoff + i * shentsize;
      secs.push({
        name_off: this.u32(o),
        type:     this.u32(o + 4),
        addr:     this.u32(o + 12),
        offset:   this.u32(o + 16),
        size:     this.u32(o + 20),
        link:     this.u32(o + 24),
        entsize:  this.u32(o + 36),
      });
    }

    const shstrtab = secs[shstrndx];
    const secName  = (s) => this.str(shstrtab.offset + s.name_off);

    let dynsym = null, dynstr = null;
    for (const s of secs) {
      const n = secName(s);
      if (n === '.dynsym') dynsym = s;
      if (n === '.dynstr') dynstr = s;
    }
    if (!dynsym) { for (const s of secs) if (s.type === 11) { dynsym = s; break; } }
    if (dynsym && !dynstr) dynstr = secs[dynsym.link];
    if (!dynsym || !dynstr) throw new Error('No symbol table found in ELF');

    const symbols = [];
    const entSize = dynsym.entsize || 16;
    const count   = Math.floor(dynsym.size / entSize);

    for (let i = 1; i < count; i++) {
      const o    = dynsym.offset + i * entSize;
      const nameOff = this.u32(o);
      const addr    = this.u32(o + 4);
      const info    = this.u8(o + 12);
      const shndx   = this.u16(o + 14);
      const name    = this.str(dynstr.offset + nameOff);

      const bind = (info >> 4);
      if (name && shndx !== 0 && (bind === 1 || bind === 2)) {
        symbols.push({ name, addr, bind, type: info & 0xf });
      }
    }
    return symbols;
  }
}

// Format symbols to text output
function formatSymbols(symbols, filterIl2cpp, showAddr) {
  let list = symbols;
  if (filterIl2cpp) {
    list = symbols.filter(s =>
      s.name.startsWith('Il2Cpp') ||
      s.name.startsWith('il2cpp') ||
      s.name.includes('_ZN') ||
      s.name.includes('Unity') ||
      s.name.includes('mono_')
    );
  }

  return list.map(s => {
    const addrStr = showAddr ? `0x${s.addr.toString(16).padStart(8,'0')}  ` : '';
    return `${addrStr}${s.name}`;
  }).join('\n');
}

// Extract .so from APK using JSZip
async function extractSoFromApk(buffer) {
  const zip    = await JSZip.loadAsync(buffer);
  const paths  = Object.keys(zip.files);
  const soPath = paths.find(p =>
    (p.includes('arm64-v8a') || p.includes('armeabi-v7a') || p.includes('x86')) &&
    p.endsWith('libil2cpp.so')
  ) || paths.find(p => p.endsWith('.so') && p.includes('il2cpp'));

  if (!soPath) throw new Error('libil2cpp.so not found inside APK');

  const soData = await zip.files[soPath].async('arraybuffer');
  return soData;
}
