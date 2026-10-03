# 🔪 Killa's il2cpp Toolkit
> built different. runs in your browser. touches your binaries.

---

## what is this

a fully client-side il2cpp reverse engineering toolkit for Unity games. no servers. no uploads. no bullshit. everything is processed locally in your browser the second you drop a file.

four tools. one page. zero excuses.

---

## tools

### ⚡ symbol extractor
drop your `libil2cpp.so` or `.apk` and watch it rip every exported symbol straight out of the ELF binary. supports both ELF32 and ELF64. filter down to il2cpp-only symbols, toggle addresses, copy or download. done in seconds.

### 🧠 metadata dumper
drop your `global-metadata.dat` or `.apk` — supports il2cpp metadata versions 24 through 29. pick your output format:
- **frida script** — class handles, method references, ready to inject
- **bnm offsets** — C++ header file for BNM modding
- **dump.cs** — full C# class stubs, il2cppdumper style

### 🌉 frida bridge extractor
drop a `symbolmap.json` or `libil2cpp.so` and get back a fully configured `frida-il2cpp-bridge.js` — the real bridge library, with your extracted offsets pre-baked into `Il2Cpp.$config`. just load it with frida and go.

### 🔒 js obfuscator
paste any javascript. hit obfuscate. it XORs your code with a random key, base64 encodes it, and wraps the whole thing in a self-executing decoder payload. no one is reading that. watermark included automatically.

---

## how to use

1. go to the live site
2. pick a tool from the tabs at the top
3. drag and drop your file (or click browse)
4. copy or download the output
5. that's literally it

---

## tech

- vanilla JS, zero frameworks, zero dependencies besides JSZip for APK unpacking
- ELF parser written from scratch — handles 32 and 64 bit, little and big endian
- il2cpp metadata parser supports versions 24–29 natively
- frida-il2cpp-bridge bundled and pre-configured on extraction
- XOR + base64 obfuscation with randomized keys every run

---

## credits

**made by Killa**
join the discord → https://discord.gg/Vt3HPSVbAk

*this toolkit was built with the help of [Claude](https://claude.ai) by Anthropic — the AI that actually writes code instead of explaining why it can't.*

---

## license

do whatever you want with it. don't be lame.
