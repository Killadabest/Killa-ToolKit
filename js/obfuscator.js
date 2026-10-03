// XOR + Base64 JS obfuscator
function obfuscateJS(code) {
  const WATERMARK = "/* Obfuscated By Killa's Website! https://discord.gg/Vt3HPSVbAk */\n";
  const full = WATERMARK + code;

  const key     = Math.floor(Math.random() * 200) + 30; // 30–229
  const encoder = new TextEncoder();
  const bytes   = encoder.encode(full);
  const xored   = new Uint8Array(bytes.length);

  for (let i = 0; i < bytes.length; i++) {
    xored[i] = bytes[i] ^ key;
  }

  // btoa on large arrays — chunk to avoid call stack overflow
  let binary = '';
  const chunkSize = 8192;
  for (let i = 0; i < xored.length; i += chunkSize) {
    binary += String.fromCharCode(...xored.subarray(i, i + chunkSize));
  }
  const b64 = btoa(binary);

  // Self-executing decoder payload — mangled variable names
  return `(function(_0x1a,_0x2b){const _0x3c=atob(_0x1a);const _0x4d=new Uint8Array(_0x3c.length);for(let i=0;i<_0x3c.length;i++){_0x4d[i]=_0x3c.charCodeAt(i)^_0x2b;}new Function(new TextDecoder().decode(_0x4d))();})(\"${b64}\",${key});`;
}
