<?php
// ═══════════════════════════════════════════════════════════════
//  SUPER APP — Web Tools Kriptografi Terpadu
//  Sultan Nur Riduan · NIM: 231220005 · Teknik Informatika
//  Kriptografi & Keamanan Komputer — PjBL OBE
//  Single File Application · PHP + OpenSSL
// ═══════════════════════════════════════════════════════════════

// ── OpenSSL Config ─────────────────────────────────────────────
$phpDir     = dirname(PHP_BINARY);
$cnfPaths   = [
    getenv('OPENSSL_CONF'),
    $phpDir . '\\extras\\ssl\\openssl.cnf',
    'C:\\laragon\\bin\\php\\php-8.4\\extras\\ssl\\openssl.cnf',
    'C:\\laragon\\bin\\php\\php-8.3\\extras\\ssl\\openssl.cnf',
    'C:\\laragon\\bin\\php\\php-8.2.19-Win32-vs16-x64\\extras\\ssl\\openssl.cnf',
    'C:\\laragon\\bin\\php\\php-8.1.10-Win32-vs16-x64\\extras\\ssl\\openssl.cnf',
    'C:\\xampp\\apache\\conf\\openssl.cnf',
    'C:\\xampp\\php\\extras\\ssl\\openssl.cnf',
    '/etc/ssl/openssl.cnf',
    '/usr/lib/ssl/openssl.cnf',
    '/usr/local/ssl/openssl.cnf',
];
$opensslCnf = null;
foreach ($cnfPaths as $p) {
    if ($p && file_exists($p)) { $opensslCnf = $p; break; }
}

$rsaConf = [
    "digest_alg"       => "sha256",
    "private_key_bits" => 2048,
    "private_key_type" => OPENSSL_KEYTYPE_RSA,
];
if ($opensslCnf) $rsaConf["config"] = $opensslCnf;

// ── Routing ────────────────────────────────────────────────────
$tool   = $_GET['tool'] ?? 'home';
$result = null;
$error  = null;

// ── 1. CAESAR CIPHER ───────────────────────────────────────────
function caesar(string $text, int $key, bool $enc): array {
    $result = '';
    $steps  = [];
    $key    = (($key % 26) + 26) % 26;
    $up     = strtoupper($text);
    for ($i = 0; $i < strlen($up); $i++) {
        $c = $up[$i];
        if (ctype_alpha($c)) {
            $P       = ord($c) - 65;
            $C       = $enc ? ($P + $key) % 26 : (($P - $key + 26) % 26);
            $out     = chr($C + 65);
            $result .= $out;
            $steps[] = ['in'=>$c,'out'=>$out,'P'=>$P,'K'=>$key,'C'=>$C];
        } else { $result .= $c; }
    }
    return ['result'=>$result,'steps'=>$steps];
}

// ── 2. XOR CIPHER ──────────────────────────────────────────────
function xorCipher(string $text, string $key): array {
    $out  = '';
    $hex  = '';
    $klen = strlen($key);
    if ($klen === 0) return ['error'=>'Kunci tidak boleh kosong.'];
    for ($i = 0; $i < strlen($text); $i++) {
        $xord = ord($text[$i]) ^ ord($key[$i % $klen]);
        $out .= chr($xord);
        $hex .= sprintf('%02X', $xord) . ' ';
    }
    return ['raw' => $out, 'hex' => trim($hex)];
}

function xorDecrypt(string $hexStr, string $key): string {
    $bytes = [];
    foreach (explode(' ', trim($hexStr)) as $h) {
        $h = trim($h);
        if ($h !== '') $bytes[] = hexdec($h);
    }
    $klen   = strlen($key);
    $result = '';
    foreach ($bytes as $i => $b) {
        $result .= chr($b ^ ord($key[$i % $klen]));
    }
    return $result;
}

// ── 3. SHA-256 HASHING ─────────────────────────────────────────
function computeHashes(string $data): array {
    return [
        'md5'    => hash('md5',    $data),
        'sha1'   => hash('sha1',   $data),
        'sha256' => hash('sha256', $data),
        'sha512' => hash('sha512', $data),
    ];
}

// ── 4. RSA GENERATOR & ENCRYPT ────────────────────────────────
function rsaGenerateKeys(array $conf): array {
    $res = @openssl_pkey_new($conf);
    if (!$res) return ['error' => openssl_error_string() ?: 'Gagal membuat keypair.'];
    @openssl_pkey_export($res, $priv, null, $conf);
    $det = openssl_pkey_get_details($res);
    return ['public' => $det['key'], 'private' => $priv];
}
function rsaEncrypt(string $msg, string $pub): string {
    if (!@openssl_public_encrypt($msg, $cipher, $pub, OPENSSL_PKCS1_OAEP_PADDING))
        return 'ERROR: ' . openssl_error_string();
    return base64_encode($cipher);
}
function rsaDecrypt(string $b64, string $priv): string {
    $cipher = base64_decode($b64);
    if (!@openssl_private_decrypt($cipher, $plain, $priv, OPENSSL_PKCS1_OAEP_PADDING))
        return 'ERROR: ' . openssl_error_string();
    return $plain;
}

// ── 5. DIGITAL SIGNATURE ──────────────────────────────────────
function dsSign(string $data, string $priv): string|false {
    if (!function_exists('openssl_sign')) return false;
    $ok = @openssl_sign($data, $sig, $priv, OPENSSL_ALGO_SHA256);
    return $ok ? base64_encode($sig) : false;
}
function dsVerify(string $data, string $sigB64, string $pub): string {
    if (!function_exists('openssl_verify')) return 'error|openssl_verify tidak tersedia.';
    $pubKey = @openssl_pkey_get_public($pub);
    if (!$pubKey) return 'error|Public Key tidak valid.';
    $sigBin = base64_decode($sigB64, true);
    if ($sigBin === false) return 'error|Signature bukan Base64 valid.';
    $r = @openssl_verify($data, $sigBin, $pubKey, OPENSSL_ALGO_SHA256);
    if ($r === 1)  return 'valid|Dokumen SAH — Tanda tangan cocok!';
    if ($r === 0)  return 'invalid|Dokumen PALSU — Data telah diubah!';
    return 'error|Error verifikasi: ' . openssl_error_string();
}

// ── POST HANDLER ───────────────────────────────────────────────
$formData = [];
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $tool = $_POST['tool'] ?? $tool;

    switch ($tool) {

        case 'caesar':
            $text  = $_POST['text'] ?? '';
            $key   = (int)($_POST['key'] ?? 3);
            $mode  = $_POST['mode'] ?? 'encrypt';
            $formData = compact('text','key','mode');
            if ($text === '') { $error = 'Teks tidak boleh kosong.'; break; }
            $out = caesar($text, $key, $mode === 'encrypt');
            $result = ['type'=>'caesar','data'=>$out,'mode'=>$mode,'key'=>$key];
            break;

        case 'xor':
            $text = $_POST['text'] ?? '';
            $key  = $_POST['key']  ?? '';
            $mode = $_POST['mode'] ?? 'encrypt';
            $formData = compact('text','key','mode');
            if ($key === '') { $error = 'Kunci tidak boleh kosong.'; break; }
            if ($mode === 'encrypt') {
                if ($text === '') { $error = 'Teks tidak boleh kosong.'; break; }
                $out = xorCipher($text, $key);
                if (isset($out['error'])) { $error = $out['error']; break; }
                $result = ['type'=>'xor','mode'=>'encrypt','hex'=>$out['hex'],'key'=>$key];
            } else {
                $hexIn = $_POST['text'] ?? '';
                $plain = xorDecrypt($hexIn, $key);
                $result = ['type'=>'xor','mode'=>'decrypt','plain'=>$plain,'key'=>$key];
            }
            break;

        case 'hash':
            $text = $_POST['text'] ?? '';
            $formData = ['text'=>$text];
            if ($text === '') { $error = 'Input tidak boleh kosong.'; break; }
            $result = ['type'=>'hash','hashes'=>computeHashes($text),'len'=>strlen($text)];
            break;

        case 'rsa':
            global $rsaConf;
            $aksi  = $_POST['aksi'] ?? 'generate';
            $pesan = trim($_POST['pesan'] ?? '');
            $kunci = trim($_POST['kunci'] ?? '');
            $formData = compact('aksi','pesan','kunci');
            if ($aksi === 'generate') {
                $keys = rsaGenerateKeys($rsaConf);
                if (isset($keys['error'])) { $error = $keys['error']; break; }
                $result = ['type'=>'rsa','aksi'=>'generate','public'=>$keys['public'],'private'=>$keys['private']];
            } elseif ($aksi === 'enkripsi') {
                if ($pesan===''||$kunci==='') { $error='Pesan & Public Key wajib diisi.'; break; }
                $cipher = rsaEncrypt($pesan, $kunci);
                $result = ['type'=>'rsa','aksi'=>'enkripsi','output'=>$cipher];
            } else {
                if ($pesan===''||$kunci==='') { $error='Ciphertext & Private Key wajib diisi.'; break; }
                $plain = rsaDecrypt($pesan, $kunci);
                $result = ['type'=>'rsa','aksi'=>'dekripsi','output'=>$plain];
            }
            break;

        case 'ds':
            global $rsaConf;
            $aksi  = $_POST['aksi'] ?? 'generate';
            $dok   = trim($_POST['dokumen'] ?? '');
            $sig   = trim($_POST['signature'] ?? '');
            $kunci = trim($_POST['kunci'] ?? '');
            $formData = compact('aksi','dok','sig','kunci');
            switch ($aksi) {
                case 'generate':
                    $keys = rsaGenerateKeys($rsaConf);
                    if (isset($keys['error'])) { $error = $keys['error']; break 2; }
                    $result = ['type'=>'ds','aksi'=>'generate','public'=>$keys['public'],'private'=>$keys['private']];
                    break;
                case 'sign':
                    if ($dok===''||$kunci==='') { $error='Dokumen & Private Key wajib diisi.'; break 2; }
                    $s = dsSign($dok, $kunci);
                    if ($s===false) { $error='Gagal sign. Pastikan Private Key PEM valid.'; break 2; }
                    $result = ['type'=>'ds','aksi'=>'sign','signature'=>$s,'hash'=>hash('sha256',$dok)];
                    break;
                case 'verify':
                    if ($dok===''||$sig===''||$kunci==='') { $error='Semua field wajib diisi.'; break 2; }
                    $raw = dsVerify($dok, $sig, $kunci);
                    [$status,$msg] = explode('|', $raw, 2);
                    $result = ['type'=>'ds','aksi'=>'verify','status'=>$status,'msg'=>$msg,'hash'=>hash('sha256',$dok)];
                    break;
            }
            break;
    }
}

// ── TOOL MENU ──────────────────────────────────────────────────
$tools = [
    'home'   => ['fa-house',        'Beranda',           'Dashboard utama'],
    'caesar' => ['fa-key',          'Caesar Cipher',     'Enkripsi & Dekripsi monoalfabetik'],
    'xor'    => ['fa-code',         'XOR Cipher',        'Enkripsi XOR dengan Bin2Hex'],
    'hash'   => ['fa-hashtag',      'SHA-256 Hashing',   'Generator hash kriptografis'],
    'rsa'    => ['fa-lock',         'RSA Generator',     'Generate keypair & enkripsi RSA'],
    'ds'     => ['fa-fingerprint',  'Digital Signature', 'Sign & Verify dokumen digital'],
];
?>
<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>KriptoTools — Sultan Nur Riduan</title>
<script src="https://cdn.tailwindcss.com"></script>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css"/>
<script>
tailwind.config = {
  theme: {
    extend: {
      fontFamily: {
        sans: ['"Sora"','sans-serif'],
        mono: ['"JetBrains Mono"','monospace'],
      },
      animation: {
        fadeUp:   'fadeUp .45s ease both',
        shimmer:  'shimmer 3s linear infinite',
        scanline: 'scanline 3s linear infinite',
        glow:     'glow 2s ease-in-out infinite alternate',
      },
      keyframes: {
        fadeUp:   { from:{opacity:'0',transform:'translateY(16px)'}, to:{opacity:'1',transform:'translateY(0)'} },
        shimmer:  { from:{backgroundPosition:'200% 0'}, to:{backgroundPosition:'-200% 0'} },
        scanline: { from:{transform:'translateY(-100%)'}, to:{transform:'translateY(100vh)'} },
        glow:     { from:{boxShadow:'0 0 8px rgba(139,92,246,.3)'}, to:{boxShadow:'0 0 22px rgba(139,92,246,.65)'} },
      },
    },
  },
}
</script>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Sora:wght@300;400;500;600;700&display=swap" rel="stylesheet"/>
<style>
  :root {
    --bg-base:    #0b0619;
    --bg-mid:     #120e28;
    --bg-card:    rgba(38,22,80,.72);
    --border:     rgba(150,110,220,.22);
    --border-hi:  rgba(139,92,246,.5);
    --purple:     #8b5cf6;
    --purple-hi:  #a78bfa;
    --purple-lo:  rgba(139,92,246,.15);
    --teal:       #14b8a6;
    --green:      #4ade80;
    --red:        #f87171;
    --amber:      #fbbf24;
  }

  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    font-family: 'Sora', sans-serif;
    background: var(--bg-base);
    color: #e2d9f3;
    min-height: 100vh;
    overflow-x: hidden;
  }

  /* Noise */
  body::before {
    content:''; position:fixed; inset:0; z-index:0; pointer-events:none;
    background: url("data:image/svg+xml,%3Csvg viewBox='0 0 300 300' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='.75' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='.028'/%3E%3C/svg%3E");
  }

  /* Layout */
  .layout { display: flex; min-height: 100vh; position: relative; z-index: 1; }

  /* ── SIDEBAR ── */
  .sidebar {
    width: 256px;
    flex-shrink: 0;
    background: rgba(14,8,38,.88);
    backdrop-filter: blur(24px);
    border-right: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    position: fixed;
    top: 0; left: 0; bottom: 0;
    z-index: 50;
    overflow-y: auto;
    overflow-x: hidden;
  }
  .sidebar-brand {
    padding: 1.5rem 1.4rem 1rem;
    border-bottom: 1px solid var(--border);
  }
  .brand-badge {
    display: inline-flex; align-items: center; gap: 6px;
    padding: 4px 10px; border-radius: 20px;
    background: var(--purple-lo);
    border: 1px solid var(--border-hi);
    font-size: 10px; font-weight: 700;
    letter-spacing: .08em; text-transform: uppercase;
    color: var(--purple-hi); margin-bottom: 10px;
  }
  .brand-title {
    font-size: 1.35rem; font-weight: 700; line-height: 1.25;
    letter-spacing: -.02em;
    background: linear-gradient(135deg,#a78bfa,#c084fc,#818cf8);
    background-size: 200% auto;
    -webkit-background-clip: text; background-clip: text;
    -webkit-text-fill-color: transparent;
    animation: shimmer 4s linear infinite;
  }
  .brand-sub { font-size: 11px; color: rgba(160,130,220,.5); margin-top: 3px; }

  .nav-section-label {
    padding: .75rem 1.4rem .35rem;
    font-size: 9px; font-weight: 700; letter-spacing: .12em;
    text-transform: uppercase; color: rgba(130,100,200,.45);
  }

  .nav-item {
    display: flex; align-items: center; gap: 11px;
    padding: .6rem 1.4rem;
    font-size: 13px; font-weight: 500;
    color: rgba(180,155,230,.55);
    border-left: 3px solid transparent;
    text-decoration: none;
    transition: all .18s;
    cursor: pointer; border-top: none; border-right: none; border-bottom: none;
    background: none; width: 100%;
    position: relative;
  }
  .nav-item:hover { color: rgba(180,155,230,.9); background: rgba(139,92,246,.07); }
  .nav-item.active {
    color: #c4b5fd;
    background: rgba(139,92,246,.15);
    border-left-color: var(--purple);
  }
  .nav-item.active .nav-icon { color: var(--purple-hi); }
  .nav-icon { width: 15px; text-align: center; font-size: 13px; flex-shrink:0; }
  .nav-badge {
    margin-left: auto; font-size: 9px; font-weight: 700;
    padding: 2px 7px; border-radius: 10px;
    background: rgba(139,92,246,.25); color: var(--purple-hi);
    border: 1px solid rgba(139,92,246,.35);
  }

  .sidebar-footer {
    margin-top: auto; padding: 1rem 1.4rem;
    border-top: 1px solid var(--border);
  }
  .sidebar-user {
    display: flex; align-items: center; gap: 10px;
  }
  .user-avatar {
    width: 34px; height: 34px; border-radius: 50%;
    background: linear-gradient(135deg,#7c3aed,#c084fc);
    display: flex; align-items: center; justify-content: center;
    font-size: 14px; color: #fff; flex-shrink: 0;
    box-shadow: 0 0 12px rgba(139,92,246,.45);
  }
  .user-name { font-size: 12px; font-weight: 600; color: #d4c5f5; line-height: 1.2; }
  .user-nim  { font-size: 10px; color: rgba(150,120,210,.5); font-family: 'JetBrains Mono', monospace; }

  /* ── MAIN CONTENT ── */
  .main {
    margin-left: 256px;
    flex: 1;
    min-height: 100vh;
    display: flex;
    flex-direction: column;
  }

  /* Top bar */
  .topbar {
    padding: .9rem 2rem;
    border-bottom: 1px solid var(--border);
    background: rgba(12,7,30,.7);
    backdrop-filter: blur(16px);
    display: flex; align-items: center; gap: 12px;
    position: sticky; top: 0; z-index: 40;
  }
  .topbar-title { font-size: 15px; font-weight: 700; color: #d4c5f5; }
  .topbar-sub   { font-size: 11px; color: rgba(150,120,210,.55); margin-top: 1px; }
  .topbar-icon  {
    width: 36px; height: 36px; border-radius: 10px;
    background: var(--purple-lo); border: 1px solid var(--border-hi);
    display: flex; align-items: center; justify-content: center;
    color: var(--purple-hi); font-size: 15px;
  }

  .page-content { padding: 2rem; flex: 1; max-width: 820px; }

  /* ── GLASS CARDS ── */
  .glass {
    background: var(--bg-card);
    backdrop-filter: blur(20px);
    border: 1px solid var(--border);
    border-radius: 18px;
    box-shadow: 0 10px 50px rgba(0,0,0,.45), 0 1px 0 rgba(255,255,255,.04) inset;
  }
  .glass-sm {
    background: rgba(25,14,58,.6);
    border: 1px solid rgba(120,80,200,.18);
    border-radius: 12px;
  }
  .glass-result {
    background: rgba(80,40,150,.2);
    backdrop-filter: blur(12px);
    border: 1px solid rgba(150,100,230,.3);
    border-radius: 14px;
  }
  .glass-success { background:rgba(20,150,85,.14); border:1px solid rgba(74,222,128,.3); border-radius:14px; }
  .glass-error   { background:rgba(180,30,30,.15);  border:1px solid rgba(248,113,113,.3); border-radius:14px; }
  .glass-invalid { background:rgba(180,30,30,.15);  border:1px solid rgba(248,113,113,.3); border-radius:14px; }
  .glass-warning { background:rgba(120,80,10,.2);   border:1px solid rgba(251,191,36,.3);  border-radius:14px; }

  /* ── SECTION HEADER ── */
  .section-title {
    display: flex; align-items: center; gap: 10px;
    font-size: 15px; font-weight: 700; color: #e2d9f3;
    margin-bottom: 1.25rem;
  }
  .section-title::before {
    content:'';
    display: block; width: 3px; height: 20px; border-radius: 2px;
    background: linear-gradient(180deg,#a78bfa,#c084fc);
    flex-shrink: 0;
  }

  /* ── INPUTS ── */
  .field-label {
    display: block; font-size: 11px; font-weight: 600;
    letter-spacing: .05em; color: rgba(160,130,220,.7);
    text-transform: uppercase; margin-bottom: 6px;
  }
  .inp {
    width: 100%;
    background: rgba(45,25,80,.65);
    border: 1px solid rgba(120,80,200,.22);
    color: #e2d9f3;
    padding: 10px 14px;
    border-radius: 10px;
    font-family: 'Sora', sans-serif;
    font-size: 13px;
    outline: none;
    transition: border-color .2s, box-shadow .2s;
  }
  .inp:focus { border-color: rgba(139,92,246,.6); box-shadow: 0 0 0 3px rgba(139,92,246,.1); }
  .inp::placeholder { color: rgba(120,90,180,.35); }
  textarea.inp { resize: vertical; font-family: 'JetBrains Mono', monospace; font-size: 12px; }
  select.inp {
    -webkit-appearance: none; appearance: none; cursor: pointer;
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='8' fill='none' viewBox='0 0 12 8'%3E%3Cpath d='M1 1l5 5 5-5' stroke='%239580c8' stroke-width='1.8' stroke-linecap='round'/%3E%3C/svg%3E");
    background-repeat: no-repeat; background-position: right 12px center;
    padding-right: 36px;
  }

  /* ── BUTTONS ── */
  .btn-primary {
    display: inline-flex; align-items: center; justify-content: center; gap: 8px;
    padding: 10px 22px; border-radius: 10px;
    font-family: 'Sora', sans-serif;
    font-size: 13px; font-weight: 700; color: #fff;
    background: linear-gradient(135deg,#7c3aed,#8b5cf6);
    box-shadow: 0 4px 16px rgba(109,40,217,.4);
    border: none; cursor: pointer;
    transition: all .18s;
  }
  .btn-primary:hover { transform: translateY(-1px); box-shadow: 0 6px 22px rgba(109,40,217,.55); }
  .btn-primary:active { transform: scale(.97); }

  .btn-ghost {
    display: inline-flex; align-items: center; justify-content: center; gap: 8px;
    padding: 10px 18px; border-radius: 10px;
    font-family: 'Sora', sans-serif;
    font-size: 13px; font-weight: 600; color: #a78bfa;
    background: rgba(139,92,246,.1);
    border: 1px solid rgba(139,92,246,.3);
    cursor: pointer; transition: all .18s; text-decoration: none;
  }
  .btn-ghost:hover { background: rgba(139,92,246,.18); color: #c4b5fd; }

  .tab-btn {
    display: flex; flex-direction: column; align-items: center; gap: 4px;
    padding: 10px 8px; border-radius: 12px;
    font-family: 'Sora', sans-serif;
    font-size: 12px; font-weight: 600;
    color: rgba(160,130,220,.5);
    background: rgba(40,22,80,.5);
    border: 1px solid rgba(120,80,200,.2);
    cursor: pointer; transition: all .18s; line-height: 1.3;
  }
  .tab-btn:hover { border-color: rgba(139,92,246,.4); color: #a78bfa; }
  .tab-btn.active {
    background: rgba(139,92,246,.2);
    border-color: var(--purple);
    color: #c4b5fd;
    box-shadow: 0 0 0 1px var(--purple) inset;
  }
  .tab-sub { font-size: 10px; font-weight: 400; opacity: .6; text-align: center; }

  /* ── OUTPUT ── */
  .output-pre {
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px; line-height: 1.75;
    color: #a5f3fc;
    background: rgba(8,4,24,.75);
    border: 1px solid rgba(139,92,246,.22);
    border-radius: 10px;
    padding: .9rem;
    white-space: pre-wrap; word-break: break-all;
    max-height: 200px; overflow-y: auto;
  }

  /* ── BADGES ── */
  .badge {
    display: inline-flex; align-items: center; gap: 5px;
    padding: 3px 10px; border-radius: 20px;
    font-size: 11px; font-weight: 600;
  }
  .badge-violet { background:rgba(139,92,246,.18); border:1px solid rgba(139,92,246,.4); color:#c4b5fd; }
  .badge-green  { background:rgba(74,222,128,.12); border:1px solid rgba(74,222,128,.35); color:#86efac; }
  .badge-teal   { background:rgba(20,184,166,.12); border:1px solid rgba(20,184,166,.35); color:#5eead4; }
  .badge-red    { background:rgba(248,113,113,.12); border:1px solid rgba(248,113,113,.35); color:#fca5a5; }
  .badge-amber  { background:rgba(251,191,36,.12); border:1px solid rgba(251,191,36,.35); color:#fcd34d; }

  /* ── STEP ROW ── */
  .step-row {
    display: flex; align-items: center; gap: 8px;
    padding: 5px 0;
    border-bottom: 1px solid rgba(120,80,200,.1);
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px; color: rgba(180,155,230,.7);
  }
  .step-row:last-child { border-bottom: none; }

  /* ── HASH BARS ── */
  .hash-entry { margin-bottom: .85rem; }
  .hash-bar { height: 3px; border-radius: 2px; margin: 4px 0 5px; }

  /* ── HOME CARDS ── */
  .home-card {
    display: block;
    padding: 1.1rem 1.25rem;
    border-radius: 14px;
    background: rgba(25,14,55,.65);
    border: 1px solid rgba(120,80,200,.18);
    text-decoration: none;
    transition: all .2s;
    cursor: pointer;
  }
  .home-card:hover {
    border-color: rgba(139,92,246,.5);
    background: rgba(39,22,85,.8);
    transform: translateY(-2px);
    box-shadow: 0 8px 28px rgba(0,0,0,.3);
  }

  /* ── SCAN OVERLAY ── */
  .scan-wrap { position:relative; overflow:hidden; border-radius:inherit; }
  .scan-line { position:absolute; width:100%; height:2px; pointer-events:none;
    background:linear-gradient(90deg,transparent,rgba(74,222,128,.25),transparent);
    animation:scanline 3s linear infinite; }

  /* ── ERROR INLINE ── */
  .err-box {
    display:flex; align-items:center; gap:10px;
    padding:.8rem 1rem; border-radius:10px;
    background:rgba(180,30,30,.15); border:1px solid rgba(248,113,113,.3);
    font-size:13px; color:#fca5a5; margin-top:1rem;
  }

  /* Scrollbar */
  ::-webkit-scrollbar { width:5px; }
  ::-webkit-scrollbar-track { background:transparent; }
  ::-webkit-scrollbar-thumb { background:rgba(139,92,246,.35); border-radius:10px; }

  /* Glows */
  .glow-blob {
    position:fixed; border-radius:50%; filter:blur(90px);
    pointer-events:none; z-index:0;
  }

  /* ── COPY BTN ── */
  .copy-btn {
    font-size:11px; color:rgba(139,92,246,.6);
    background:none; border:none; cursor:pointer;
    font-family:'JetBrains Mono',monospace;
    transition:color .15s; padding: 2px 6px;
  }
  .copy-btn:hover { color: var(--purple-hi); }

  /* Mobile sidebar toggle */
  @media (max-width: 768px) {
    .sidebar { transform: translateX(-100%); transition: transform .3s; }
    .sidebar.open { transform: translateX(0); }
    .main { margin-left: 0; }
    .page-content { padding: 1.25rem; }
    .topbar { padding: .8rem 1.25rem; }
    .menu-toggle { display:flex !important; }
  }
  .menu-toggle { display:none; }

  /* Toast */
  #toast {
    position:fixed; bottom:24px; left:50%; transform:translateX(-50%) translateY(60px);
    background:rgba(30,180,90,.92); color:#fff; padding:10px 22px;
    border-radius:12px; font-size:13px; font-weight:600;
    transition:transform .3s ease, opacity .3s ease;
    opacity:0; z-index:9999; pointer-events:none;
    border:1px solid rgba(74,222,128,.4);
    box-shadow:0 6px 24px rgba(0,0,0,.4);
  }
  #toast.show { transform:translateX(-50%) translateY(0); opacity:1; }
  #toast.error-toast { background:rgba(180,30,30,.92); border-color:rgba(248,113,113,.4); }

  .hidden { display: none !important; }
</style>
</head>
<body>

<!-- Toast -->
<div id="toast"></div>

<!-- Glows -->
<div class="glow-blob" style="width:500px;height:500px;background:rgba(109,40,217,.09);top:-160px;left:-160px;"></div>
<div class="glow-blob" style="width:400px;height:400px;background:rgba(20,184,166,.07);bottom:-120px;right:-100px;"></div>

<div class="layout">

<!-- ═══════════════ SIDEBAR ═══════════════ -->
<aside class="sidebar" id="sidebar">

  <div class="sidebar-brand">
    <div class="brand-badge"><i class="fa-solid fa-shield-halved"></i> Kriptografi</div>
    <div class="brand-title">KriptoTools</div>
    <div class="brand-sub">Web Tools Kriptografi Terpadu</div>
  </div>

  <div class="nav-section-label">Menu Utama</div>
  <?php foreach ($tools as $key => [$icon, $label, $desc]): ?>
  <form method="GET" style="display:contents">
    <input type="hidden" name="tool" value="<?= $key ?>"/>
    <button type="submit" class="nav-item <?= $tool===$key?'active':'' ?>">
      <i class="fa-solid <?= $icon ?> nav-icon"></i>
      <span><?= $label ?></span>
      <?php if ($key==='ds'): ?><span class="nav-badge">+10</span><?php endif; ?>
    </button>
  </form>
  <?php endforeach; ?>

  <div style="flex:1"></div>

  <div class="sidebar-footer">
    <div class="sidebar-user">
      <div class="user-avatar"><i class="fa-solid fa-user-graduate"></i></div>
      <div>
        <div class="user-name">Sultan Nur Riduan</div>
        <div class="user-nim">231220005</div>
      </div>
    </div>
    <div style="margin-top:.6rem;font-size:10px;color:rgba(130,100,200,.35);line-height:1.5;">
      Teknik Informatika<br/>Praktikum PjBL — OBE
    </div>
  </div>

</aside>

<!-- ═══════════════ MAIN ═══════════════ -->
<div class="main">

  <!-- Topbar -->
  <div class="topbar">
    <button class="menu-toggle" id="menuToggle" onclick="toggleSidebar()"
            style="background:rgba(139,92,246,.15);border:1px solid rgba(139,92,246,.3);color:#a78bfa;width:34px;height:34px;border-radius:8px;cursor:pointer;font-size:14px;">
      <i class="fa-solid fa-bars"></i>
    </button>
    <div class="topbar-icon">
      <i class="fa-solid <?= $tools[$tool][0] ?>"></i>
    </div>
    <div>
      <div class="topbar-title"><?= $tools[$tool][1] ?></div>
      <div class="topbar-sub"><?= $tools[$tool][2] ?></div>
    </div>
    <div style="margin-left:auto;display:flex;align-items:center;gap:8px;">
      <span class="badge badge-violet" style="font-size:10px;">
        <i class="fa-solid fa-circle" style="font-size:7px;color:#4ade80"></i> PHP OpenSSL
      </span>
    </div>
  </div>

  <!-- Page Content -->
  <div class="page-content">

  <?php
  // ════════════════════════════════════════════
  //  HOME
  // ════════════════════════════════════════════
  if ($tool === 'home'): ?>

  <div style="animation:fadeUp .45s ease both">
    <div style="margin-bottom:1.75rem;">
      <div class="badge badge-violet" style="margin-bottom:.75rem;font-size:11px;">
        <i class="fa-solid fa-graduation-cap"></i> PjBL OBE · Pertemuan 1–7
      </div>
      <h1 style="font-size:2rem;font-weight:700;letter-spacing:-.03em;line-height:1.15;margin-bottom:.5rem;">
        Web Tools<br/>
        <span style="background:linear-gradient(135deg,#a78bfa,#c084fc,#818cf8);background-size:200% auto;-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;animation:shimmer 3s linear infinite;">
          Kriptografi
        </span>
      </h1>
      <p style="font-size:13px;color:rgba(160,130,220,.6);line-height:1.7;max-width:480px;">
        Aplikasi single-file PHP terpadu untuk mempelajari dan mempraktikkan berbagai algoritma kriptografi klasik dan modern.
      </p>
    </div>

    <!-- Tool grid -->
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:.85rem;margin-bottom:2rem;">
      <?php
      $homeCards = [
        ['caesar','Caesar Cipher','Substitusi monoalfabetik dengan pergeseran tetap.','fa-key','#8b5cf6','1'],
        ['xor','XOR Cipher','Enkripsi XOR dengan output Bin2Hex.','fa-code','#06b6d4','2'],
        ['hash','SHA-256 Hashing','Generator hash MD5, SHA-1, SHA-256, SHA-512.','fa-hashtag','#10b981','3'],
        ['rsa','RSA Generator','Keypair RSA 2048-bit + enkripsi OAEP.','fa-lock','#f59e0b','4'],
        ['ds','Digital Signature','Sign & Verify dokumen. Bonus +10 poin!','fa-fingerprint','#ec4899','5'],
      ];
      foreach ($homeCards as [$k,$label,$desc,$icon,$color,$num]):
      ?>
      <form method="GET" style="display:contents">
        <input type="hidden" name="tool" value="<?= $k ?>"/>
        <button type="submit" class="home-card" style="text-align:left;width:100%;">
          <div style="display:flex;align-items:flex-start;gap:12px;">
            <div style="width:38px;height:38px;border-radius:10px;display:flex;align-items:center;justify-content:center;flex-shrink:0;background:<?= $color ?>22;border:1px solid <?= $color ?>44;">
              <i class="fa-solid <?= $icon ?>" style="color:<?= $color ?>;font-size:15px;"></i>
            </div>
            <div>
              <div style="display:flex;align-items:center;gap:6px;margin-bottom:3px;">
                <span style="font-size:13px;font-weight:700;color:#e2d9f3;"><?= $label ?></span>
                <?php if ($k==='ds'): ?><span class="badge badge-violet" style="font-size:9px;padding:1px 6px;">+10</span><?php endif; ?>
              </div>
              <p style="font-size:11px;color:rgba(150,120,210,.55);line-height:1.5;"><?= $desc ?></p>
            </div>
          </div>
        </button>
      </form>
      <?php endforeach; ?>
    </div>

    <!-- Info card -->
    <div class="glass" style="padding:1.5rem;margin-bottom:1rem;">
      <div class="section-title" style="font-size:13px;">Spesifikasi Teknis Proyek</div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:.6rem;">
        <?php $specs = [
          ['fa-microchip','Arsitektur','Single File PHP (switch routing)','#8b5cf6'],
          ['fa-layer-group','Algoritma','Caesar · XOR · SHA · RSA · DSig','#10b981'],
          ['fa-lock','Kriptografi','OpenSSL 2048-bit RSA + OAEP','#f59e0b'],
          ['fa-palette','UI Framework','Tailwind CSS + Font Awesome','#06b6d4'],
        ];
        foreach ($specs as [$icon,$lbl,$val,$c]): ?>
        <div class="glass-sm" style="padding:.75rem 1rem;display:flex;align-items:center;gap:10px;">
          <div style="width:30px;height:30px;border-radius:8px;display:flex;align-items:center;justify-content:center;background:<?= $c ?>1a;flex-shrink:0;">
            <i class="fa-solid <?= $icon ?>" style="color:<?= $c ?>;font-size:12px;"></i>
          </div>
          <div>
            <div style="font-size:10px;color:rgba(130,100,200,.5);margin-bottom:1px;"><?= $lbl ?></div>
            <div style="font-size:12px;font-weight:600;color:#d4c5f5;"><?= $val ?></div>
          </div>
        </div>
        <?php endforeach; ?>
      </div>
    </div>
  </div>

  <?php
  // ════════════════════════════════════════════
  //  CAESAR CIPHER
  // ════════════════════════════════════════════
  elseif ($tool === 'caesar'):
  $cFd = $formData + ['text'=>'','key'=>3,'mode'=>'encrypt'];
  ?>

  <div style="animation:fadeUp .45s ease both">
  <div class="glass" style="padding:1.75rem;margin-bottom:1rem;">
    <div class="section-title">
      <i class="fa-solid fa-key" style="color:#8b5cf6;"></i> Kalkulator Caesar Cipher
    </div>

    <form method="POST">
      <input type="hidden" name="tool" value="caesar"/>

      <div style="margin-bottom:1rem;">
        <label class="field-label"><i class="fa-solid fa-align-left" style="opacity:.6;margin-right:4px;"></i> Teks Input</label>
        <textarea name="text" rows="3" class="inp" placeholder="Ketik pesan di sini..."><?= htmlspecialchars($cFd['text']) ?></textarea>
      </div>

      <div style="display:grid;grid-template-columns:1fr 1fr;gap:.85rem;margin-bottom:1.25rem;">
        <div>
          <label class="field-label"><i class="fa-solid fa-hashtag" style="opacity:.6;margin-right:4px;"></i> Kunci (K) · 1–25</label>
          <input type="number" name="key" min="1" max="25" class="inp" value="<?= htmlspecialchars($cFd['key']) ?>"/>
        </div>
        <div>
          <label class="field-label"><i class="fa-solid fa-sliders" style="opacity:.6;margin-right:4px;"></i> Mode</label>
          <select name="mode" class="inp">
            <option value="encrypt" <?= $cFd['mode']==='encrypt'?'selected':'' ?>>🔒 Enkripsi</option>
            <option value="decrypt" <?= $cFd['mode']==='decrypt'?'selected':'' ?>>🔓 Dekripsi</option>
          </select>
        </div>
      </div>

      <div style="display:flex;gap:.75rem;">
        <button type="submit" class="btn-primary"><i class="fa-solid fa-bolt"></i> Hitung</button>
        <a href="?tool=caesar" class="btn-ghost"><i class="fa-solid fa-rotate-left"></i> Reset</a>
      </div>
    </form>

    <?php if ($error): ?><div class="err-box"><i class="fa-solid fa-triangle-exclamation"></i><?= htmlspecialchars($error) ?></div><?php endif; ?>

    <?php if ($result && $result['type']==='caesar'): ?>
    <div class="glass-result" style="padding:1.25rem;margin-top:1.25rem;">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:.75rem;">
        <span style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:rgba(160,130,220,.6);">
          <i class="fa-solid fa-star-of-life" style="color:#8b5cf6;margin-right:4px;"></i>
          Hasil <?= $result['mode']==='encrypt'?'Enkripsi':'Dekripsi' ?>
        </span>
        <button onclick="copyText('caesar-out')" class="copy-btn"><i class="fa-regular fa-copy"></i> Copy</button>
      </div>
      <div id="caesar-out" class="output-pre" style="font-size:1.15rem;font-weight:700;letter-spacing:.05em;color:#c4b5fd;"><?= htmlspecialchars($result['data']['result']) ?></div>
      <div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:.85rem;">
        <span class="badge badge-violet"><i class="fa-solid fa-key"></i> K = <?= $result['key'] ?></span>
        <span class="badge <?= $result['mode']==='encrypt'?'badge-green':'badge-amber' ?>">
          <i class="fa-solid <?= $result['mode']==='encrypt'?'fa-lock':'fa-lock-open' ?>"></i>
          <?= $result['mode']==='encrypt'?'Enkripsi':'Dekripsi' ?>
        </span>
      </div>

      <?php if (!empty($result['data']['steps'])): ?>
      <div style="margin-top:1rem;">
        <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:rgba(130,100,200,.45);margin-bottom:.5rem;">Langkah Pergeseran</div>
        <div style="max-height:180px;overflow-y:auto;">
          <?php foreach (array_slice($result['data']['steps'],0,20) as $i=>$s): ?>
          <div class="step-row">
            <span style="color:rgba(130,100,200,.4);width:20px;text-align:right;"><?= $i+1 ?>.</span>
            <span style="color:#c4b5fd;font-weight:700;"><?= $s['in'] ?></span>
            <span style="color:rgba(130,100,200,.5);">(<?= $s['P'] ?>)</span>
            <span style="color:rgba(130,100,200,.5);"><?= $result['mode']==='encrypt'?'+':'−' ?> <?= $s['K'] ?></span>
            <span style="color:rgba(130,100,200,.5);">=</span>
            <span style="color:#4ade80;font-weight:700;"><?= $s['out'] ?></span>
            <span style="color:rgba(130,100,200,.4);">(<?= $s['C'] ?>)</span>
          </div>
          <?php endforeach; ?>
          <?php if (count($result['data']['steps'])>20): ?>
          <div style="font-size:11px;color:rgba(130,100,200,.4);padding:4px 0;">… dan <?= count($result['data']['steps'])-20 ?> huruf lainnya</div>
          <?php endif; ?>
        </div>
      </div>
      <?php endif; ?>
    </div>
    <?php endif; ?>
  </div>

  <!-- Formula Card -->
  <div class="glass-sm" style="padding:1.1rem 1.25rem;">
    <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:rgba(130,100,200,.45);margin-bottom:.6rem;">Rumus</div>
    <div style="font-family:'JetBrains Mono',monospace;font-size:12px;line-height:2;color:rgba(180,155,230,.7);">
      Enkripsi: <span style="color:#4ade80;font-weight:600;">C = (P + K) mod 26</span><br/>
      Dekripsi: <span style="color:#fbbf24;font-weight:600;">P = (C − K + 26) mod 26</span>
    </div>
  </div>
  </div>

  <?php
  // ════════════════════════════════════════════
  //  XOR CIPHER
  // ════════════════════════════════════════════
  elseif ($tool === 'xor'):
  $xFd = $formData + ['text'=>'','key'=>'','mode'=>'encrypt'];
  ?>

  <div style="animation:fadeUp .45s ease both">
  <div class="glass" style="padding:1.75rem;margin-bottom:1rem;">
    <div class="section-title">
      <i class="fa-solid fa-code" style="color:#06b6d4;"></i> XOR Cipher · Bin2Hex
    </div>

    <form method="POST">
      <input type="hidden" name="tool" value="xor"/>

      <div style="margin-bottom:1rem;">
        <label class="field-label"><i class="fa-solid fa-align-left" style="opacity:.6;margin-right:4px;"></i>
          <span id="xor-input-label">Teks Asli (Plaintext)</span>
        </label>
        <textarea name="text" rows="3" class="inp" id="xor-text-inp"
          placeholder="Ketik pesan atau paste hex..."><?= htmlspecialchars($xFd['text']) ?></textarea>
      </div>

      <div style="display:grid;grid-template-columns:1fr 1fr;gap:.85rem;margin-bottom:1.25rem;">
        <div>
          <label class="field-label"><i class="fa-solid fa-key" style="opacity:.6;margin-right:4px;"></i> Kunci (Key)</label>
          <input type="text" name="key" class="inp" placeholder="Contoh: rahasia" value="<?= htmlspecialchars($xFd['key']) ?>"/>
        </div>
        <div>
          <label class="field-label"><i class="fa-solid fa-sliders" style="opacity:.6;margin-right:4px;"></i> Mode</label>
          <select name="mode" class="inp" id="xor-mode-sel" onchange="xorModeSwitch(this.value)">
            <option value="encrypt" <?= $xFd['mode']==='encrypt'?'selected':'' ?>>🔒 Enkripsi → Hex</option>
            <option value="decrypt" <?= $xFd['mode']==='decrypt'?'selected':'' ?>>🔓 Dekripsi ← Hex</option>
          </select>
        </div>
      </div>

      <div style="display:flex;gap:.75rem;">
        <button type="submit" class="btn-primary"><i class="fa-solid fa-bolt"></i> Proses</button>
        <a href="?tool=xor" class="btn-ghost"><i class="fa-solid fa-rotate-left"></i> Reset</a>
      </div>
    </form>

    <?php if ($error): ?><div class="err-box"><i class="fa-solid fa-triangle-exclamation"></i><?= htmlspecialchars($error) ?></div><?php endif; ?>

    <?php if ($result && $result['type']==='xor'): ?>
    <div class="glass-result" style="padding:1.25rem;margin-top:1.25rem;">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:.75rem;">
        <span style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:rgba(160,130,220,.6);">
          <i class="fa-solid fa-star-of-life" style="color:#06b6d4;margin-right:4px;"></i>
          Hasil <?= $result['mode']==='encrypt'?'Enkripsi (Hex)':'Dekripsi (Plaintext)' ?>
        </span>
        <button onclick="copyText('xor-out')" class="copy-btn"><i class="fa-regular fa-copy"></i> Copy</button>
      </div>
      <div id="xor-out" class="output-pre" style="color:#67e8f9;">
        <?= $result['mode']==='encrypt' ? htmlspecialchars($result['hex']) : htmlspecialchars($result['plain']) ?>
      </div>
      <div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:.75rem;">
        <span class="badge badge-teal"><i class="fa-solid fa-code"></i> XOR Cipher</span>
        <span class="badge badge-violet"><i class="fa-solid fa-key"></i> Key: <?= htmlspecialchars($result['key']) ?></span>
        <span class="badge <?= $result['mode']==='encrypt'?'badge-green':'badge-amber' ?>">
          <?= $result['mode']==='encrypt'?'Plaintext → Hex':'Hex → Plaintext' ?>
        </span>
      </div>
    </div>
    <?php endif; ?>
  </div>

  <div class="glass-sm" style="padding:1.1rem 1.25rem;">
    <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:rgba(130,100,200,.45);margin-bottom:.6rem;">Prinsip XOR</div>
    <div style="font-family:'JetBrains Mono',monospace;font-size:12px;line-height:2;color:rgba(180,155,230,.7);">
      Enkripsi: <span style="color:#67e8f9;font-weight:600;">C[i] = P[i] XOR K[i mod len(K)]</span><br/>
      Dekripsi: <span style="color:#fbbf24;font-weight:600;">P[i] = C[i] XOR K[i mod len(K)]</span><br/>
      Output: <span style="color:#4ade80;font-weight:600;">sprintf('%02X', byte) per karakter</span>
    </div>
  </div>
  </div>

  <?php
  // ════════════════════════════════════════════
  //  SHA-256 HASH
  // ════════════════════════════════════════════
  elseif ($tool === 'hash'):
  $hFd = $formData + ['text'=>''];
  ?>

  <div style="animation:fadeUp .45s ease both">
  <div class="glass" style="padding:1.75rem;margin-bottom:1rem;">
    <div class="section-title">
      <i class="fa-solid fa-hashtag" style="color:#10b981;"></i> Hash Generator
    </div>

    <form method="POST">
      <input type="hidden" name="tool" value="hash"/>
      <div style="margin-bottom:1.25rem;">
        <label class="field-label"><i class="fa-solid fa-align-left" style="opacity:.6;margin-right:4px;"></i> Input Teks / Data</label>
        <textarea name="text" rows="4" class="inp" placeholder="Ketik atau paste data yang akan di-hash..."><?= htmlspecialchars($hFd['text']) ?></textarea>
      </div>
      <div style="display:flex;gap:.75rem;">
        <button type="submit" class="btn-primary"><i class="fa-solid fa-hashtag"></i> Generate Hash</button>
        <a href="?tool=hash" class="btn-ghost"><i class="fa-solid fa-rotate-left"></i> Reset</a>
      </div>
    </form>

    <?php if ($error): ?><div class="err-box"><i class="fa-solid fa-triangle-exclamation"></i><?= htmlspecialchars($error) ?></div><?php endif; ?>

    <?php if ($result && $result['type']==='hash'):
    $algos = [
      'md5'    => ['MD5',    '#ef4444','⚠️ Usang',   'badge-red'],
      'sha1'   => ['SHA-1',  '#f59e0b','⚠️ Lemah',   'badge-amber'],
      'sha256' => ['SHA-256','#10b981','✅ Aman',    'badge-green'],
      'sha512' => ['SHA-512','#14b8a6','✅ Sangat Aman','badge-teal'],
    ];
    ?>
    <div class="glass-result" style="padding:1.25rem;margin-top:1.25rem;">
      <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:rgba(160,130,220,.6);margin-bottom:1rem;">
        <i class="fa-solid fa-hashtag" style="color:#10b981;margin-right:4px;"></i>
        Hash Results · <?= $result['len'] ?> karakter diproses
      </div>
      <?php foreach ($result['hashes'] as $algo=>$h):
        [$label,$color,$note,$badgeClass] = $algos[$algo]; ?>
      <div class="hash-entry">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:2px;">
          <div style="display:flex;align-items:center;gap:8px;">
            <span style="font-size:13px;font-weight:700;color:<?= $color ?>;"><?= $label ?></span>
            <span class="badge <?= $badgeClass ?>" style="font-size:9px;padding:1px 7px;"><?= $note ?></span>
            <span style="font-size:10px;color:rgba(130,100,200,.4);font-family:'JetBrains Mono',monospace;"><?= strlen($h)*4 ?> bits</span>
          </div>
          <button onclick="copyText('h-<?= $algo ?>')" class="copy-btn"><i class="fa-regular fa-copy"></i></button>
        </div>
        <div class="hash-bar" style="background:linear-gradient(90deg,<?= $color ?>,transparent);"></div>
        <code id="h-<?= $algo ?>" style="display:block;font-family:'JetBrains Mono',monospace;font-size:11px;word-break:break-all;padding:.6rem .8rem;border-radius:8px;color:rgba(200,175,240,.8);background:rgba(8,4,24,.6);border:1px solid rgba(120,80,200,.15);"><?= $h ?></code>
      </div>
      <?php endforeach; ?>
    </div>
    <?php endif; ?>
  </div>

  <div class="glass-sm" style="padding:1.1rem 1.25rem;">
    <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:rgba(130,100,200,.45);margin-bottom:.6rem;">Sifat Fungsi Hash</div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:.5rem;">
      <?php $props = [['One-Way','Tidak bisa dibalik'],['Deterministic','Input sama → output sama'],['Avalanche','Satu bit berubah → output berubah drastis'],['Collision-Resistant','Sangat susah menemukan dua input dengan hash sama']];
      foreach ($props as [$t,$d]): ?>
      <div style="padding:.5rem .75rem;border-radius:8px;background:rgba(20,10,50,.5);border:1px solid rgba(120,80,200,.12);">
        <div style="font-size:11px;font-weight:700;color:#a78bfa;"><?= $t ?></div>
        <div style="font-size:10px;color:rgba(130,100,200,.5);margin-top:2px;"><?= $d ?></div>
      </div>
      <?php endforeach; ?>
    </div>
  </div>
  </div>

  <?php
  // ════════════════════════════════════════════
  //  RSA
  // ════════════════════════════════════════════
  elseif ($tool === 'rsa'):
  $rFd = $formData + ['aksi'=>'generate','pesan'=>'','kunci'=>''];
  ?>

  <div style="animation:fadeUp .45s ease both">
  <div class="glass" style="padding:1.75rem;margin-bottom:1rem;">
    <div class="section-title">
      <i class="fa-solid fa-lock" style="color:#f59e0b;"></i> RSA Generator & Enkripsi
    </div>

    <!-- Tabs -->
    <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:.6rem;margin-bottom:1.5rem;" id="rsa-tabs">
      <?php foreach ([['generate','fa-key','Generate Key'],['enkripsi','fa-lock','Enkripsi'],['dekripsi','fa-lock-open','Dekripsi']] as [$v,$ic,$lb]): ?>
      <button type="button" onclick="rsaTab('<?= $v ?>')" id="rsa-tab-<?= $v ?>"
              class="tab-btn <?= $rFd['aksi']===$v?'active':'' ?>">
        <i class="fa-solid <?= $ic ?>"></i><?= $lb ?>
      </button>
      <?php endforeach; ?>
    </div>

    <form method="POST">
      <input type="hidden" name="tool" value="rsa"/>
      <input type="hidden" name="aksi" id="rsa-aksi" value="<?= htmlspecialchars($rFd['aksi']) ?>"/>

      <div id="rsa-hint" <?= $rFd['aksi']!=='generate'?'style="display:none"':'' ?>
           style="padding:.85rem 1rem;border-radius:10px;background:rgba(20,10,50,.6);border:1px solid rgba(139,92,246,.2);border-left:3px solid #8b5cf6;font-size:12px;color:rgba(160,130,220,.65);line-height:1.7;margin-bottom:1rem;">
        <strong style="color:#a78bfa;">Cara pakai:</strong> Klik <em>Proses</em> → sistem generate Public + Private Key RSA 2048-bit. Copy Public Key untuk enkripsi, simpan Private Key untuk dekripsi.
      </div>

      <div id="rsa-pesan-wrap" <?= $rFd['aksi']==='generate'?'style="display:none"':'' ?> style="margin-bottom:1rem;">
        <label class="field-label" id="rsa-pesan-label">
          <i class="fa-solid fa-align-left" style="opacity:.6;margin-right:4px;"></i>
          <?= $rFd['aksi']==='dekripsi'?'Ciphertext (Base64)':'Pesan / Plaintext' ?>
        </label>
        <textarea name="pesan" rows="3" class="inp" placeholder="Ketik pesan atau paste ciphertext..."><?= htmlspecialchars($rFd['pesan']) ?></textarea>
      </div>

      <div id="rsa-kunci-wrap" <?= $rFd['aksi']==='generate'?'style="display:none"':'' ?> style="margin-bottom:1.25rem;">
        <label class="field-label" id="rsa-kunci-label">
          <i class="fa-solid <?= $rFd['aksi']==='dekripsi'?'fa-lock':'fa-unlock' ?>" style="opacity:.6;margin-right:4px;"></i>
          <?= $rFd['aksi']==='dekripsi'?'Private Key (PEM)':'Public Key (PEM)' ?>
        </label>
        <textarea name="kunci" rows="5" class="inp" placeholder="-----BEGIN ... KEY-----"><?= htmlspecialchars($rFd['kunci']) ?></textarea>
      </div>

      <div style="display:flex;gap:.75rem;">
        <button type="submit" class="btn-primary"><i class="fa-solid fa-bolt"></i> Proses</button>
        <a href="?tool=rsa" class="btn-ghost"><i class="fa-solid fa-rotate-left"></i> Reset</a>
      </div>
    </form>

    <?php if ($error): ?><div class="err-box"><i class="fa-solid fa-triangle-exclamation"></i><?= htmlspecialchars($error) ?></div><?php endif; ?>

    <?php if ($result && $result['type']==='rsa'): ?>
    <div style="margin-top:1.25rem;">

      <?php if ($result['aksi']==='generate'): ?>
      <div class="glass-result" style="padding:1.25rem;">
        <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:rgba(160,130,220,.6);margin-bottom:1rem;">
          <i class="fa-solid fa-key" style="color:#f59e0b;margin-right:4px;"></i> RSA Keypair Berhasil Digenerate
        </div>
        <div style="margin-bottom:.85rem;">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:5px;">
            <span style="font-size:12px;font-weight:700;color:#fca5a5;"><i class="fa-solid fa-lock" style="margin-right:4px;"></i>Private Key — RAHASIA</span>
            <button onclick="copyText('rsa-priv')" class="copy-btn"><i class="fa-regular fa-copy"></i> Copy</button>
          </div>
          <pre id="rsa-priv" class="output-pre" style="color:#fca5a5;max-height:150px;"><?= htmlspecialchars($result['private']) ?></pre>
        </div>
        <div>
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:5px;">
            <span style="font-size:12px;font-weight:700;color:#86efac;"><i class="fa-solid fa-unlock" style="margin-right:4px;"></i>Public Key</span>
            <button onclick="copyText('rsa-pub')" class="copy-btn"><i class="fa-regular fa-copy"></i> Copy</button>
          </div>
          <pre id="rsa-pub" class="output-pre" style="color:#86efac;max-height:150px;"><?= htmlspecialchars($result['public']) ?></pre>
        </div>
        <div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:.85rem;">
          <span class="badge badge-violet"><i class="fa-solid fa-microchip"></i> RSA 2048-bit</span>
          <span class="badge badge-teal"><i class="fa-solid fa-shield-halved"></i> OAEP Padding</span>
        </div>
      </div>

      <?php else: ?>
      <div class="glass-result" style="padding:1.25rem;">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:.75rem;">
          <span style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:rgba(160,130,220,.6);">
            <i class="fa-solid fa-star-of-life" style="color:#8b5cf6;margin-right:4px;"></i>
            Hasil <?= $result['aksi']==='enkripsi'?'Enkripsi (Base64)':'Dekripsi (Plaintext)' ?>
          </span>
          <button onclick="copyText('rsa-out')" class="copy-btn"><i class="fa-regular fa-copy"></i> Copy</button>
        </div>
        <div id="rsa-out" class="output-pre" style="<?= str_starts_with($result['output'],'ERROR')?'color:#f87171':'color:#a5f3fc' ?>">
          <?= htmlspecialchars($result['output']) ?>
        </div>
      </div>
      <?php endif; ?>

    </div>
    <?php endif; ?>
  </div>
  </div>

  <?php
  // ════════════════════════════════════════════
  //  DIGITAL SIGNATURE
  // ════════════════════════════════════════════
  elseif ($tool === 'ds'):
  $dFd = $formData + ['aksi'=>'generate','dok'=>'','sig'=>'','kunci'=>''];
  ?>

  <div style="animation:fadeUp .45s ease both">

  <div style="padding:.75rem 1rem;border-radius:12px;background:rgba(139,92,246,.1);border:1px solid rgba(139,92,246,.3);display:flex;align-items:center;gap:10px;margin-bottom:1rem;font-size:12px;">
    <span class="badge badge-violet" style="font-size:12px;padding:4px 12px;"><i class="fa-solid fa-star"></i> Bonus +10 Poin</span>
    <span style="color:rgba(160,130,220,.7);">Sign & Verify dokumen digital menggunakan RSA-SHA256</span>
  </div>

  <div class="glass" style="padding:1.75rem;margin-bottom:1rem;">
    <div class="section-title">
      <i class="fa-solid fa-fingerprint" style="color:#ec4899;"></i> Digital Signature Simulator
    </div>

    <!-- Tabs -->
    <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:.5rem;margin-bottom:1.5rem;">
      <?php foreach ([['generate','fa-key','Generate','Keypair'],['sign','fa-pen-nib','Sign','Tanda Tangan'],['verify','fa-shield-halved','Verify','Validasi'],['hash','fa-hashtag','Hash','SHA-256']] as [$v,$ic,$lb,$sub]): ?>
      <button type="button" onclick="dsTab('<?= $v ?>')" id="ds-tab-<?= $v ?>"
              class="tab-btn <?= $dFd['aksi']===$v?'active':'' ?>">
        <i class="fa-solid <?= $ic ?>"></i><?= $lb ?>
        <span class="tab-sub"><?= $sub ?></span>
      </button>
      <?php endforeach; ?>
    </div>

    <form method="POST">
      <input type="hidden" name="tool" value="ds"/>
      <input type="hidden" name="aksi" id="ds-aksi" value="<?= htmlspecialchars($dFd['aksi']) ?>"/>

      <div id="ds-dok-wrap" <?= in_array($dFd['aksi'],['sign','verify','hash'])?'':'style="display:none"' ?> style="margin-bottom:1rem;">
        <label class="field-label"><i class="fa-solid fa-file-lines" style="opacity:.6;margin-right:4px;"></i> Isi Dokumen</label>
        <textarea name="dokumen" rows="3" class="inp" placeholder="Contoh: Transfer ke Budi Rp100.000"><?= htmlspecialchars($dFd['dok']) ?></textarea>
      </div>

      <div id="ds-sig-wrap" <?= $dFd['aksi']==='verify'?'':'style="display:none"' ?> style="margin-bottom:1rem;">
        <label class="field-label"><i class="fa-solid fa-signature" style="opacity:.6;margin-right:4px;"></i> Tanda Tangan Digital (Base64)</label>
        <textarea name="signature" rows="3" class="inp" placeholder="Paste Base64 signature..."><?= htmlspecialchars($dFd['sig']) ?></textarea>
      </div>

      <div id="ds-kunci-wrap" <?= in_array($dFd['aksi'],['sign','verify'])?'':'style="display:none"' ?> style="margin-bottom:1.25rem;">
        <label class="field-label" id="ds-kunci-label">
          <i class="fa-solid <?= $dFd['aksi']==='verify'?'fa-unlock':'fa-lock' ?>" style="opacity:.6;margin-right:4px;"></i>
          <?= $dFd['aksi']==='verify'?'Public Key (PEM)':'Private Key (PEM)' ?>
        </label>
        <textarea name="kunci" rows="4" class="inp" placeholder="-----BEGIN ... KEY-----"><?= htmlspecialchars($dFd['kunci']) ?></textarea>
      </div>

      <div id="ds-generate-hint" <?= $dFd['aksi']==='generate'?'':'style="display:none"' ?>
           style="padding:.85rem 1rem;border-radius:10px;background:rgba(20,10,50,.6);border:1px solid rgba(139,92,246,.2);border-left:3px solid #ec4899;font-size:12px;color:rgba(160,130,220,.65);line-height:1.7;margin-bottom:1rem;">
        <strong style="color:#f9a8d4;">Alur kerja:</strong> Generate Keypair → Sign dokumen dengan Private Key → Verify dengan Public Key. Coba ganti isi dokumen setelah sign untuk melihat avalanche effect!
      </div>

      <div style="display:flex;gap:.75rem;">
        <button type="submit" class="btn-primary"><i class="fa-solid fa-bolt"></i> Jalankan</button>
        <a href="?tool=ds" class="btn-ghost"><i class="fa-solid fa-rotate-left"></i> Reset</a>
      </div>
    </form>

    <?php if ($error): ?><div class="err-box"><i class="fa-solid fa-triangle-exclamation"></i><?= htmlspecialchars($error) ?></div><?php endif; ?>

    <?php if ($result && $result['type']==='ds'): ?>
    <div style="margin-top:1.25rem;">

      <?php if ($result['aksi']==='generate'): ?>
      <div class="glass-result" style="padding:1.25rem;">
        <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:rgba(160,130,220,.6);margin-bottom:1rem;">
          <i class="fa-solid fa-key" style="color:#ec4899;margin-right:4px;"></i> Keypair RSA Berhasil Digenerate
        </div>
        <div style="margin-bottom:.85rem;">
          <div style="display:flex;justify-content:space-between;margin-bottom:5px;">
            <span style="font-size:12px;font-weight:700;color:#fca5a5;"><i class="fa-solid fa-lock" style="margin-right:4px;"></i>Private Key</span>
            <button onclick="copyText('ds-priv')" class="copy-btn"><i class="fa-regular fa-copy"></i> Copy</button>
          </div>
          <pre id="ds-priv" class="output-pre" style="color:#fca5a5;max-height:130px;"><?= htmlspecialchars($result['private']) ?></pre>
        </div>
        <div>
          <div style="display:flex;justify-content:space-between;margin-bottom:5px;">
            <span style="font-size:12px;font-weight:700;color:#86efac;"><i class="fa-solid fa-unlock" style="margin-right:4px;"></i>Public Key</span>
            <button onclick="copyText('ds-pub')" class="copy-btn"><i class="fa-regular fa-copy"></i> Copy</button>
          </div>
          <pre id="ds-pub" class="output-pre" style="color:#86efac;max-height:130px;"><?= htmlspecialchars($result['public']) ?></pre>
        </div>
      </div>

      <?php elseif ($result['aksi']==='sign'): ?>
      <div class="glass-result" style="padding:1.25rem;">
        <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:#86efac;margin-bottom:.75rem;">
          <i class="fa-solid fa-pen-nib" style="margin-right:4px;"></i> Dokumen Berhasil Ditandatangani
        </div>
        <div style="margin-bottom:.85rem;">
          <p style="font-size:11px;color:rgba(130,100,200,.55);margin-bottom:4px;">SHA-256 dokumen:</p>
          <code style="display:block;font-family:'JetBrains Mono',monospace;font-size:11px;word-break:break-all;padding:.6rem .8rem;border-radius:8px;color:#a78bfa;background:rgba(8,4,24,.6);border:1px solid rgba(120,80,200,.15);"><?= $result['hash'] ?></code>
        </div>
        <div>
          <div style="display:flex;justify-content:space-between;margin-bottom:5px;">
            <p style="font-size:11px;color:rgba(130,100,200,.55);">Tanda Tangan Digital (Base64):</p>
            <button onclick="copyText('ds-sig-out')" class="copy-btn"><i class="fa-regular fa-copy"></i> Copy Signature</button>
          </div>
          <pre id="ds-sig-out" class="output-pre" style="color:#86efac;max-height:120px;"><?= htmlspecialchars($result['signature']) ?></pre>
        </div>
      </div>

      <?php elseif ($result['aksi']==='verify'): ?>
      <div class="<?= $result['status']==='valid'?'glass-success':($result['status']==='invalid'?'glass-invalid':'glass-warning') ?> scan-wrap" style="padding:1.25rem;">
        <?php if ($result['status']==='valid'): ?><div class="scan-line"></div><?php endif; ?>
        <div style="position:relative;display:flex;align-items:center;gap:14px;margin-bottom:.85rem;">
          <div style="width:42px;height:42px;border-radius:50%;flex-shrink:0;display:flex;align-items:center;justify-content:center;background:<?= $result['status']==='valid'?'rgba(74,222,128,.2)':'rgba(248,113,113,.2)' ?>;border:1px solid <?= $result['status']==='valid'?'rgba(74,222,128,.4)':'rgba(248,113,113,.4)' ?>">
            <i class="fa-solid <?= $result['status']==='valid'?'fa-circle-check text-green-400':'fa-circle-xmark text-red-400' ?>" style="font-size:18px;color:<?= $result['status']==='valid'?'#4ade80':'#f87171' ?>;"></i>
          </div>
          <div>
            <p style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:<?= $result['status']==='valid'?'#4ade80':'#f87171' ?>;">
              <?= $result['status']==='valid'?'Verifikasi Berhasil':'Verifikasi Gagal' ?>
            </p>
            <p style="font-size:13px;font-weight:600;color:<?= $result['status']==='valid'?'#86efac':'#fca5a5' ?>;margin-top:2px;"><?= htmlspecialchars($result['msg']) ?></p>
          </div>
        </div>
        <p style="font-size:11px;color:rgba(130,100,200,.55);margin-bottom:4px;">SHA-256 dokumen yang diterima:</p>
        <code style="display:block;font-family:'JetBrains Mono',monospace;font-size:11px;word-break:break-all;padding:.6rem .8rem;border-radius:8px;color:#a78bfa;background:rgba(8,4,24,.5);border:1px solid rgba(120,80,200,.15);"><?= $result['hash'] ?></code>
      </div>

      <?php elseif ($result['aksi']==='hash'): ?>
      <div class="glass-result" style="padding:1.25rem;">
        <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:rgba(160,130,220,.6);margin-bottom:1rem;">
          <i class="fa-solid fa-hashtag" style="color:#10b981;margin-right:4px;"></i> Hasil Hash
        </div>
        <?php foreach (['md5'=>['MD5','#ef4444'],'sha256'=>['SHA-256','#10b981'],'sha512'=>['SHA-512','#14b8a6']] as $algo=>[$lbl,$c]): ?>
        <div class="hash-entry">
          <div style="display:flex;align-items:center;justify-content:space-between;">
            <span style="font-size:12px;font-weight:700;color:<?= $c ?>;"><?= $lbl ?></span>
            <button onclick="copyText('ds-h-<?= $algo ?>')" class="copy-btn"><i class="fa-regular fa-copy"></i></button>
          </div>
          <div class="hash-bar" style="background:linear-gradient(90deg,<?= $c ?>,transparent);"></div>
          <code id="ds-h-<?= $algo ?>" style="display:block;font-family:'JetBrains Mono',monospace;font-size:10px;word-break:break-all;padding:.5rem .75rem;border-radius:8px;color:rgba(200,175,240,.8);background:rgba(8,4,24,.6);border:1px solid rgba(120,80,200,.15);"><?= hash($algo, $dFd['dok']) ?></code>
        </div>
        <?php endforeach; ?>
      </div>
      <?php endif; ?>

    </div>
    <?php endif; ?>
  </div>

  <!-- Rumus -->
  <div class="glass-sm" style="padding:1.1rem 1.25rem;">
    <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:rgba(130,100,200,.45);margin-bottom:.6rem;">Konsep RSA Signature</div>
    <div style="font-family:'JetBrains Mono',monospace;font-size:12px;line-height:2;color:rgba(180,155,230,.7);">
      Sign:   <span style="color:#f9a8d4;font-weight:600;">S = H<sup>d</sup> mod n</span>&nbsp;&nbsp;(d = Private Key)<br/>
      Verify: <span style="color:#86efac;font-weight:600;">H = S<sup>e</sup> mod n</span>&nbsp;&nbsp;(e = Public Key)<br/>
      Hash:   <span style="color:#a5f3fc;font-weight:600;">H = SHA256(Dokumen)</span>
    </div>
  </div>
  </div>

  <?php endif; ?>

  <!-- Footer -->
  <div style="margin-top:2rem;padding:1rem 0;border-top:1px solid rgba(120,80,200,.12);display:flex;align-items:center;justify-content:space-between;font-size:11px;color:rgba(130,100,200,.4);">
    <span>Kriptografi & Keamanan Komputer · PjBL OBE · 2025</span>
    <span class="badge badge-violet" style="font-size:10px;">PHP OpenSSL · RSA 2048-bit</span>
  </div>

  </div><!-- page-content -->
</div><!-- main -->
</div><!-- layout -->

<script>
// ── Sidebar Mobile Toggle ──────────────────────
function toggleSidebar() {
  document.getElementById('sidebar').classList.toggle('open');
}

// ── XOR Mode Switch ───────────────────────────
function xorModeSwitch(mode) {
  const lbl = document.getElementById('xor-input-label');
  if (lbl) lbl.textContent = mode === 'encrypt' ? 'Teks Asli (Plaintext)' : 'Ciphertext (Hex, spasi antar byte)';
}

// ── RSA Tab ───────────────────────────────────
function rsaTab(tab) {
  document.getElementById('rsa-aksi').value = tab;
  ['generate','enkripsi','dekripsi'].forEach(t => {
    const b = document.getElementById('rsa-tab-' + t);
    if (b) { b.classList.toggle('active', t === tab); }
  });
  const show = tab !== 'generate';
  document.getElementById('rsa-hint').style.display       = show ? 'none' : '';
  document.getElementById('rsa-pesan-wrap').style.display = show ? '' : 'none';
  document.getElementById('rsa-kunci-wrap').style.display = show ? '' : 'none';

  const kl = document.getElementById('rsa-kunci-label');
  if (kl) kl.innerHTML = tab === 'dekripsi'
    ? '<i class="fa-solid fa-lock" style="opacity:.6;margin-right:4px;"></i> Private Key (PEM)'
    : '<i class="fa-solid fa-unlock" style="opacity:.6;margin-right:4px;"></i> Public Key (PEM)';
  const pl = document.getElementById('rsa-pesan-label');
  if (pl) pl.innerHTML = tab === 'dekripsi'
    ? '<i class="fa-solid fa-align-left" style="opacity:.6;margin-right:4px;"></i> Ciphertext (Base64)'
    : '<i class="fa-solid fa-align-left" style="opacity:.6;margin-right:4px;"></i> Pesan / Plaintext';
}

// ── DS Tab ────────────────────────────────────
function dsTab(tab) {
  document.getElementById('ds-aksi').value = tab;
  ['generate','sign','verify','hash'].forEach(t => {
    const b = document.getElementById('ds-tab-' + t);
    if (b) b.classList.toggle('active', t === tab);
  });
  const showDok  = ['sign','verify','hash'].includes(tab);
  const showSig  = tab === 'verify';
  const showKey  = ['sign','verify'].includes(tab);
  const showHint = tab === 'generate';

  document.getElementById('ds-dok-wrap').style.display      = showDok  ? '' : 'none';
  document.getElementById('ds-sig-wrap').style.display      = showSig  ? '' : 'none';
  document.getElementById('ds-kunci-wrap').style.display    = showKey  ? '' : 'none';
  document.getElementById('ds-generate-hint').style.display = showHint ? '' : 'none';

  const kl = document.getElementById('ds-kunci-label');
  if (kl) kl.innerHTML = tab === 'verify'
    ? '<i class="fa-solid fa-unlock" style="opacity:.6;margin-right:4px;"></i> Public Key (PEM)'
    : '<i class="fa-solid fa-lock" style="opacity:.6;margin-right:4px;"></i> Private Key (PEM)';
}

// ── Toast ─────────────────────────────────────
function showToast(msg, err=false) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = err ? 'show error-toast' : 'show';
  clearTimeout(t._t);
  t._t = setTimeout(() => t.className = err ? 'error-toast' : '', 2200);
}

// ── Copy ──────────────────────────────────────
function copyText(id) {
  const el = document.getElementById(id);
  if (!el) return;
  const text = (el.tagName==='TEXTAREA'||el.tagName==='INPUT') ? el.value : el.textContent.trim();
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(()=>showToast('✓ Tersalin!')).catch(()=>fallback(text));
  } else { fallback(text); }
}
function fallback(text) {
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.style.cssText = 'position:fixed;top:-9999px;left:-9999px;opacity:0;';
  document.body.appendChild(ta);
  ta.focus(); ta.select(); ta.setSelectionRange(0,99999);
  let ok = false;
  try { ok = document.execCommand('copy'); } catch(e){}
  document.body.removeChild(ta);
  ok ? showToast('✓ Tersalin!') : showToast('Ctrl+A lalu Ctrl+C manual.',true);
}
</script>
</body>
</html>