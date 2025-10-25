<?php
/**
 * Domain Intelligence API v2 — domains.php (with debug mode)
 * PHP 8.1
 *
 * POST JSON:
 * {
 *   "domains": ["example.com","sub.example.com","https://example.org/path"],
 *   "options": ["Reg_date","IP","IP_org","NS","MX","MX_org","IsSusp","Regist","HasContent"],
 *   "debug": true                      // optional
 * }
 *
 * Or quick GET:
 *   /api/domains.php?domain=example.com&__debug=1
 *
 * Response:
 * {
 *   "ok": true,
 *   "query_ms": 123,
 *   "items": [
 *     { "domain":"...", "fields": { ...selected... }, "debug": { ...optional... } }
 *   ]
 * }
 */

/////////////////////////////
// CORS & error handling
/////////////////////////////
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(204); exit; }

error_reporting(E_ALL);
ini_set('display_errors', '0');

set_error_handler(function ($severity, $message, $file, $line) {
  throw new ErrorException($message, 0, $severity, $file, $line);
});
register_shutdown_function(function () {
  $e = error_get_last();
  if ($e && in_array($e['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR], true)) {
    http_response_code(500);
    echo json_encode([
      'ok'    => false,
      'error' => 'fatal',
      'detail'=> $e['message'],
      'file'  => basename($e['file']),
      'line'  => $e['line'],
    ], JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);
  }
});

$started = microtime(true);

/////////////////////////////
// Config
/////////////////////////////
const DIG_BIN   = 'dig';
const WHOIS_BIN = 'whois';
const DIG_TIMEOUT_SEC   = 4;
const WHOIS_TIMEOUT_SEC = 8;
const WHOIS_MAX_BYTES   = 200000;

const DEBUG_RAW_LIMIT   = 4000; // limit raw text in debug payload

const WHOIS_TLD_MAP = [
  'gg' => 'whois.gg',
  'je' => 'whois.je',
  'me' => 'whois.nic.me',
  'io' => 'whois.nic.io',
  'es'   => 'whois.nic.es',
  'info' => 'whois.afilias.net',
];

const WHOIS_SLD_MAP = [
  'jp.net' => 'whois.centralnic.com',
  // (optional) other CentralNic SLDs you care about:
  'uk.com' => 'whois.centralnic.com',
  'us.com' => 'whois.centralnic.com',
  'gb.net' => 'whois.centralnic.com',
  'de.com' => 'whois.centralnic.com',
  'eu.com' => 'whois.centralnic.com',
  'ae.org' => 'whois.centralnic.com',
];

$GLOBALS['WHOIS_TRACE'] = [];
$GLOBALS['RDAP_LAST']   = null;


/////////////////////////////
// Helpers: IO/JSON/IDN/date
/////////////////////////////
function body_json(): array {
  $raw = file_get_contents('php://input');
  if (!$raw) return [];
  $data = json_decode($raw, true);
  return is_array($data) ? $data : [];
}
function clip_str(string $s, int $n = DEBUG_RAW_LIMIT): string {
  return (strlen($s) > $n) ? (substr($s, 0, $n).'…') : $s;
}
function idn_to_ascii_safe(string $host): string {
  if (function_exists('idn_to_ascii')) {
    $ascii = @idn_to_ascii($host, IDNA_DEFAULT);
    if ($ascii !== false) return $ascii;
    if (defined('INTL_IDNA_VARIANT_UTS46')) {
      $ascii = @idn_to_ascii($host, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
      if ($ascii !== false) return $ascii;
    }
  }
  return $host;
}
function normalize_domain(string $input): ?string {
  $s = trim(strtolower($input));
  if (strpos($s, '://') !== false) {
    $p = parse_url($s);
    $s = $p['host'] ?? $s;
  }
  $s = rtrim($s, '.');
  $s = preg_split('~[\/\s?#]~', $s, 2)[0] ?? $s;
  $s = idn_to_ascii_safe($s);
  if (!preg_match('~^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$~i', $s)) return null;
  return $s;
}
function is_full_url(string $s): bool {
  return (bool) preg_match('~^[a-z][a-z0-9+.-]*://~i', $s);
}
function to_us_date(string $isoOrAny = null): string {
  if (!$isoOrAny) return '';
  if (preg_match('~^(\d{4})-(\d{2})-(\d{2})~', $isoOrAny, $m)) {
    return intval($m[2]).'/'.intval($m[3]).'/'.$m[1]; // M/D/YYYY
  }
  $d = date_create($isoOrAny);
  return $d ? (intval($d->format('n')).'/'.intval($d->format('j')).'/'.$d->format('Y')) : '';
}

/////////////////////////////
// Shell + DNS helpers
/////////////////////////////
function is_proc_open_enabled(): bool {
  if (!function_exists('proc_open')) return false;
  $disabled = strtolower((string) ini_get('disable_functions'));
  return (strpos($disabled, 'proc_open') === false);
}
function run_cmd(string $cmd, int $timeoutSec, int $maxBytes = 1000000): array {
  if (!is_proc_open_enabled()) return ['out'=>'', 'err'=>'proc_open disabled', 'exit'=>1];
  $desc = [0=>['pipe','r'], 1=>['pipe','w'], 2=>['pipe','w']];
  $proc = proc_open($cmd, $desc, $pipes, null, null, ['bypass_shell'=>true]);
  if (!is_resource($proc)) return ['out'=>'', 'err'=>'failed to start', 'exit'=>1];
  foreach ([0,1,2] as $i) if (isset($pipes[$i]) && is_resource($pipes[$i])) stream_set_blocking($pipes[$i], false);
  if (isset($pipes[0]) && is_resource($pipes[0])) { fclose($pipes[0]); unset($pipes[0]); }
  $out=''; $err=''; $start=microtime(true);
  while (true) {
    if (isset($pipes[1]) && is_resource($pipes[1])) { $c = stream_get_contents($pipes[1]); if ($c!==false) $out.=$c; }
    if (isset($pipes[2]) && is_resource($pipes[2])) { $c = stream_get_contents($pipes[2]); if ($c!==false) $err.=$c; }
    if (strlen($out)+strlen($err) > $maxBytes) break;
    $st = proc_get_status($proc); if (!$st['running']) break;
    if ((microtime(true)-$start) > $timeoutSec) { proc_terminate($proc, 9); $err.="\n[TIMEOUT {$timeoutSec}s]"; break; }
    usleep(30000);
  }
  foreach ($pipes as $p) if (is_resource($p)) fclose($p);
  $exit = proc_close($proc);
  return ['out'=>$out,'err'=>$err,'exit'=>$exit];
}
function safe_dns_get_record(string $host, int $type): array {
  try { $res = @dns_get_record($host, $type); return is_array($res) ? $res : []; }
  catch (Throwable $e) { return []; }
}
function dig_short(string $qname, string $type): array {
  if (is_proc_open_enabled()) {
    $cmd = sprintf('%s +short %s %s +time=%d +tries=1', DIG_BIN, escapeshellarg($type), escapeshellarg($qname), DIG_TIMEOUT_SEC);
    $res = run_cmd($cmd, DIG_TIMEOUT_SEC);
    $out = trim($res['out']);
    if ($out !== '') return array_values(array_filter(array_map('trim', explode("\n", $out))));
  }
  // Fallback to PHP DNS
  $vals = [];
  switch (strtoupper($type)) {
    case 'A':
      $recs = safe_dns_get_record($qname, DNS_A);
      foreach ($recs as $r) if (!empty($r['ip'])) $vals[] = $r['ip'];
      break;
    case 'NS':
      $recs = safe_dns_get_record($qname, DNS_NS);
      foreach ($recs as $r) if (!empty($r['target'])) $vals[] = rtrim($r['target'],'.');
      break;
    case 'CNAME':
      $recs = safe_dns_get_record($qname, DNS_CNAME);
      foreach ($recs as $r) if (!empty($r['target'])) $vals[] = rtrim($r['target'],'.');
      break;
  }
  return array_values(array_unique($vals));
}
function dig_a(string $host): array {
  $ips = dig_short($host, 'A');
  if (!$ips) {
    $c = dig_short($host, 'CNAME');
    if (!empty($c[0])) $ips = dig_short(rtrim($c[0],'.'), 'A');
  }
  $out = [];
  foreach ($ips as $ip) if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) $out[] = $ip;
  return array_values(array_unique($out));
}
function dig_ns_exact(string $name): array {
  $rows = dig_short($name, 'NS');
  $out = []; foreach ($rows as $r) $out[] = rtrim($r,'.');
  return array_values(array_unique($out));
}
/** NS "nearest": try exact name, else walk up labels until found */
function dig_ns_nearest(string $name): array {
  $test = $name;
  while (true) {
    $ns = dig_ns_exact($test);
    if (!empty($ns)) return $ns;
    $dot = strpos($test, '.');
    if ($dot === false) break;
    $test = substr($test, $dot + 1);
  }
  return [];
}
function dig_mx(string $domain): array {
  $mx = [];
  if (is_proc_open_enabled()) {
    $cmd = sprintf('%s +short MX %s +time=%d +tries=1', DIG_BIN, escapeshellarg($domain), DIG_TIMEOUT_SEC);
    $res = run_cmd($cmd, DIG_TIMEOUT_SEC);
    $lines = array_values(array_filter(array_map('trim', explode("\n", $res['out']))));
    foreach ($lines as $line) {
      if (preg_match('~^(\d+)\s+([\w\.-]+)\.?$~', $line, $m)) {
        $mx[] = ['priority'=>(int)$m[1], 'host'=>rtrim($m[2],'.')];
      }
    }
  }
  if (!$mx) {
    $recs = safe_dns_get_record($domain, DNS_MX);
    foreach ($recs as $r) if (!empty($r['target'])) {
      $mx[] = ['priority'=> (int)($r['pri'] ?? 0), 'host'=> rtrim($r['target'],'.')];
    }
  }
  foreach ($mx as &$rec) { $rec['ips'] = dig_a($rec['host']); }
  unset($rec);
  usort($mx, fn($a,$b)=>$a['priority']<=>$b['priority']);
  return $mx;
}

/////////////////////////////
// WHOIS / RDAP helpers
/////////////////////////////

function whois_is_no_match(string $txt): bool {
  if ($txt === '') return false;
  return (bool)preg_match(
    '~(0 objects|No entries found|No existen entradas|no match|not found|no data found|no object found|the queried object does not exist|available for registration)~i',
    $txt
  );
}

function whois_suffix_server(string $domain): ?string {
  $labels = explode('.', strtolower($domain));
  for ($i = 0; $i < count($labels)-1; $i++) {
    $suffix = implode('.', array_slice($labels, $i)); // e.g. jp.net, net
    if (isset(WHOIS_SLD_MAP[$suffix])) return WHOIS_SLD_MAP[$suffix];
  }
  return null;
}

function whois_no_match_line(string $txt): ?string {
  if ($txt === '') return null;
  // Check line-by-line to avoid false positives in disclaimers
  $lines = preg_split('~\R~', $txt) ?: [];
  foreach ($lines as $ln) {
    $line = trim($ln);
    if ($line === '') continue;

    // Common registry messages
    $patterns = [
      '~\bno\s+match\s+for\b~i',          // .com, .net, many others
      '~\bnot\s+found\b~i',               // “NOT FOUND”
      '~\bno\s+entries?\s+found\b~i',     // “No entries found”
      '~\bno\s+data\s+found\b~i',
      '~\bno\s+object\s+found\b~i',
      '~\bno\s+such\s+domain\b~i',
      '~\bthe\s+queried\s+object\s+does\s+not\s+exist\b~i',
      '~\bstatus:\s*available\b~i',       // some registries say “Status: available”
      '~\bavailable\s+for\s+registration\b~i',
      '~\bhas\s+not\s+been\s+registered\b~i',

      // NEW: ESNIC / .es variants
      '~\b0\s+objects\b~i',                 // "% This query returned 0 objects."
      '~\bno\s+existen\s+entradas\b~i',     // Spanish: "No existen entradas ..."
    ];
    foreach ($patterns as $re) {
      if (preg_match($re, $line)) {
        return $line; // return the exact matching line (e.g., "No match for "EXAMPLE.TLD"")
      }
    }
  }
  return null;
}

function whois_tld_referral(string $tld): ?string {
  // Query IANA for this TLD’s WHOIS record
  $timeout = defined('WHOIS_TIMEOUT_SEC') ? WHOIS_TIMEOUT_SEC : 5;
  $txt = whois_port43('whois.iana.org', $tld, $timeout);
  if ($txt === '') return null;

  // Clean and normalize
  $txt = trim(preg_replace('/[^\P{C}\n]+/u', '', $txt)); // remove control chars
  $txt = str_replace("\r", '', $txt);

  // Match "whois:" or "refer:" lines that contain a proper hostname
  if (preg_match(
    '~^\s*(?:whois|refer)\s*:\s*([a-z0-9.-]+\.[a-z]{2,})\s*$~im',
    $txt,
    $m
  )) {
    $ref = strtolower(trim($m[1]));

    // Basic sanity: must contain at least one dot and no spaces
    if (preg_match('/^[a-z0-9.-]+\.[a-z]{2,}$/i', $ref)) {
      return $ref;
    }
  }

  // Nothing valid found
  return null;
}

function whois_text_domain(string $domain): string {
  $trace =& $GLOBALS['WHOIS_TRACE'];

  // helper
  $push = function(string $method, ?string $server, bool $ok, int $bytes, string $note = '') use (&$trace) {
    $trace[] = [
      'method' => $method,
      'server' => $server,
      'ok'     => $ok,
      'bytes'  => $bytes,
      'note'   => $note,
    ];
  };

  // 1) Try local whois binary first
  if (is_proc_open_enabled()) {
    $cmd = sprintf('%s -H %s', WHOIS_BIN, escapeshellarg($domain));
    $res = run_cmd($cmd, WHOIS_TIMEOUT_SEC, WHOIS_MAX_BYTES);
    $txt = trim(($res['out'] ?: $res['err']) ?? '');
    $bad = ($res['exit'] !== 0) || ($txt === '') || stripos($txt, 'not found') !== false;
    $push('whois-bin', null, !$bad, strlen($txt));
    if (!$bad) return substr($txt, 0, WHOIS_MAX_BYTES);
  }

  // 2) SLD-specific server (multi-label suffixes like jp.net -> CentralNic)
  if ($srv = whois_suffix_server($domain)) {
    $txt = whois_port43($srv, $domain);
    $ok  = trim($txt) !== '';
    $push('port43-suffix', $srv, $ok, strlen($txt));
    if ($ok) return substr($txt, 0, WHOIS_MAX_BYTES);
  }

  // 3) Generic IANA referral (works for many TLDs if not in the map)
  $tld = strtolower(substr($domain, strrpos($domain, '.') + 1));
  if ($slv = whois_suffix_server($domain)) {
    // already tried above; nothing to do
  }
  if ($srv = whois_tld_referral($tld)) {
    // sanity: require a plausible hostname
    if (preg_match('~^[a-z0-9.-]+\.[a-z]{2,}$~i', $srv)) {
      $txt = whois_port43($srv, $domain);
      $ok  = trim($txt) !== '';
      $push('port43-referral', $srv, $ok, strlen($txt));
      if ($ok) return substr($txt, 0, WHOIS_MAX_BYTES);
    } else {
      $push('port43-referral', $srv, false, 0, 'invalid-referral');
    }
  } else {
    $push('port43-referral', null, false, 0, 'no-referral');
  }

  // 4) TLD hard map fallback (if you use one)
  if (defined('WHOIS_TLD_MAP') && isset(WHOIS_TLD_MAP[$tld])) {
    $srv = WHOIS_TLD_MAP[$tld];
    $txt = whois_port43($srv, $domain);
    $ok  = trim($txt) !== '';
    $push('port43-map', $srv, $ok, strlen($txt));
    if ($ok) return substr($txt, 0, WHOIS_MAX_BYTES);
  }

  // Nothing worked
  $push('port43-none', null, false, 0, 'all-attempts-failed');
  return '';
}

function whois_text_ip(string $ip): string {
  if (is_proc_open_enabled()) {
    $cmd = sprintf('%s %s', WHOIS_BIN, escapeshellarg($ip));
    $res = run_cmd($cmd, WHOIS_TIMEOUT_SEC, WHOIS_MAX_BYTES);
    $txt = $res['out'] ?: $res['err'];
    return substr($txt, 0, WHOIS_MAX_BYTES);
  }
  $rd = rdap_ip($ip);
  return $rd ? rdap_ip_textify($rd) : '';
}
function normalize_date(string $s): ?string {
  $candidates = is_array($s) ? $s : [$s];
  foreach ($candidates as $one) {
    $one = trim((string)$one);
    if ($one === '') continue;

    // remove ordinal suffixes: 1st/2nd/3rd/4th -> 1/2/3/4
    $one = preg_replace('~\b(\d{1,2})(st|nd|rd|th)\b~i', '$1', $one);
    // drop the word "at" used in some WHOIS blocks
    $one = preg_replace('~\bat\b~i', ' ', $one);
    // collapse spaces
    $one = preg_replace('~\s+~', ' ', $one);

    // let PHP parse it now
    $dt = date_create($one);
    if ($dt) return $dt->format(DATE_ATOM);
  }
  return null;
}
function first_nonempty(array $bag, array $keys): ?string {
  foreach ($keys as $k) { $kk = strtolower($k); if (!empty($bag[$kk][0])) return $bag[$kk][0]; }
  return null;
}

/** Clean & de-dup status strings; strip trailing ICANN URLs */
function clean_statuses(array $arr): array {
  $out = [];
  foreach ($arr as $s) {
    $s = preg_replace('~\s+https?://\S+$~', '', (string)$s);
    $s = strtolower(preg_replace('~\s+~', ' ', trim($s)));
    if ($s !== '') $out[] = $s;
  }
  $seen=[]; $res=[];
  foreach ($out as $x) if (!isset($seen[$x])) { $seen[$x]=1; $res[]=$x; }
  return $res;
}
/** Fallback: scan raw WHOIS text for status lines if KV parse missed them */
function extract_statuses_from_raw(string $txt): array {
  $out = [];
  $lines = preg_split('~\R~', $txt) ?: [];
  $n = count($lines);
  for ($i = 0; $i < $n; $i++) {
    $ln = rtrim($lines[$i], "\r\n");
    if (preg_match('~^\s*(?:domain\s+)?status:\s*(.*)$~i', $ln, $m)) {
      $first = trim($m[1]);
      if ($first !== '') {
        $out[] = $first;
      } else {
        // Block style: consume indented lines
        $j = $i + 1;
        while ($j < $n) {
          $next = rtrim($lines[$j], "\r\n");
          if (preg_match('~^\s+\S~', $next)) {
            $out[] = trim($next);
            $j++;
            continue;
          }
          break;
        }
        $i = $j - 1;
      }
    }
  }
  return clean_statuses($out);
}

/** Parse domain WHOIS into registrar, creation, statuses, nameservers */
function parse_domain_whois(string $txt): array {
  $lines = preg_split('~\R~', $txt) ?: [];
  $kv = [];
  $n = count($lines);

  for ($i = 0; $i < $n; $i++) {
    $ln = rtrim($lines[$i], "\r\n");
    if (!preg_match('~^\s*([^:]+?)\s*:\s*(.*)$~', $ln, $m)) continue;

    $key = strtolower(trim($m[1]));
    $val = trim($m[2]);

    // If the value is blank here, collect following indented lines as the value block
    if ($val === '') {
      $block = [];
      $j = $i + 1;
      while ($j < $n) {
        $next = rtrim($lines[$j], "\r\n");
        if (preg_match('~^\s+\S~', $next)) {          // indented line => continuation
          $block[] = trim($next);
          $j++;
          continue;
        }
        break; // next header or blank/non-indented line
      }
      $i = $j - 1;
      if (!empty($block)) {
        // Some keys are list-like; store each line as a separate value
        foreach ($block as $b) {
          $kv[$key][] = $b;
        }
        continue;
      }
    }

    // Single-line key:value
    $kv[$key][] = $val;
  }

  // Registrar (first non-empty of common variants)
  $registrar = ($kv['registrar'][0] ?? null) ?: ($kv['sponsoring registrar'][0] ?? null)
             ?: ($kv['registrar name'][0] ?? null) ?: ($kv['registrar organization'][0] ?? null);

  // Creation date — try common keys, or parse from “Relevant dates:” block (e.g., .gg)
  $created = null;
  foreach (['creation date','registered on','created','created on','domain registration date','registration time'] as $k) {
    if (!empty($kv[$k][0])) { $created = $kv[$k][0]; break; }
  }
  if (!$created && !empty($kv['relevant dates'])) {
    // Look for a line like: "Registered on 12th March 2023 at 15:05:34.456"
    foreach ($kv['relevant dates'] as $rd) {
      if (preg_match('~registered on\s+(.+)$~i', $rd, $m)) { $created = $m[1]; break; }
    }
  }

  // Statuses: from “domain status” or “status” (now populated even if block-style)
  $statuses = $kv['domain status'] ?? $kv['status'] ?? [];

  // Nameservers: handle both “name server” + “name servers” + “nserver”
  $nss = [];
  foreach (['name server','name servers','nserver'] as $k) {
    if (!empty($kv[$k])) {
      foreach ($kv[$k] as $ns) $nss[] = rtrim(strtolower($ns), '.');
    }
  }
  $nss = array_values(array_unique(array_filter($nss)));

  // Normalize statuses (strip trailing URLs, lowercase, collapse spaces)
  $statuses = clean_statuses($statuses);

  return [
    'registrar'     => $registrar ?: '',
    'creation_date' => $created ? normalize_date($created) : '',
    'statuses'      => $statuses,
    'nameservers'   => $nss,
  ];
}

/** Port-43 client */
function whois_port43(string $server, string $query, int $timeout = 6): string {
  $errno = 0; $errstr = '';
  $fp = @fsockopen($server, 43, $errno, $errstr, $timeout);
  if (!$fp) return '';
  stream_set_timeout($fp, $timeout);
  fwrite($fp, $query . "\r\n");
  $out = '';
  while (!feof($fp)) { $out .= fgets($fp, 8192) ?: ''; }
  fclose($fp);
  return $out;
}

/** RDAP */
function http_get_json(string $url, int $timeout = 8): ?array {
  $ua = 'DomainInfo/2.0 (+https://example.org)';
  if (function_exists('curl_init')) {
    $ch = curl_init($url);
    curl_setopt_array($ch, [
      CURLOPT_RETURNTRANSFER => true,
      CURLOPT_FOLLOWLOCATION => true,
      CURLOPT_USERAGENT      => $ua,
      CURLOPT_CONNECTTIMEOUT => $timeout,
      CURLOPT_TIMEOUT        => $timeout,
      CURLOPT_SSL_VERIFYPEER => true,
      CURLOPT_SSL_VERIFYHOST => 2,
      CURLOPT_HTTPHEADER     => ['Accept: application/rdap+json, application/json;q=0.9, */*;q=0.8'],
    ]);
    $body = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    if ($body !== false && $code >= 200 && $code < 300) {
      $j = json_decode($body, true);
      if (is_array($j)) return $j;
    }
    return null;
  }
  $ctx = stream_context_create([
    'http' => [
      'method'  => 'GET',
      'header'  => "User-Agent: $ua\r\nAccept: application/rdap+json, application/json\r\n",
      'timeout' => $timeout,
    ],
    'ssl' => ['verify_peer'=>true,'verify_peer_name'=>true],
  ]);
  $body = @file_get_contents($url, false, $ctx);
  if ($body !== false) {
    $j = json_decode($body, true);
    return is_array($j) ? $j : null;
  }
  return null;
}
function rdap_domain(string $domain): ?array { return http_get_json('https://rdap.org/domain/'.rawurlencode($domain)); }
function rdap_ip(string $ip): ?array { return http_get_json('https://rdap.org/ip/'.rawurlencode($ip)); }

function rdap_domain_textify(array $j): string {
  $lines = [];
  if (!empty($j['ldhName'])) $lines[] = "Domain: ".$j['ldhName'];
  if (!empty($j['status'])) foreach ($j['status'] as $s) $lines[] = "Status: ".$s;
  if (!empty($j['events'])) foreach ($j['events'] as $e) if (!empty($e['eventAction']) && !empty($e['eventDate'])) $lines[] = ucfirst($e['eventAction']).": ".$e['eventDate'];
  if (!empty($j['nameservers'])) foreach ($j['nameservers'] as $ns) if (!empty($ns['ldhName'])) $lines[] = "Name Server: ".$ns['ldhName'];
  return implode("\n", $lines);
}
function rdap_ip_textify(array $j): string {
  $lines = [];
  if (!empty($j['name'])) $lines[] = "NetName: ".$j['name'];
  if (!empty($j['entities'])) {
    foreach ($j['entities'] as $ent) {
      $role = implode(',', $ent['roles'] ?? []);
      $name = $ent['vcardArray'][1][1][3] ?? ($ent['fn'] ?? null);
      if ($name) $lines[] = ucfirst($role ?: 'entity').": ".$name;
    }
  }
  return implode("\n", $lines);
}

/** Enrich WHOIS gaps from RDAP */
function enrich_whois_with_rdap_if_missing(array $whois, string $domain): array {
  $needReg  = empty($whois['registrar']);
  $needDate = empty($whois['creation_date']);
  if (!$needReg && !$needDate) return $whois;

  $rd = rdap_domain($domain);
  if (!$rd) return $whois;

  $used = false;

  if ($needDate && !empty($rd['events'])) {
    foreach ($rd['events'] as $e) {
      $act = strtolower((string)($e['eventAction'] ?? ''));
      if (in_array($act, ['registration','registered','create','created'], true) && !empty($e['eventDate'])) {
        $whois['creation_date'] = $e['eventDate'];
        $used = true;
        break;
      }
    }
  }

  if ($needReg && !empty($rd['entities'])) {
    foreach ($rd['entities'] as $ent) {
      $roles = array_map('strtolower', (array)($ent['roles'] ?? []));
      if (in_array('registrar', $roles, true)) {
        $name = null;
        if (!empty($ent['vcardArray'][1])) {
          foreach ($ent['vcardArray['] ?? $ent['vcardArray'][1] as $v) {
            if (($v[0] ?? '') === 'fn' && !empty($v[3])) { $name = $v[3]; break; }
          }
        }
        if (!$name && !empty($ent['fn'])) $name = $ent['fn'];
        if ($name) { $whois['registrar'] = $name; $used = true; break; }
      }
    }
  }

  if ($used) {
    $GLOBALS['RDAP_LAST'] = [
      'used'    => true,
      'excerpt' => rdap_domain_textify($rd),
      'json'    => $rd, // keep full JSON in memory (not printed unless you add it)
    ];
  }

  return $whois;
}

/** Parse org name from classic IP WHOIS text */
if (!function_exists('parse_ip_org')) {
  function parse_ip_org(string $txt): ?string {
    $patterns = [
      '~^OrgName:\s*(.+)$~im',
      '~^org-name:\s*(.+)$~im',
      '~^Org:\s*(.+)$~im',
      '~^owner:\s*(.+)$~im',
      '~^responsible:\s*(.+)$~im',
      '~^organisation:\s*(.+)$~im',
      '~^descr:\s*(.+)$~im',
      '~^netname:\s*(.+)$~im', // fallback
    ];
    foreach ($patterns as $re) if (preg_match($re, $txt, $m)) return trim($m[1]);
    return null;
  }
}
/** Extract org from IP RDAP JSON */
function parse_ip_org_from_rdap(array $j): ?string {
  if (!empty($j['entities'])) {
    foreach ($j['entities'] as $ent) {
      $name = null;
      if (!empty($ent['vcardArray'][1])) {
        foreach ($ent['vcardArray'][1] as $v) if (($v[0] ?? '') === 'fn' && !empty($v[3])) { $name = $v[3]; break; }
      }
      if (!$name && !empty($ent['fn'])) $name = $ent['fn'];
      if ($name) return $name;
    }
  }
  if (!empty($j['name'])) return $j['name'];
  return null;
}

/////////////////////////////
// HTTP probe (HasContent)
/////////////////////////////
function http_fetch_url(string $url, int $timeout = 8): array {
  $ua = 'DomainInfo/2.0 (+https://example.org)';
  if (function_exists('curl_init')) {
    $ch = curl_init($url);
    curl_setopt_array($ch, [
      CURLOPT_RETURNTRANSFER => true,
      CURLOPT_FOLLOWLOCATION => true,
      CURLOPT_MAXREDIRS      => 5,
      CURLOPT_USERAGENT      => $ua,
      CURLOPT_CONNECTTIMEOUT => $timeout,
      CURLOPT_TIMEOUT        => $timeout,
      CURLOPT_SSL_VERIFYPEER => true,
      CURLOPT_SSL_VERIFYHOST => 2,
      CURLOPT_HEADER         => false,
    ]);
    $body = curl_exec($ch);
    $err  = curl_error($ch);
    $info = curl_getinfo($ch);
    curl_close($ch);
    return [
      'ok'         => ($body !== false),
      'status'     => (int)($info['http_code'] ?? 0),
      'final_url'  => (string)($info['url'] ?? $url),
      'ctype'      => (string)($info['content_type'] ?? ''),
      'bytes'      => is_string($body) ? strlen($body) : 0,
      'body'       => is_string($body) ? $body : '',
      'error'      => $err,
    ];
  }
  $ctx = stream_context_create([
    'http' => [
      'method' => 'GET',
      'header' => "User-Agent: $ua\r\n",
      'timeout' => $timeout,
      'follow_location' => 1,
      'max_redirects' => 5,
    ],
    'ssl' => ['verify_peer'=>true, 'verify_peer_name'=>true],
  ]);
  $body = @file_get_contents($url, false, $ctx);
  $meta = $http_response_header ?? [];
  $status = 0; $ctype = '';
  foreach ($meta as $hdr) {
    if (preg_match('~^HTTP/\S+\s+(\d{3})~i', $hdr, $m)) $status = (int)$m[1];
    if (stripos($hdr, 'Content-Type:') === 0) $ctype = trim(substr($hdr, 13));
  }
  return [
    'ok'     => ($body !== false),
    'status' => $status,
    'final_url' => $url,
    'ctype'  => $ctype,
    'bytes'  => is_string($body) ? strlen($body) : 0,
    'body'   => is_string($body) ? $body : '',
    'error'  => $body === false ? 'fetch failed' : '',
  ];
}
function html_visible_text_len(string $html): int {
  $clean = preg_replace('~<!--.*?-->|<script\b[^>]*>.*?</script>|<style\b[^>]*>.*?</style>|<noscript\b[^>]*>.*?</noscript>~is', '', $html);
  $text  = trim(html_entity_decode(strip_tags($clean) ?? '', ENT_QUOTES | ENT_HTML5, 'UTF-8'));
  return function_exists('mb_strlen') ? mb_strlen($text, 'UTF-8') : strlen($text);
}
function http_probe_root_or_url(string $inputHostOrUrl): array {
  if (is_full_url($inputHostOrUrl)) return http_fetch_url($inputHostOrUrl, 8);
  foreach (["https://{$inputHostOrUrl}/", "http://{$inputHostOrUrl}/"] as $url) {
    $r = http_fetch_url($url, 8);
    if ($r['status'] > 0) return $r;
  }
  return ['ok'=>false, 'status'=>0, 'final_url'=>'', 'ctype'=>'', 'bytes'=>0, 'body'=>'', 'error'=>'connect failed'];
}
function http_has_meaningful_content(array $r): bool {
  if (!$r || empty($r['status'])) return false;
  $code = (int)$r['status'];
  if ($code >= 400 || $code === 204) return false;
  $textLen = html_visible_text_len($r['body'] ?? '');
  if ($textLen >= 20) return true;
  if (($r['bytes'] ?? 0) >= 512 && stripos($r['ctype'] ?? '', 'text/') !== false) return true;
  if (stripos($r['ctype'] ?? '', 'text/html') !== false && preg_match('~<title[^>]*>(.*?)</title>~is', $r['body'] ?? '')) return true;
  return false;
}

/////////////////////////////
// Option registry
/////////////////////////////
$OPTION_REGISTRY = [
  // WHOIS-derived
  'Reg_date' => [
    'deps' => ['WHOIS'],
    'present' => function(array $ctx): string {
      return to_us_date($ctx['whois']['creation_date'] ?? '');
    }
  ],
  'IsSusp' => [
    'deps' => ['WHOIS'],
    'present' => function(array $ctx): array {
      $raw = (string)($ctx['whois_raw'] ?? '');
      $st  = clean_statuses($ctx['whois']['statuses'] ?? []);

      // If parsed list is empty but we have raw text, try block-aware fallback
      if (!$st && $raw !== '') {
        $st = extract_statuses_from_raw($raw);
      }

      // If we *still* have no statuses, report that WHOIS/RDAP didn’t provide them
      if (!$st) {
        return ['notFound'];
      }

      // Detect holds (parsed OR raw fallback)
      $rawLower = strtolower($raw);
      $has = function(string $regex) use ($st, $rawLower): bool {
        foreach ($st as $s) if (preg_match($regex, $s)) return true;
        return $rawLower !== '' ? (bool)preg_match($regex, $rawLower) : false;
      };

      $out = [];
      if ($has('~server[\s\-_]*hold~i')) $out[] = 'serverHold';
      if ($has('~client[\s\-_]*hold~i')) $out[] = 'clientHold';

      // de-dup, preserve order
      $seen = []; $res = [];
      foreach ($out as $x) if (!isset($seen[$x])) { $seen[$x]=1; $res[]=$x; }
      return $res; // [] means "statuses present, but no hold flags"
    }
  ],
  'Regist' => [
    'deps' => ['WHOIS'],
    'present' => function(array $ctx): string {
      return $ctx['whois']['registrar'] ?? '';
    }
  ],'NoMatch' => [
      'deps' => ['WHOIS'],
      'present' => function(array $ctx): string {
        // Try parsed WHOIS text first
        $raw = (string)($ctx['whois_raw'] ?? '');
        $line = whois_no_match_line($raw);
        if ($line !== null) return $line;

        // Optional: if you kept RDAP JSON somewhere, you can mark 404 here.
        // Otherwise, just return empty string to mean “not not-found”.
        return '';
      }
    ],

  // DNS & orgs
  'IP' => [
    'deps' => ['A'],
    'present' => function(array $ctx): array {
      return array_values($ctx['a'] ?? []);
    }
  ],
  'IP_org' => [
    'deps' => ['A','IP_ORG'],
    'present' => function(array $ctx): array {
      $orgs = [];
      foreach (($ctx['ip_owner'] ?? []) as $io) if (!empty($io['org'])) $orgs[] = $io['org'];
      return array_values(array_unique($orgs));
    }
  ],
  'NS' => [
    'deps' => ['NS'],
    'present' => function(array $ctx): array {
      return array_values($ctx['ns'] ?? []);
    }
  ],
  'MX' => [
    'deps' => ['MX'],
    'present' => function(array $ctx): array {
      $hosts = [];
      foreach (($ctx['mx'] ?? []) as $m) $hosts[] = $m['host'];
      return array_values(array_unique($hosts));
    }
  ],
  'MX_org' => [
    'deps' => ['MX','IP_ORG'],
    'present' => function(array $ctx): array {
      $out = [];
      foreach (($ctx['mx'] ?? []) as $m) {
        foreach (($m['ip_orgs'] ?? []) as $io) {
          $ip  = $io['ip'] ?? '';
          $org = $io['org'] ?? '';
          if ($ip && $org) $out[] = $ip.' - '.$org;
        }
      }
      // de-dup preserve order
      $seen=[]; $dedup=[];
      foreach ($out as $s) if (!isset($seen[$s])) { $seen[$s]=1; $dedup[]=$s; }
      return $dedup;
    }
  ],

  // HTTP content probe
  'HasContent' => [
    'deps' => ['HTTP'],
    'present' => function(array $ctx): bool {
      return http_has_meaningful_content($ctx['http'] ?? []);
    }
  ],
];

/////////////////////////////
// Request parsing
/////////////////////////////
$input = body_json();

$rawItems = [];
if (!empty($_GET['domain'])) {
  $rawItems = [$_GET['domain']];
} else {
  $rawItems = $input['domains'] ?? [];
}
if (!is_array($rawItems) || !$rawItems) {
  echo json_encode(['ok'=>false,'error'=>'POST {"domains":[...],"options":[...]} or GET ?domain=example.com']);
  exit;
}

$options = $input['options'] ?? [];
if (isset($_GET['options']) && is_string($_GET['options'])) {
  // allow GET testing: ?options=Reg_date,IsSusp
  $options = array_map('trim', explode(',', $_GET['options']));
}
if (!is_array($options) || !$options) {
  echo json_encode(['ok'=>false,'error'=>'Provide "options" array with UI option names.']);
  exit;
}

$debug = !empty($input['debug']) || !empty($_GET['__debug']) || !empty($_GET['debug']);

/////////////////////////////
// Collect deps to compute
/////////////////////////////
$deps = [];
foreach ($options as $opt) {
  if (!isset($OPTION_REGISTRY[$opt])) continue;
  foreach ($OPTION_REGISTRY[$opt]['deps'] as $d) $deps[$d] = true;
}

/////////////////////////////
// Per-item processing
/////////////////////////////
$items = [];
foreach ($rawItems as $rawInput) {
  $rawInput = (string)$rawInput;
  $hostForDns = $rawInput;
  if (is_full_url($rawInput)) {
    $p = parse_url($rawInput);
    $hostForDns = $p['host'] ?? $rawInput;
  }

  $norm = normalize_domain($hostForDns);
  if (!$norm) {
    // invalid host; still allow HasContent on URL
    $ctx = [];
    $dbg = [];
    if (!empty($deps['HTTP'])) {
      $ctx['http'] = http_probe_root_or_url($rawInput);
      if ($debug) $dbg['http'] = [
        'target'    => $rawInput,
        'status'    => (int)($ctx['http']['status'] ?? 0),
        'final_url' => (string)($ctx['http']['final_url'] ?? ''),
        'ctype'     => (string)($ctx['http']['ctype'] ?? ''),
        'bytes'     => (int)($ctx['http']['bytes'] ?? 0),
        'sample'    => clip_str((string)($ctx['http']['body'] ?? ''), 600),
      ];

    }
    $fields = [];
    foreach ($options as $opt) {
      if (!isset($OPTION_REGISTRY[$opt])) continue;
      $val = $OPTION_REGISTRY[$opt]['present']($ctx);
      $fields[$opt] = is_array($val) ? array_values($val) : (is_bool($val) ? $val : (string)$val);
    }
    $item = ['domain'=>$rawInput, 'fields'=>$fields];
    if ($debug && $dbg) $item['debug'] = $dbg;
    $items[] = $item;
    continue;
  }

  $ctx = [];
  $dbg = [];

  if (!empty($deps['A'])) {
    $ctx['a'] = dig_a($norm);
    if ($debug) $dbg['dig_a'] = $ctx['a'];
  }

  if (!empty($deps['NS'])) {
    $ctx['ns'] = dig_ns_nearest($norm);
    if ($debug) $dbg['dig_ns'] = $ctx['ns'];
  }

  if (!empty($deps['MX'])) {
    $ctx['mx'] = dig_mx($norm);
    if ($debug) $dbg['dig_mx'] = $ctx['mx']; // includes hosts + resolved IPs
  }

  if (!empty($deps['WHOIS'])) {
    $wtxt = whois_text_domain($norm);
    $ctx['whois_raw'] = $wtxt;
    if ($debug) {
      $dbg['whois_trace'] = $GLOBALS['WHOIS_TRACE'] ?? [];
      if (!empty($GLOBALS['RDAP_LAST']['used'])) {
        $dbg['rdap_used']    = true;
        $dbg['rdap_excerpt'] = clip_str($GLOBALS['RDAP_LAST']['excerpt'] ?? '');
        // if you also want the full RDAP JSON in debug (careful with size):
        // $dbg['rdap_json'] = $GLOBALS['RDAP_LAST']['json'] ?? null;
      }
    }
    $ctx['whois'] = parse_domain_whois($wtxt);
    $ctx['whois'] = enrich_whois_with_rdap_if_missing($ctx['whois'], $norm);
    if ($debug) $dbg['whois_parsed'] = $ctx['whois'];
  }

  if (!empty($deps['IP_ORG'])) {
    // Owners for A IPs (WHOIS with RDAP fallback)
    $ctx['ip_owner'] = [];
    foreach (($ctx['a'] ?? []) as $ip) {
      $t   = whois_text_ip($ip);
      $org = parse_ip_org($t);
      if (!$org) {
        $rd = rdap_ip($ip);
        if ($rd) $org = parse_ip_org_from_rdap($rd) ?? $org;
      }
      $ctx['ip_owner'][] = ['ip'=>$ip, 'org'=>$org];
      if ($debug) {
        $dbg['whois_ip'][$ip] = clip_str($t, 2000);
      }
    }
    // Owners for MX IPs
    if (!empty($ctx['mx'])) {
      foreach ($ctx['mx'] as &$mx) {
        $mx['ip_orgs'] = [];
        $host = $mx['host'] ?? '';
        foreach (($mx['ips'] ?? []) as $ip) {
          $t   = whois_text_ip($ip);
          $org = parse_ip_org($t);
          if (!$org) {
            $rd = rdap_ip($ip);
            if ($rd) $org = parse_ip_org_from_rdap($rd) ?? $org;
          }
          $mx['ip_orgs'][] = ['ip'=>$ip, 'org'=>$org];
          if ($debug) {
            $dbg['whois_mx_ip'][] = ['host'=>$host, 'ip'=>$ip, 'raw'=>clip_str($t, 2000)];
          }
        }
      }
      unset($mx);
    }
  }

  if (!empty($deps['HTTP'])) {
    $probeTarget = is_full_url($rawInput) ? $rawInput : $norm;
    $ctx['http'] = http_probe_root_or_url($probeTarget);
    if ($debug) {
      $dbg['http'] = [
        'target'    => $probeTarget,
        'status'    => (int)($ctx['http']['status'] ?? 0),
        'final_url' => (string)($ctx['http']['final_url'] ?? ''),
        'ctype'     => (string)($ctx['http']['ctype'] ?? ''),
        'bytes'     => (int)($ctx['http']['bytes'] ?? 0),
        'sample'    => clip_str((string)($ctx['http']['body'] ?? ''), 600),
      ];
    }
  }

  // Present selected fields
  $fields = [];
  foreach ($options as $opt) {
    if (!isset($OPTION_REGISTRY[$opt])) continue;
    $val = $OPTION_REGISTRY[$opt]['present']($ctx);
    if (is_array($val)) $fields[$opt] = array_values($val);
    elseif (is_bool($val)) $fields[$opt] = $val;
    else $fields[$opt] = is_string($val) ? $val : (string)$val;
  }

  $item = ['domain'=>$norm, 'fields'=>$fields];
  if ($debug && $dbg) $item['debug'] = $dbg;
  $items[] = $item;
}

echo json_encode([
  'ok' => true,
  'query_ms' => round((microtime(true)-$started)*1000),
  'items' => $items,
], JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE|JSON_PRETTY_PRINT);
