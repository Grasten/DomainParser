<?php
/**
 * Domain Intelligence API v2 — domains.php (with debug mode + trace)
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
header('Content-Type: application/json; charset=UTF-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header("Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With");

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
      'file'  => basename($e['file'] ?? ''),
      'line'  => (int)($e['line'] ?? 0),
    ], JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);
  }
});

/////////////////////////////
// Trace globals
/////////////////////////////
$GLOBALS['WHOIS_TRACE'] = [];
$GLOBALS['RDAP_LAST']   = null;

/////////////////////////////
// Constants & utilities
/////////////////////////////
const WHOIS_BIN          = '/usr/bin/whois';
const DIG_BIN            = '/usr/bin/dig';
const CURL_UA            = 'DomainIntel/2 (+https://test.grasten.org)';
const WHOIS_MAX_BYTES    = 128*1024;
const WHOIS_TIMEOUT_SEC  = 6;
const DIG_TIMEOUT_SEC    = 4;
const HTTP_UA            = CURL_UA;

function is_proc_open_enabled(): bool {
  $disabled = array_map('trim', explode(',', (string)ini_get('disable_functions')));
  return function_exists('proc_open') && !in_array('proc_open', $disabled, true);
}
function run_cmd(string $cmd, int $timeout = 5, int $maxBytes = 262144): array {
  $descriptors = [
    0 => ['pipe','r'],
    1 => ['pipe','w'],
    2 => ['pipe','w'],
  ];
  $p = @proc_open($cmd, $descriptors, $pipes);
  if (!is_resource($p)) return ['exit'=>-1, 'out'=>'', 'err'=>'proc_open failed'];
  fclose($pipes[0]);
  stream_set_blocking($pipes[1], false);
  stream_set_blocking($pipes[2], false);
  $out = ''; $err = '';
  $start = microtime(true);
  while (true) {
    if (isset($pipes[1]) && !feof($pipes[1])) $out .= fread($pipes[1], 8192);
    if (isset($pipes[2]) && !feof($pipes[2])) $err .= fread($pipes[2], 8192);
    if ((microtime(true)-$start) > $timeout) break;
    if (feof($pipes[1]) && feof($pipes[2])) break;
    usleep(20000);
    if (strlen($out) > $maxBytes) { $out = substr($out, 0, $maxBytes); break; }
  }
  foreach ($pipes as $pp) if (is_resource($pp)) @fclose($pp);
  $status = proc_get_status($p);
  if ($status && $status['running']) @proc_terminate($p);
  $code = @proc_close($p);
  return ['exit'=>$code, 'out'=>$out, 'err'=>$err];
}

function is_full_url(string $s): bool {
  return (bool)preg_match('~^https?://~i', $s);
}
function to_us_date(string $s): string {
  if ($s === '') return '';
  $t = strtotime($s);
  if ($t === false) return '';
  return date('m/d/Y', $t);
}

/////////////////////////////
// DNS helpers
/////////////////////////////
function dig_a(string $domain): array {
  if (is_proc_open_enabled()) {
    $cmd = sprintf('%s +short A %s +time=%d +tries=1', DIG_BIN, escapeshellarg($domain), DIG_TIMEOUT_SEC);
    $res = run_cmd($cmd, DIG_TIMEOUT_SEC);
    $lines = array_values(array_filter(array_map('trim', explode("\n", $res['out']))));
    $ips = [];
    foreach ($lines as $ln) if (filter_var($ln, FILTER_VALIDATE_IP)) $ips[] = $ln;
    return array_values(array_unique($ips));
  }
  $r = dns_get_record($domain, DNS_A);
  $ips = [];
  foreach ($r as $e) if (!empty($e['ip'])) $ips[] = $e['ip'];
  return array_values(array_unique($ips));
}
function dig_ns_exact(string $domain): array {
  if (is_proc_open_enabled()) {
    $cmd = sprintf('%s +short NS %s +time=%d +tries=1', DIG_BIN, escapeshellarg($domain), DIG_TIMEOUT_SEC);
    $res = run_cmd($cmd, DIG_TIMEOUT_SEC);
    $lines = array_values(array_filter(array_map('trim', explode("\n", $res['out']))));
    $hosts = [];
    foreach ($lines as $ln) {
      $h = rtrim($ln, '.');
      if ($h !== '') $hosts[] = $h;
    }
    return array_values(array_unique($hosts));
  }
  $r = dns_get_record($domain, DNS_NS);
  $hosts = [];
  foreach ($r as $e) if (!empty($e['target'])) $hosts[] = rtrim($e['target'], '.');
  return array_values(array_unique($hosts));
}
function dig_ns_chain(string $domain): array {
  $labels = explode('.', $domain);
  $n = count($labels);
  $test = $domain;
  for ($i = 0; $i < $n; $i++) {
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
    foreach ($lines as $ln) {
      // "10 mx1.example.com."
      if (preg_match('~^\s*\d+\s+([a-z0-9.-]+)\.?$~i', $ln, $m)) {
        $mx[] = ['prio'=>(int)preg_replace('~\D~', '', $ln), 'host'=>rtrim($m[1], '.')];
      }
    }
    return $mx;
  }
  $r = dns_get_record($domain, DNS_MX);
  foreach ($r as $e) $mx[] = ['prio'=>(int)($e['pri'] ?? 0), 'host'=>rtrim((string)($e['target'] ?? ''), '.')];
  return $mx;
}

/////////////////////////////
// WHOIS maps & helpers
/////////////////////////////

function parse_rdap_domain_fields(array $rd): array {
  $out = [
    'registrar'      => '',
    'creation_date'  => '',
    'statuses'       => [],
    'suspended'      => false, // derived flag
  ];

  // Registrar: often in entities with role registrar / sponsoring registrar
  if (!empty($rd['entities']) && is_array($rd['entities'])) {
    foreach ($rd['entities'] as $ent) {
      $roles = array_map('strtolower', (array)($ent['roles'] ?? []));
      if (array_intersect($roles, ['registrar','sponsoring registrar','sponsor'])) {
        // vCard FN is canonical name
        if (!empty($ent['vcardArray'][1])) {
          foreach ($ent['vcardArray'][1] as $v) {
            if (($v[0] ?? '') === 'fn' && !empty($v[3])) {
              $out['registrar'] = (string)$v[3];
              break 2;
            }
          }
        }
      }
    }
  }

  // Creation/Registration date: accept several eventAction variants
  $created = null;
  foreach ((array)($rd['events'] ?? []) as $ev) {
    $action = strtolower((string)($ev['eventAction'] ?? ''));
    if (in_array($action, ['registration','creation','created'], true)) {
      $created = (string)($ev['eventDate'] ?? '');
      if ($created !== '') break;
    }
  }
  if (!$created) {
    // fallback: some servers only expose 'registered'
    foreach ((array)($rd['events'] ?? []) as $ev) {
      $action = strtolower((string)($ev['eventAction'] ?? ''));
      if ($action === 'registered') { $created = (string)($ev['eventDate'] ?? ''); break; }
    }
  }
  if ($created) {
    $t = strtotime($created);
    if ($t !== false) $out['creation_date'] = date('c', $t);
  }

  // Statuses: direct from RDAP
  $statuses = array_map('strval', (array)($rd['status'] ?? []));
  $out['statuses'] = $statuses;

  // Suspension heuristic: common “hold/inactive” flags
  $suspSignals = ['clienthold','serverhold','inactive','redemptionperiod','pendingdelete'];
  $hasSusp = false;
  foreach ($statuses as $s) {
    $k = strtolower(preg_replace('~\s+~', '', $s));
    if (in_array($k, $suspSignals, true)) { $hasSusp = true; break; }
  }
  $out['suspended'] = $hasSusp;

  return $out;
}

// --- Namecheap fallback WHOIS ---
// Only for .com/.net/.org-like zones when all normal queries failed.
function whois_namecheap_fallback(string $domain): string {
  $txt = whois_port43('whois.namecheap.com', $domain);
  $txt = trim($txt);
  if ($txt !== '' && stripos($txt, 'whois server:') === false) {
    // Looks like real Namecheap data
    error_log("whois_namecheap_fallback: got {$domain}");
    return substr($txt, 0, WHOIS_MAX_BYTES);
  }
  return '';
}

// --- Enom fallback WHOIS ---
// Good as a last-resort for many retail .com/.net/.org/.info/.biz domains.
function whois_enom_fallback(string $domain): string {
  $txt = whois_port43('whois.enom.com', $domain);
  $txt = trim($txt);

  // Return only if it looks like a real Enom response (not an empty stub)
  // Enom usually includes "Registration Service Provided By:" or "Domain record activated:"
  if ($txt !== '' &&
      (stripos($txt, 'Registration Service Provided By') !== false
       || stripos($txt, 'Domain record') !== false
       || stripos($txt, 'Registrar: eNom') !== false
       || stripos($txt, 'whois.enom.com') !== false)) {
    error_log("whois_enom_fallback: got {$domain}");
    return substr($txt, 0, WHOIS_MAX_BYTES);
  }
  return '';
}

// hostname helpers for SLD mapping (e.g., jp.net, uk.com)
function host_suffix(string $host, int $labels = 2): string {
  $parts = explode('.', $host);
  $n = count($parts);
  if ($n < $labels) return $host;
  return implode('.', array_slice($parts, $n - $labels));
}

//// Maps

//  TLD map (single label TLDs to WHOIS servers)
const WHOIS_TLD_MAP = [
  // --- original ones ---
  'gg' => 'whois.gg',
  'je' => 'whois.je',
  'me' => 'whois.nic.me',
  'io' => 'whois.nic.io',
  'es' => 'whois.nic.es',

  // --- stable and widely used ccTLDs ---
  'uk' => 'whois.nic.uk',
  'co.uk' => 'whois.nic.uk',
  'org.uk' => 'whois.nic.uk',
  'ca' => 'whois.cira.ca',
  'de' => 'whois.denic.de',
  'fr' => 'whois.nic.fr',
  'nl' => 'whois.domain-registry.nl',
  'be' => 'whois.dns.be',
  'pl' => 'whois.dns.pl',
  'se' => 'whois.iis.se',
  'no' => 'whois.norid.no',
  'dk' => 'whois.dk-hostmaster.dk',
  'fi' => 'whois.fi',
  'ch' => 'whois.nic.ch',
  'li' => 'whois.nic.li',
  'cz' => 'whois.nic.cz',
  'sk' => 'whois.sk-nic.sk',
  'at' => 'whois.nic.at',
  'hu' => 'whois.nic.hu',
  'ru' => 'whois.tcinet.ru',
  'su' => 'whois.tcinet.ru',
  'by' => 'whois.cctld.by',
  'ua' => 'whois.ua',
  'kz' => 'whois.nic.kz',
  'lt' => 'whois.domreg.lt',
  'lv' => 'whois.nic.lv',
  'ee' => 'whois.tld.ee',
  'is' => 'whois.isnic.is',
  'nz' => 'whois.srs.net.nz',
  'au' => 'whois.auda.org.au',
  'br' => 'whois.registro.br',
  'ar' => 'whois.nic.ar',
  'mx' => 'whois.mx',
  'cl' => 'whois.nic.cl',
  'co' => 'whois.nic.co',
  'in' => 'whois.registry.in',
  'jp' => 'whois.jprs.jp',
  'kr' => 'whois.kr',
  'sg' => 'whois.sgnic.sg',
  'hk' => 'whois.hkirc.hk',
  'tw' => 'whois.twnic.net.tw',
  'cn' => 'whois.cnnic.cn',
  'id' => 'whois.idnic.net.id',
  'my' => 'whois.mynic.my',
  'ph' => 'whois.dot.ph',
  'th' => 'whois.thnic.co.th',
  'vn' => 'whois.vnnic.vn',
  'za' => 'whois.registry.net.za',

  // --- classic gTLDs (for completeness; many still support port 43) ---
  'com' => 'whois.verisign-grs.com',
  'net' => 'whois.verisign-grs.com',
  'org' => 'whois.pir.org',
  'info' => 'whois.afilias.net',
  'biz' => 'whois.nic.biz',
  'mobi' => 'whois.dotmobiregistry.net',
  'name' => 'whois.nic.name',
  'pro' => 'whois.dotproregistry.net',
  'tv' => 'whois.nic.tv',
  'cc' => 'whois.nic.cc',

  // --- newer ccTLDs or RDAP-heavy zones (WHOIS still works for most) ---
  'us' => 'whois.nic.us',
  'la' => 'whois.nic.la',
  'io' => 'whois.nic.io',
  'ai' => 'whois.nic.ai',
  'sh' => 'whois.nic.sh',
  'ac' => 'whois.nic.ac',
  'fm' => 'whois.nic.fm',
  'to' => 'whois.tonic.to',
  'cx' => 'whois.nic.cx',
  'gs' => 'whois.nic.gs',
  'ws' => 'whois.website.ws',
];


const WHOIS_SLD_MAP = [
  'jp.net' => 'whois.centralnic.com',
  // (optional) other CentralNic SLDs you care about:
  'uk.com' => 'whois.centralnic.com',
  'eu.com' => 'whois.centralnic.com',
];

// Polyfill for PHP < 8.0 (if needed). Safe to keep even on newer PHP.
if (!function_exists('str_ends_with')) {
  function str_ends_with(string $haystack, string $needle): bool {
    if ($needle === '') return true;
    $len = strlen($needle);
    return substr($haystack, -$len) === $needle;
  }
}

/**
 * Return a WHOIS server for multi-label "pseudo-TLD" zones.
 * CentralNic operates many second-level zones (e.g., *.it.com, *.cn.com, *.uk.net)
 * that are NOT IANA TLDs. These must go to whois.centralnic.com (port 43).
 */
function whois_suffix_server(string $domain): ?string {
  static $centralnicZones = [
    // Common CentralNic-operated SLD zones. Add more as you need.
    'it.com',
    'cn.com', 'uk.com', 'uk.net', 'us.com', 'eu.com', 'de.com', 'no.com',
    'jpn.com', 'kr.com', 'ru.com', 'za.com', 'br.com', 'ar.com',
    'se.com', 'se.net', 'hu.com', 'hu.net', 'uy.com',
    'co.com', 'gr.com', 'in.net',
    'gb.com', 'gb.net',
    'qc.com', 'qc.ca',
    'com.se', // legacy style in some datasets
  ];

  $d = strtolower($domain);
  foreach ($centralnicZones as $z) {
    if (str_ends_with($d, '.'.$z)) {
      return 'whois.centralnic.com';
    }
  }
  return null; // not a CentralNic SLD that we know
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

      // ESNIC / .es variants
      '~\b0\s+objects\b~i',               // "% This query returned 0 objects."
      '~\bno\s+existen\s+entradas\b~i',   // "No existen entradas ..."
    ];
    foreach ($patterns as $re) {
      if (preg_match($re, $line)) {
        return $line; // return the exact matching line
      }
    }
  }
  return null;
}

function whois_tld_referral(string $tld, int $timeout = 6): ?string {
  if ($tld === '') return null;
  $txt = whois_port43('whois.iana.org', $tld, $timeout);
  if ($txt === '') return null;
  // IANA uses either "whois:" or "refer:" for the referral field
  if (preg_match('~^\s*(?:whois|refer)\s*:\s*([a-z0-9.-]+\.[a-z]{2,})~im', $txt, $m)) {
    return strtolower(trim($m[1]));
  }
  return null;
}

function whois_text_domain(string $domain): string {
  $trace =& $GLOBALS['WHOIS_TRACE'];
  $push = function(string $method, ?string $server, bool $ok, int $bytes, string $note = '') use (&$trace) {
    $trace[] = [
      'method' => $method,
      'server' => $server,
      'ok'     => $ok,
      'bytes'  => $bytes,
      'note'   => $note,
    ];
  };

  // Compute TLD up-front (used by later steps too)
  $tld = strtolower(substr(strrchr($domain, '.'), 1) ?: '');

  // 0) RDAP (bootstrap via rdap.org) — do this first for gTLDs / most zones
  // Works for .app, .dev, .group, .support, .doctor, .tours, .repair, .ventures, .news, .services, many ccTLDs, etc.
  if ($domain !== '') {
    $rd_org = rdap_fetch_domain($domain);
    if ($rd_org) {
      // Reuse your existing textifier so downstream logic stays unchanged
      $txt = rdap_domain_textify($rd_org);
      $ok  = trim($txt) !== '';
      $push('rdap-org', null, $ok, strlen($txt));
      if ($ok) return substr($txt, 0, WHOIS_MAX_BYTES);
    } else {
      $push('rdap-org', null, false, 0, 'no-json-or-non200');
    }
  }

  // 1) Try local whois binary first
  if (is_proc_open_enabled()) {
    $cmd = sprintf('%s -H %s', WHOIS_BIN, escapeshellarg($domain));
    $res = run_cmd($cmd, WHOIS_TIMEOUT_SEC, WHOIS_MAX_BYTES);
    $txt = trim(($res['out'] ?: $res['err']) ?? '');
    $ok  = ($res['exit'] === 0) && ($txt !== '');
    $push('whois-bin', null, $ok, strlen($txt));
    if ($ok) return substr($txt, 0, WHOIS_MAX_BYTES);
  }

  // 2) SLD-specific server (multi-label suffixes like it.com / cn.com / uk.net -> CentralNic)
  if ($srv = whois_suffix_server($domain)) {
    $txt = whois_port43($srv, $domain);
    $ok  = trim($txt) !== '';
    $push('port43-suffix', $srv, $ok, strlen($txt));
    if ($ok) return substr($txt, 0, WHOIS_MAX_BYTES);
  }

  // 3) TLD-specific server (single-label map like io -> whois.nic.io)
  if ($tld && !empty(WHOIS_TLD_MAP[$tld])) {
    $srv = WHOIS_TLD_MAP[$tld];
    $txt = whois_port43($srv, $domain);
    $ok  = trim($txt) !== '';
    $push('port43-map', $srv, $ok, strlen($txt));
    if ($ok) return substr($txt, 0, WHOIS_MAX_BYTES);
  }

  // 4) Generic IANA referral (fallback when not in our maps)
  $ref = whois_tld_referral($tld);
  if ($ref) {
    if (preg_match('~^[a-z0-9.-]+\.[a-z]{2,}$~i', $ref)) {
      $txt = whois_port43($ref, $domain);
      $ok  = trim($txt) !== '';
      $push('port43-referral', $ref, $ok, strlen($txt));
      if ($ok) return substr($txt, 0, WHOIS_MAX_BYTES);
    } else {
      $push('port43-referral', $ref, false, 0, 'invalid-referral');
    }
  } else {
    $push('port43-referral', null, false, 0, 'no-referral');
  }

  // 5) RDAP fallback (your existing resolver, useful for ccTLDs your bootstrap didn't cover)
  $rd = rdap_domain($domain);
  $txt = $rd ? rdap_domain_textify($rd) : '';
  $push('rdap', null, $txt !== '', strlen($txt));
  return $txt;

  // 6) Namecheap fallback (for .com / .net / .org retail domains)
  if (in_array($tld, ['com','net','org','info','biz'], true)) {
    $txt2 = whois_namecheap_fallback($domain);
    $ok   = trim($txt2) !== '';
    $push('port43-namecheap', 'whois.namecheap.com', $ok, strlen($txt2));
    if ($ok) return $txt2;
  }

    // 7) Enom fallback (secondary, same gTLD set)
    $txt3 = whois_enom_fallback($domain);
    $ok3  = trim($txt3) !== '';
    $push('port43-enom', 'whois.enom.com', $ok3, strlen($txt3));
    if ($ok3) return $txt3;

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
function normalize_date(string|array $s): ?string {
  $candidates = is_array($s) ? $s : [$s];
  foreach ($candidates as $x) {
    $x = trim((string)$x);
    if ($x === '') continue;
    $t = strtotime($x);
    if ($t !== false) return date('c', $t);
  }
  return null;
}

/////////////////////////////
// WHOIS port-43 & RDAP
/////////////////////////////
function whois_port43(string $server, string $query, int $timeout = WHOIS_TIMEOUT_SEC): string {
  $query = trim($query);
  if ($server === '' || $query === '') return '';

  // Skip known-problematic TLDs/hosts if you like:
  // if (preg_match('/\.es$/i', $query)) return '';

  $errno = 0; $errstr = '';
  $ctx = stream_context_create(['socket' => ['connect_timeout' => $timeout]]);

  // --- Temporarily suppress your custom error handler just for connect ---
  $prevHandler = set_error_handler(function () { /* swallow warnings */ });
  try {
    $fp = stream_socket_client(
      "tcp://{$server}:43",
      $errno,
      $errstr,
      $timeout,
      STREAM_CLIENT_CONNECT,
      $ctx
    );
  } finally {
    restore_error_handler();
  }

  // Handle connect failure gracefully (e.g., "No route to host")
  if ($fp === false || $errno) {
    // common errno on Linux: 113 = No route to host, 110 = Connection timed out
    error_log("whois_port43: connect failed to {$server}: {$errstr} (errno {$errno})");
    return '';
  }

  stream_set_timeout($fp, $timeout);

  // Send query
  fwrite($fp, $query . "\r\n");

  // Read response
  $buf = '';
  while (!feof($fp)) {
    $chunk = fread($fp, 8192);
    if ($chunk === false) break;
    $buf .= $chunk;
    if (strlen($buf) >= WHOIS_MAX_BYTES) break;

    $meta = stream_get_meta_data($fp);
    if (!empty($meta['timed_out'])) {
      error_log("whois_port43: read timed out for {$server}");
      break;
    }
  }
  fclose($fp);

  return substr($buf, 0, WHOIS_MAX_BYTES);
}

// --- RDAP lookup helper ---
// Uses rdap.org as a universal redirector to authoritative RDAP servers
function rdap_fetch_domain(string $domain): ?array {
  $url = 'https://rdap.org/domain/' . rawurlencode($domain);

  $ch = curl_init($url);
  curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_MAXREDIRS      => 8,
    CURLOPT_CONNECTTIMEOUT => 5,
    CURLOPT_TIMEOUT        => 10,
    CURLOPT_HTTPHEADER     => [
      'Accept: application/rdap+json, application/json',
      'User-Agent: GrastenDomainProbe/1.0 (+test.grasten.org)',
    ],
  ]);

  $body = curl_exec($ch);
  $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
  curl_close($ch);

  if ($code === 200 && $body) {
    $data = json_decode($body, true);
    if (is_array($data)) {
      return $data;
    }
  }

  return null; // RDAP unavailable or domain not found
}

function rdap_fetch(string $url, int $timeout = 6): ?array {
  $ua   = HTTP_UA;
  $host = parse_url($url, PHP_URL_HOST) ?: '';

  // Default SSL opts (strict)
  $ssl = ['verify_peer' => true, 'verify_peer_name' => true];

  // rdap.nic.es sometimes serves a cert with a mismatched CN.
  // For JUST this host, relax peer_name verification so we can read the RDAP JSON.
  if (strcasecmp($host, 'rdap.nic.es') === 0) {
    $ssl['verify_peer_name'] = false;   // keep verify_peer=true
  }

  $ctx = stream_context_create([
    'http' => [
      'method'  => 'GET',
      'header'  => "User-Agent: $ua\r\nAccept: application/rdap+json, application/json;q=0.9\r\n",
      'timeout' => $timeout,
      'follow_location' => 1,
      'max_redirects'   => 3,
    ],
    'ssl' => $ssl,
  ]);

  // Temporarily swallow warnings so the global error handler doesn't fatal on TLS notices.
  $tmpErr = null;
  $prev = set_error_handler(function($severity, $message) use (&$tmpErr) {
    $tmpErr = $message;
    return true; // handled
  });

  $raw = @file_get_contents($url, false, $ctx);

  if ($prev !== null) set_error_handler($prev);
  if ($raw === false) return null;

  $j = json_decode($raw, true);
  return is_array($j) ? $j : null;
}

function rdap_domain(string $domain): ?array {
  $tld = strtolower(substr(strrchr($domain, '.'), 1) ?: '');
  if ($tld === '') return null;
  // Try IANA bootstrap (static quick map for common TLDs)
  $rdap = [
    'com'  => 'https://rdap.verisign.com/com/v1/domain/',
    'net'  => 'https://rdap.verisign.com/net/v1/domain/',
    'org'  => 'https://rdap.publicinterestregistry.net/rdap/org/domain/',
    'io'   => 'https://rdap.nic.io/domain/',
    'me'   => 'https://rdap.nic.me/domain/',
    'info' => 'https://rdap.afilias.net/rdap/info/domain/',
    'es'   => 'https://rdap.nic.es/domain/',
  ][$tld] ?? null;
  if (!$rdap) return null;
  return rdap_fetch($rdap . urlencode($domain));
}
function rdap_domain_textify(array $rd): string {
  $lines = [];
  $name = (string)($rd['ldhName'] ?? '');
  if ($name !== '') $lines[] = "Domain: $name";
  if (!empty($rd['status']) && is_array($rd['status'])) {
    $lines[] = 'Status: ' . implode(', ', $rd['status']);
  }
  if (!empty($rd['events']) && is_array($rd['events'])) {
    foreach ($rd['events'] as $e) {
      $act = strtolower((string)($e['eventAction'] ?? ''));
      $dt  = (string)($e['eventDate'] ?? '');
      if ($act !== '' && $dt !== '') $lines[] = ucfirst($act) . ': ' . $dt;
    }
  }
  if (!empty($rd['entities']) && is_array($rd['entities'])) {
    foreach ($rd['entities'] as $ent) {
      $roles = array_map('strtolower', (array)($ent['roles'] ?? []));
      if (in_array('registrar', $roles, true)) {
        $fn = '';
        if (!empty($ent['vcardArray'][1])) {
          foreach ($ent['vcardArray'][1] as $v) {
            if (($v[0] ?? '') === 'fn' && !empty($v[3])) { $fn = $v[3]; break; }
          }
        }
        if (!$fn && !empty($ent['fn'])) $fn = (string)$ent['fn'];
        if ($fn !== '') $lines[] = 'Registrar: ' . $fn;
      }
    }
  }
  return implode("\n", $lines);
}
function rdap_ip(string $ip): ?array {
  $v = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? 'v6' : 'v4';
  $map = [
    'v4' => 'https://rdap.apnic.net/ip/',
    'v6' => 'https://rdap.apnic.net/ip/',
  ];
  return rdap_fetch($map[$v] . urlencode($ip));
}
function rdap_ip_textify(array $rd): string {
  $lines = [];
  $name = (string)($rd['name'] ?? '');
  if ($name !== '') $lines[] = "Network: $name";
  if (!empty($rd['events'])) {
    foreach ($rd['events'] as $e) {
      $act = strtolower((string)($e['eventAction'] ?? ''));
      $dt  = (string)($e['eventDate'] ?? '');
      if ($act !== '' && $dt !== '') $lines[] = ucfirst($act) . ': ' . $dt;
    }
  }
  return implode("\n", $lines);
}

/////////////////////////////
// HTTP helpers
/////////////////////////////
function http_fetch_url(string $url, int $timeout = 8): array {
  $ua = HTTP_UA;
  if (function_exists('curl_init')) {
    $ch = curl_init($url);
    curl_setopt_array($ch, [
      CURLOPT_RETURNTRANSFER => true,
      CURLOPT_FOLLOWLOCATION => true,
      CURLOPT_MAXREDIRS      => 5,
      CURLOPT_CONNECTTIMEOUT => $timeout,
      CURLOPT_TIMEOUT        => $timeout,
      CURLOPT_USERAGENT      => $ua,
      CURLOPT_SSL_VERIFYHOST => 2,
      CURLOPT_SSL_VERIFYPEER => 1,
      CURLOPT_HTTPHEADER     => ['Accept: text/html,application/xhtml+xml;q=0.9,*/*;q=0.8'],
    ]);
    $body = curl_exec($ch);
    $err  = curl_error($ch);
    $ctype= curl_getinfo($ch, CURLINFO_CONTENT_TYPE) ?: '';
    $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    $final= curl_getinfo($ch, CURLINFO_EFFECTIVE_URL) ?: $url;
    curl_close($ch);
    return [
      'ok'         => $body !== false && $code > 0,
      'status'     => $code,
      'final_url'  => $final,
      'ctype'      => is_string($ctype) ? $ctype : '',
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
  $code = 0; $ctype = ''; $final = $url;
  foreach ($meta as $h) {
    if (preg_match('~^HTTP/[\d.]+\s+(\d+)~i', $h, $m)) $code = (int)$m[1];
    if (stripos($h, 'Content-Type:') === 0) $ctype = trim(substr($h, strlen('Content-Type:')));
    if (stripos($h, 'Location:') === 0)     $final = trim(substr($h, strlen('Location:')));
  }
  return [
    'ok'     => $body !== false && $code > 0,
    'status' => $code,
    'final_url' => $final,
    'ctype'  => is_string($ctype) ? $ctype : '',
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
  if (stripos((string)($r['ctype'] ?? ''), 'text/html') === false) return false;
  return html_visible_text_len((string)($r['body'] ?? '')) >= 80;
}

/////////////////////////////
// Parsing helpers
/////////////////////////////
function clean_statuses(array $st): array {
  $out = [];
  foreach ($st as $x) {
    $x = strtolower(trim((string)$x));
    if ($x === '') continue;
    $x = preg_replace('~\s+~', ' ', $x);
    $x = preg_replace('~\s*\(.*?\)\s*~', '', $x); // strip comments
    $out[] = $x;
  }
  return array_values(array_unique($out));
}

/////////////////////////////
// Options
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

      // If parsed list is empty but we have raw text, try block-aware extraction
      if (empty($st) && $raw !== '') {
        $has = function(string $re) use ($raw): bool {
          // match only in first "Domain Status" block if present
          $block = $raw;
          if (preg_match('~^\s*Domain\s+Status\s*:\s*(.+?)(?:^\S|\z)~ims', $raw, $mm)) {
            $block = $mm[1];
          }
          return (bool)preg_match($re, $block);
        };
        $out = [];
        if ($has('~server[\s\-_]*hold~i')) $out[] = 'serverHold';
        if ($has('~client[\s\-_]*hold~i')) $out[] = 'clientHold';

        // de-dup, preserve order
        $seen = []; $res = [];
        foreach ($out as $x) if (!isset($seen[$x])) { $seen[$x]=1; $res[]=$x; }
        return $res; // [] means "statuses present, but no hold flags"
      }
      return $st;
    }
  ],
  'Regist' => [
    'deps' => ['WHOIS'],
    'present' => function(array $ctx): string {
      return $ctx['whois']['registrar'] ?? '';
    }
  ],
  'NoMatch' => [
    'deps' => ['WHOIS'],
    'present' => function(array $ctx): string {
      $raw = (string)($ctx['whois_raw'] ?? '');
      $line = whois_no_match_line($raw);
      if ($line !== null) return $line;
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
      $out = [];
      foreach (($ctx['a_org'] ?? []) as $ip => $org) $out[] = $org;
      return array_values(array_unique(array_filter($out, 'strlen')));
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
      $orgs = $ctx['a_org'] ?? [];
      foreach (($ctx['mx'] ?? []) as $m) {
        $ips = dig_a($m['host']);
        foreach ($ips as $ip) if (!empty($orgs[$ip])) $out[] = $orgs[$ip];
      }
      return array_values(array_unique($out));
    }
  ],

  // HTTP
  'HasContent' => [
    'deps' => ['HTTP'],
    'present' => function(array $ctx): string {
      return !empty($ctx['http_ok']) && !empty($ctx['http_meaningful']) ? '1' : '';
    }
  ],
];

/////////////////////////////
// Org lookups (IP → org)
/////////////////////////////
function ip_org_lookup(string $ip): string {
  $rd = rdap_ip($ip);
  if (!$rd) return '';

  // 1) Prefer the organization/registrant entity name
  if (!empty($rd['entities']) && is_array($rd['entities'])) {
    foreach ($rd['entities'] as $ent) {
      $roles = array_map('strtolower', (array)($ent['roles'] ?? []));
      if (array_intersect($roles, ['registrant','organization','org','owner'])) {
        // vCard FN is the canonical display name
        $org = '';
        if (!empty($ent['vcardArray'][1])) {
          foreach ($ent['vcardArray'][1] as $v) {
            if (($v[0] ?? '') === 'fn' && !empty($v[3])) { $org = (string)$v[3]; break; }
          }
        }
        if ($org === '' && !empty($ent['fn']))   $org = (string)$ent['fn'];
        if ($org === '' && !empty($ent['name'])) $org = (string)$ent['name'];
        if ($org !== '') return $org;
      }
    }
  }

  // 2) Fallback: network name (NetName) or handle
  $name = (string)($rd['name'] ?? '');
  if ($name !== '') return $name;
  return (string)($rd['handle'] ?? '');
}

/////////////////////////////
// Request parsing
/////////////////////////////
$body = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  $body = file_get_contents('php://input');
}
$inDomains = [];
$inOptions = [];
$debugFlag = false;

if (isset($_GET['domain']) && is_string($_GET['domain'])) $inDomains[] = $_GET['domain'];
if (isset($_GET['__debug'])) $debugFlag = true;

if ($body) {
  $j = json_decode($body, true);
  if (is_array($j)) {
    if (!empty($j['domains']) && is_array($j['domains'])) $inDomains = array_merge($inDomains, $j['domains']);
    if (!empty($j['options']) && is_array($j['options'])) $inOptions = array_merge($inOptions, $j['options']);
    if (!empty($j['debug'])) $debugFlag = true;
  }
}

$inDomains = array_values(array_unique(array_filter(array_map('trim', $inDomains), 'strlen')));
if (empty($inDomains)) {
  echo json_encode(['ok'=>false, 'error'=>'no_input','detail'=>'No domains provided'], JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);
  exit;
}

$inOptions = array_values(array_unique(array_filter(array_map('trim', $inOptions), 'strlen')));
// Default options if none provided
if (empty($inOptions)) $inOptions = ['Reg_date','Regist','IsSusp','IP','NS','MX','HasContent'];

/////////////////////////////
// Main processing
/////////////////////////////
$ts0 = microtime(true);
$items = [];

foreach ($inDomains as $rawDomain) {
  $norm = strtolower(trim($rawDomain));
  // extract host from URL if needed
  if (is_full_url($norm)) {
    $u = parse_url($norm);
    $norm = strtolower((string)($u['host'] ?? $norm));
  }
  $norm = rtrim($norm, '.');

  $depsNeeded = [];
  foreach ($inOptions as $opt) {
    $d = $OPTION_REGISTRY[$opt]['deps'] ?? [];
    foreach ($d as $dd) $depsNeeded[$dd] = 1;
  }
  $depsNeeded = array_keys($depsNeeded);

  $ctx = ['domain'=>$norm];
  // Resolve dependencies
  foreach ($depsNeeded as $dep) {
    switch ($dep) {
      case 'WHOIS': {
        // reset trace for this domain
        $GLOBALS['WHOIS_TRACE'] = [];

        $wtxt = whois_text_domain($norm);
        $ctx['whois_raw'] = $wtxt;

        // OPTIONAL: detect ES port-43 policy banner
        if (preg_match('~Conditions of use .* whois service via port 43 .* \.es~i', $wtxt)) {
          // No actionable WHOIS data; RDAP will be used below to fill gaps.
        }
        $parsed = [
          'registrar'     => '',
          'creation_date' => '',
          'statuses'      => [],
          'nameservers'   => [],
        ];

        // quick “no match” early return for parsed extractor
        $line = whois_no_match_line($wtxt);
        if ($line === null) {
          // parse registrar, creation date (very tolerant)
          if (preg_match('~^\s*Registrar\s*:\s*(.+?)\s*$~im', $wtxt, $m)) {
            $parsed['registrar'] = trim($m[1]);
          } elseif (preg_match('~^\s*Sponsoring\s+Registrar\s*:\s*(.+?)\s*$~im', $wtxt, $m)) {
            $parsed['registrar'] = trim($m[1]);
          } elseif (preg_match('~^\s*Registrar\s+Name\s*:\s*(.+?)\s*$~im', $wtxt, $m)) {
            $parsed['registrar'] = trim($m[1]);
          }

          $cdCandidates = [];
          if (preg_match('~^\s*(?:Creation Date|Created On|Registered On|Registration Time)\s*:\s*(.+?)\s*$~im', $wtxt, $m)) {
            $cdCandidates[] = trim($m[1]);
          }
          if (preg_match('~^\s*Domain\s+Registration\s+Date\s*:\s*(.+?)\s*$~im', $wtxt, $m)) {
            $cdCandidates[] = trim($m[1]);
          }
          $parsed['creation_date'] = normalize_date($cdCandidates) ?? '';

          // statuses (try “Domain Status:” blocks first)
          if (preg_match_all('~^\s*Domain\s+Status\s*:\s*(.+?)\s*$~im', $wtxt, $mm)) {
            $parsed['statuses'] = clean_statuses($mm[1]);
          } elseif (preg_match('~^\s*Status\s*:\s*(.+?)\s*$~im', $wtxt, $m)) {
            $parsed['statuses'] = clean_statuses(array_map('trim', preg_split('~\s*,\s*~', $m[1])));
          }

          // nameservers
          if (preg_match_all('~^\s*Name\s*Server\s*:\s*([a-z0-9.-]+)\s*$~im', $wtxt, $mm)) {
            $parsed['nameservers'] = array_values(array_unique(array_map(fn($x)=>strtolower(rtrim($x,'.')), $mm[1])));
          }
        }

        // RDAP enrichment (registrar / creation_date only if missing)
        $rdap_used = false;
        if (($parsed['registrar'] === '' || $parsed['creation_date'] === '')) {
          $rd = rdap_domain($norm);
          if ($rd) {
            if ($parsed['creation_date'] === '' && !empty($rd['events'])) {
              foreach ($rd['events'] as $e) {
                $act = strtolower((string)($e['eventAction'] ?? ''));
                if (in_array($act, ['registration','registered','create','created'], true) && !empty($e['eventDate'])) {
                  $parsed['creation_date'] = $e['eventDate'];
                  $rdap_used = true;
                  break;
                }
              }
            }
            if ($parsed['registrar'] === '' && !empty($rd['entities'])) {
              foreach ($rd['entities'] as $ent) {
                $roles = array_map('strtolower', (array)($ent['roles'] ?? []));
                if (in_array('registrar', $roles, true)) {
                  $name = '';
                  if (!empty($ent['vcardArray'][1])) {
                    foreach ($ent['vcardArray'][1] as $v) {
                      if (($v[0] ?? '') === 'fn' && !empty($v[3])) { $name = $v[3]; break; }
                    }
                  }
                  if (!$name && !empty($ent['fn'])) $name = (string)($ent['fn']);
                  if ($name !== '') { $parsed['registrar'] = $name; $rdap_used = true; break; }
                }
              }
            }
            if ($rdap_used) {
              $GLOBALS['RDAP_LAST'] = [
                'used'    => true,
                'excerpt' => rdap_domain_textify($rd),
              ];
            } else {
              $GLOBALS['RDAP_LAST'] = null;
            }
          }
        } else {
          $GLOBALS['RDAP_LAST'] = null;
        }

        $ctx['whois'] = $parsed;
        break;
      }
      case 'A': {
        $ctx['a'] = dig_a($norm);
        break;
      }
      case 'NS': {
        $ctx['ns'] = dig_ns_chain($norm);
        break;
      }
      case 'MX': {
        $ctx['mx'] = dig_mx($norm);
        break;
      }
      case 'IP_ORG': {
        $orgs = [];
        foreach (dig_a($norm) as $ip) $orgs[$ip] = ip_org_lookup($ip);
        $ctx['a_org'] = $orgs;
        break;
      }
      case 'HTTP': {
        $r = http_probe_root_or_url($norm);
        $ctx['http_ok'] = $r['ok'];
        $ctx['http_status'] = $r['status'];
        $ctx['http_meaningful'] = http_has_meaningful_content($r);
        $ctx['http_final'] = $r['final_url'];
        $ctx['http_ctype'] = $r['ctype'];
        break;
      }
    }
  }

  // Present selected fields
  $fields = [];
  foreach ($inOptions as $opt) {
    $presenter = $OPTION_REGISTRY[$opt]['present'] ?? null;
    if (is_callable($presenter)) {
      $val = $presenter($ctx);
      $fields[$opt] = $val;
    }
  }

  // Build debug payload
  $dbg = null;
  if ($debugFlag) {
    $dbg = [
      'whois_raw_excerpt' => substr((string)($ctx['whois_raw'] ?? ''), 0, 800),
      'whois_parsed'      => $ctx['whois'] ?? [],
      'whois_trace'       => $GLOBALS['WHOIS_TRACE'] ?? [],
      'rdap_used'         => !empty($GLOBALS['RDAP_LAST']['used']),
      'rdap_excerpt'      => isset($GLOBALS['RDAP_LAST']['excerpt']) ? substr($GLOBALS['RDAP_LAST']['excerpt'], 0, 800) : null,
      'http_status'       => $ctx['http_status'] ?? null,
      'http_final'        => $ctx['http_final'] ?? null,
      'http_ctype'        => $ctx['http_ctype'] ?? null,
    ];
  }

  $items[] = [
    'domain' => $norm,
    'fields' => $fields,
    'debug'  => $dbg,
  ];
}

$ms = (int)round((microtime(true) - $ts0) * 1000);
echo json_encode(['ok'=>true, 'query_ms'=>$ms, 'items'=>$items], JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);
