import {parse} from 'tldts';
import linkifyit from 'linkify-it';
import tlds from 'tlds';
import { SLTLDs, skipDomains } from "./domainLists.jsx";

const linkify = linkifyit();
linkify.tlds(tlds)
linkify.tlds(SLTLDs)

let filteredLinksArray = [];
const regBracketDotText = /(\s?\W\s?)dot(\s?\W\s?)/ig;
const regBracketDot = /(\s?\W\s?)\.(\s?\W\s?)/ig;
const regDomains = /(?<=^|[^a-z0-9])((?:[a-z0-9-]+\.)+[a-z]{2,})(?=[^a-z0-9]|$)/gi;
const regHxxps = /hxxps\s*\[?\s*?:\s*?]?\s*\/{1,2}\s*/gi;
const regHxxp = /hxxp\s*\[?\s*?:\s*?]?\s*\/{1,2}\s*/gi;
const regSemicolon = / ?\[:] ?/gi;

// --- HELPERS ---

// Keep only domains where predicate(row, domain) === true
export function filterApiDomains(api, predicate) {
  const out = { ...api, domains: {} };
  if (!api || !api.domains) return out;
  for (const [domain, row] of Object.entries(api.domains)) {
    try {
      if (predicate(row, domain)) out.domains[domain] = row;
    } catch (_) {}
  }
  return out;
}

// Convenience: filter by registrar substring (case-insensitive)
export function filterByRegistrar(api, name) {
  const q = String(name || '').toLowerCase();
  if (!q) return api;
  return filterApiDomains(api, (row) =>
    String(row?.whois?.registrar || '').toLowerCase().includes(q)
  );
}


export function enforceIpOrgDependency() {
  const a  = document.getElementById('checkboxA')?.checked ?? false;
  const mx = document.getElementById('checkboxMX')?.checked ?? false;

  const ip     = document.getElementById('checkboxIP_ORG');
  const ipVis  = document.getElementById('checkboxIP_ORGVis');
  const checkedCls  = 'parser__options__checkModule__vis-checkbox--checked';
  const disabledCls = 'is-disabled'; // optional; add CSS if you want styling

  const shouldDisable = !(a || mx);

  if (!ip) return;

  ip.disabled = shouldDisable;

  if (shouldDisable) {
    ip.checked = false;                 // uncheck if not allowed
    if (ipVis) ipVis.classList.remove(checkedCls);
    if (ipVis) ipVis.classList.add(disabledCls);
  } else {
    if (ipVis) ipVis.classList.remove(disabledCls);
  }
}

// Read checked boxes as UI labels: 'Reg_date','IP','IP_org','NS','MX','MX_org','IsSusp','Regist'
function getSelectedUiOptions() {
  const fs = document.getElementById('infoTypeSelector');
  if (!fs) return [];
  return Array.from(fs.querySelectorAll('input[type="checkbox"]'))
    .filter(el => el.checked && !el.disabled)
    .map(el => el.value || el.id.replace(/^checkbox/, ''));
}

// Map UI labels -> API include flags expected by backend
function buildApiIncludeFromUi(ui) {
  const api = new Set();

  // WHOIS-derived fields
  if (ui.some(x => ['Reg_date','IsSusp','Regist'].includes(x))) api.add('WHOIS');

  // IP/A
  if (ui.includes('IP')) api.add('A');

  // NS
  if (ui.includes('NS')) api.add('NS');

  // MX (+ extras)
  if (ui.includes('MX')) api.add('MX');

  // IP org lookups (covers A IPs and MX IPs when MX is requested)
  if (ui.includes('IP_org')) { api.add('A'); api.add('IP_ORG'); }
  if (ui.includes('MX_org')) { api.add('MX'); api.add('IP_ORG'); }

  return Array.from(api);
}

const toUSDate = (s) => {
  if (!s) return '—';
  // prefer YYYY-MM-DD prefix if present (avoids TZ shifts)
  const m = String(s).match(/^(\d{4})-(\d{2})-(\d{2})/);
  if (m) return `${+m[2]}/${+m[3]}/${m[1]}`; // M/D/YYYY (no leading zeros)

  // fallback: parse whatever it is
  const d = new Date(s);
  return isNaN(d) ? String(s) : `${d.getUTCMonth() + 1}/${d.getUTCDate()}/${d.getUTCFullYear()}`;
};

// Handles custom checkbox toggling
function toggleCheckbox(id, checked){
  const el = document.getElementById(id);
  if (!el) return;
  const cls = "parser__options__checkModule__vis-checkbox--checked";
  if (typeof checked === 'boolean') {
    el.classList.toggle(cls, checked);
  } else {
    el.classList.toggle(cls);
  }
}

// --- BASE FUNCTIONS ---

// Returns input text with basic parsing (brackets, protocols)
function getInputText(){

  // Get domains from input
  let worklist = document.getElementById("parserInput").value;

  // Remove brackets, fix protocols
  worklist = worklist.replace(regBracketDot, ".");
  worklist = worklist.replace(regBracketDotText, ".");
  worklist = worklist.replace(regHxxps, "https://");
  worklist = worklist.replace(regHxxp, "http://");
  worklist = worklist.replace(regSemicolon, ":");
  return worklist;
}

// Returns an array of verified domains from input. Accepts either hostname or domain as a type
function getDomains(type) {
  // Get text from input
  let worklist = getInputText();

  // Search for domains in text
  worklist = worklist.match(regDomains) || [];

  // Set them in array with unique values
  worklist = [...new Set(worklist)];

  // Validate domains and remove invalid
  let tempArray = [];

  worklist.forEach((domain) => {
    let el = parse(domain)
    if (el.isIcann && el.domain && !SLTLDs.includes(el.hostname)) {
      // Treat known used second level TLDs (us.com) as TLDs instead of domains
      if (SLTLDs.includes(el.domain)){
        let tempRegExp = new RegExp(`.+\\.${el.domain}`, "gm");
        el.domain = el.hostname.match(tempRegExp)[0];
      }
      tempArray.push(el);
    }
  });
  worklist = [...new Set(tempArray)];

  // Reset filtered array/output
  filteredLinksArray = [];

  // Set domains into filtered array
  tempArray = [];
  worklist.forEach((domain) => {
    tempArray.push(domain[type]);
  });
  filteredLinksArray= [...new Set(tempArray)];

  // Get a text list from filtered array
  worklist = createListFromArray(filteredLinksArray);
  return({worklist, filteredLinksArray});
}

// Returns an array of verified links from input
function getLinks() {
  // Get text from input
  let worklist = getInputText();

  // Search for links in text
  worklist = linkify.match(worklist) || [];

  // Set them in array with unique values
  worklist = [...new Set(worklist)];

  // Validate domains and remove duplicates
  let tempArray = [];
  worklist.forEach((domain) => {

    //Skip emails
    if (!domain.text.includes("@")) {
      let el = parse(domain.text);
      if (el.isIcann) {
        tempArray.push(domain.text);
      }
    }
  });
  worklist = [...new Set(tempArray)];

  // Reset filtered array/output and set domains
  /*filteredLinksArray = [];
  tempArray = [];
  worklist.forEach((domain) => {
    tempArray.push(domain);
  });*/
  filteredLinksArray= [...new Set(worklist)];

  // Get a text list from filtered array
  worklist = createListFromArray(filteredLinksArray);

  return({worklist, filteredLinksArray});
}

// Converts an array of domains to a text list
function createListFromArray(domainArray){
  let i = domainArray.length -1;
  let domainList = "";
  domainArray.forEach((domain) => {
    domainList+= `${domain}${i!==0?"\n":""}`;
    i--;
  })
  return domainList;
}

// Copies to clipboard command from the template
async function copyCommand(type){
  let domains = getDomains("domain").filteredLinksArray;
  let button = document.getElementById(`get${type}`);

  let tempDomains = "", text = "";
  if (type === "whois"){
    try {
      domains.forEach((domain, index) => {
        let line = `${domain}${index === domains.length-1 ? "" : "\n"}`;
        tempDomains += (line);
      })

      text = (`declare -a testStatus=(${tempDomains})
for i in ` + '"${testStatus[@]}"' + `; do
  echo -e "$i: $(whois "$i" | grep 'Status:')"
echo    
done`);

      await navigator.clipboard.writeText(text);
      button.innerHTML = "Copied!";
      setTimeout(() => {
        button.innerHTML = "Copy bulk Whois";
      }, 1000);
    }
    catch (e) {console.log(e)}
  } else if (type === "dig"){
    try {
      domains.forEach((domain, index) => {
        let line = `${domain}${index === domains.length-1 ? "" : "\n"}`;
        tempDomains += (line);
      })

      text = (`declare -a testStatus=(${tempDomains})
for i in ` + '"${testStatus[@]}"' + `; do
  echo "=== $i ==="
  dig +trace +nodnssec "$i" | grep "$i" | tail -n 3
  echo    
done`);

      await navigator.clipboard.writeText(text);
      button.innerHTML = "Copied!";
      setTimeout(() => {
        button.innerHTML = `Copy bulk <br/> dig`;
      }, 1000);
    }
    catch (e) {console.log(e)}
  }
}

// utils.js — send a request to your PHP API using the global `filteredLinksArray`
async function fetchDomainInfo(options = {}) {

  const {
    endpoint = 'https://grasten.org/api/domaininfo.php',
    include = ['A', 'IP_ORG', 'NS', 'MX', 'WHOIS'],
    blacklists,                 // e.g. ['dbl','surbl']
    debug = false,              // true to get _debug raw outputs
  } = options;

  // read domains from global/local variable
  const src =
    (typeof filteredLinksArray !== 'undefined' && Array.isArray(filteredLinksArray)) ? filteredLinksArray
      : (typeof window !== 'undefined' && Array.isArray(window.filteredLinksArray)) ? window.filteredLinksArray
        : [];

  // clean + dedupe
  const domains = [...new Set(src.map(s => String(s).trim()).filter(Boolean))];
  if (domains.length === 0) return { ok: true, domains: {} };

  // include BLACKLISTS if caller passed a list
  const includeSet = new Set(include.map(s => String(s).toUpperCase()));
  if (blacklists && !includeSet.has('BLACKLISTS')) includeSet.add('BLACKLISTS');

  const body = {
    domains,
    include: Array.from(includeSet),
    ...(blacklists ? { blacklists } : {}),
    ...(debug ? { debug: true } : {}),
  };

  const res = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });

  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

// Pretty printer that shows ONLY the lines for selected UI options.
function formatDomainInfoPretty(api, uiSelected = [], order) {
  const domains = (api && api.domains) || {};
  const want = new Set(uiSelected || []);
  const keys = order
    ? Array.from(new Set(order)).filter(d => d in domains)
    : Object.keys(domains).sort((a,b)=>a.localeCompare(b));

  const holdSummary = (statuses = []) => {
    const lower = statuses.map(x => String(x).toLowerCase());
    const holds = [];
    if (lower.some(s => s.includes('client hold'))) holds.push('clientHold');
    if (lower.some(s => s.includes('server hold'))) holds.push('serverHold');
    return holds;
  };

  const out = [];

  for (const d of keys) {
    const row = domains[d] || {};
    const block = [];

    // Always show domain; append " - Reg_date" only if selected
    if (want.has('Reg_date')) {
      block.push(`${d} - ${toUSDate(row.whois?.creation_date)}`);
    } else {
      block.push(d);
    }

    // IP / IP_org line (only if IP or IP_org selected)
    if (want.has('IP') || want.has('IP_org')) {
      const ips = Array.isArray(row.a) ? row.a : [];
      const owners = Array.isArray(row.ip_owner) ? row.ip_owner : [];
      let line = '—';

      if (want.has('IP_org') && owners.length) {
        line = owners
          .map(io => `${io.ip}${io.org ? ` owned by ${io.org}` : ' owned by unknown org'}`)
          .join('; ');
      } else if (want.has('IP') && ips.length) {
        line = ips.join(', ');
      } else if (want.has('IP') && !ips.length && owners.length) {
        line = owners.map(io => io.ip).join(', ');
      }
      block.push(line);
    }

    // NS
    if (want.has('NS')) {
      block.push((row.ns && row.ns.length) ? row.ns.join(', ') : '—');
    }

    // MX (header + one line per record)
    if (want.has('MX')) {
      const mx = Array.isArray(row.mx) ? row.mx : [];
      block.push('MX:');
      if (mx.length) {
        for (const m of mx) {
          const one = `${m.priority ?? ''} ${m.host}`.trim() +
            (m.ips?.length ? ` [${m.ips.join(', ')}]` : '');
          block.push(one);
        }
      } else {
        block.push('—');
      }
    }

    // MX_org
    if (want.has('MX_org')) {
      const mx = Array.isArray(row.mx) ? row.mx : [];
      if (mx.length) {
        const parts = [];
        for (const m of mx) {
          const orgs = Array.isArray(m.ip_orgs) ? m.ip_orgs : [];
          if (orgs.length) {
            parts.push(
              `${m.host}: ` +
              orgs.map(io => `${io.ip}${io.org ? ` owned by ${io.org}` : ' owned by unknown org'}`).join('; ')
            );
          }
        }
        block.push(parts.length ? parts.join('\n') : '—');
      } else {
        block.push('—');
      }
    }

    // IsSusp
    if (want.has('IsSusp')) {
      const holds = holdSummary(row.whois?.statuses || []);
      block.push(holds.length ? `Suspended: ${holds.join(', ')}` : 'Not suspended');
    }

    // Regist (Registrar)
    if (want.has('Regist')) {
      block.push(`${row.whois?.registrar || '—'}`);
    }

    out.push(block.join('\n'));
  }

  return out.join('\n\n');
}

async function handleFetch(){
  const btn = document.getElementById("fetchInfo");
  btn.innerText = "Running...";

  if (filteredLinksArray.length === 0){
    btn.innerText = "No links found";
    setTimeout(() => { btn.innerText = "Fetch domains info"; }, 1000);
    return;
  }

  try {
    const ui = getSelectedUiOptions();
    const include = buildApiIncludeFromUi(ui);

    let data = await fetchDomainInfo({ include });

// Example: keep only domains registered with NameCheap, Inc.
    //data = filterByRegistrar(data, 'NameCheap, Inc.');

// Preserve your original order but only for kept domains
    const order = filteredLinksArray.filter(d => data.domains?.[d]);

    const text = formatDomainInfoPretty(data, ui, order);
    document.getElementById('parserOutput').value = text;
    document.getElementById('parserOutputCounter').innerText =
      `Domains returned: ${Object.keys(data.domains || {}).length}`;

  } catch (e) {
    console.error(e);
  } finally {
    btn.innerText = "Fetch domains info";
  }

}

// --- EXPORT FUNCTIONS ---

// Accepts either "domain" or "hostname" as a param, sets filtered array and values to frontend
export function parseDomains(type){
  let links = {};
  let filter = document.getElementById("filterInput").value;

  switch(type){
    case "hostname": links = getDomains(type);
    break;
    case "domain": links = getDomains(type);
    break;
    case "url": links = getLinks();
    break;
  }

  // If filter option is present, filter the array for it and update worklist
  if (filter){
    links.filteredLinksArray = links.filteredLinksArray.filter((link) => link.includes(filter));
    links.worklist = createListFromArray(links.filteredLinksArray);
  }

  // If skip domains enabled, filter the array for it and update worklist
  if (document.getElementById("checkboxSkip").checked){
    let tempArray = [];
    links.filteredLinksArray.forEach((domain) => {
      let skipDetected, el = domain;
      skipDomains.forEach(skip => {
        if (el === skip){
          skipDetected = true;
        }
      })
      if(!skipDetected){tempArray.push(el)}
    });

    links.filteredLinksArray = [...new Set(tempArray)];
    links.worklist = createListFromArray(links.filteredLinksArray);
  }

  // Set values to front-end and update array used by other functions
  document.getElementById("parserOutput").value = links.worklist;
  document.getElementById("parserOutputCounter").innerText = `Number of links: ${links.filteredLinksArray.length}`;
  filteredLinksArray = links.filteredLinksArray;
}

// Opens parsed domains
export function openParsedDomains(){

  let button = document.getElementById(`openLinks`);
  if(!filteredLinksArray[0]){
    button.innerHTML = "No parsed links";
    setTimeout(() => {
      button.innerHTML = "Open parsed links";
    }, 1000);
  } else {
    filteredLinksArray.forEach((el) => {
      linkify.match(el) ? window.open(`${el}`) : window.open(`https://${el}`);
    })
  }
}

// Searches for targets on Google
export function findTargets(){

  let button = document.getElementById(`openTargets`);
  if(!filteredLinksArray[0]){
    button.innerHTML = "No parsed domains";
    setTimeout(() => {
      button.innerHTML = "Find possible targets";
    }, 1000);
  }

  filteredLinksArray.forEach((el) => {
    window.open(`https://www.google.com/search?q=${el}`);
  })
}

// Copies to clipboard command from the template
export { copyCommand, handleFetch, toggleCheckbox };
