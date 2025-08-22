import {parse} from 'tldts';
import linkifyit from 'linkify-it';
import tlds from 'tlds';
import { SLTLDs, skipDomains } from "./domainLists.jsx";

const linkify = linkifyit();
linkify.tlds(tlds);
linkify.tlds(SLTLDs);

let filteredLinksArray = [];
const regBracketDotText = /(\s?\W\s?)dot(\s?\W\s?)/ig;
const regBracketDot = /(\s?\W\s?)\.(\s?\W\s?)/ig;
const regDomains = /(?<=^|[^a-z0-9])((?:[a-z0-9-]+\.)+[a-z]{2,})(?=[^a-z0-9]|$)/gi;
const regHxxps = /hxxps\s*\[?\s*?:\s*?]?\s*\/{1,2}\s*/gi;
const regHxxp = /hxxp\s*\[?\s*?:\s*?]?\s*\/{1,2}\s*/gi;
const regSemicolon = / ?\[:] ?/gi;

/* =========================
   UI helpers
   ========================= */

// Read checked boxes as UI labels (Reg_date, IP, IP_org, NS, MX, MX_org, IsSusp, Regist)
function getSelectedUiOptions() {
  const fs = document.getElementById('infoTypeSelector');
  if (!fs) return [];
  return Array.from(fs.querySelectorAll('input[type="checkbox"]'))
    .filter(el => el.checked && !el.disabled)
    .map(el => el.value || el.id.replace(/^checkbox/, ''));
}

// Visual checkbox toggle (kept as-is)
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

/* =========================
   Input parsing
   ========================= */

function getInputText(){
  let worklist = document.getElementById("parserInput").value;
  worklist = worklist.replace(regBracketDot, ".");
  worklist = worklist.replace(regBracketDotText, ".");
  worklist = worklist.replace(regHxxps, "https://");
  worklist = worklist.replace(regHxxp, "http://");
  worklist = worklist.replace(regSemicolon, ":");
  return worklist;
}

// Find valid domains/hostnames in text and set filteredLinksArray
function getDomains(type) {
  let worklist = getInputText();
  worklist = worklist.match(regDomains) || [];
  worklist = [...new Set(worklist)];

  const tempArray = [];
  worklist.forEach((domain) => {
    const el = parse(domain);
    if (el.isIcann && el.domain && !SLTLDs.includes(el.hostname)) {
      if (SLTLDs.includes(el.domain)){
        const tempRegExp = new RegExp(`.+\\.${el.domain}`, "gm");
        el.domain = el.hostname.match(tempRegExp)[0];
      }
      tempArray.push(el);
    }
  });

  filteredLinksArray = [...new Set(tempArray.map(d => d[type]))];
  const listText = createListFromArray(filteredLinksArray);
  return ({ worklist: listText, filteredLinksArray });
}

// Extract full URLs (used if user clicks “Parse URLs”)
function getLinks() {
  let worklist = getInputText();
  worklist = linkify.match(worklist) || [];
  worklist = [...new Set(worklist)];

  const urls = [];
  worklist.forEach((m) => {
    if (!m.text.includes("@")) {
      const el = parse(m.text);
      if (el.isIcann) urls.push(m.text);
    }
  });

  filteredLinksArray = [...new Set(urls)];
  const listText = createListFromArray(filteredLinksArray);
  return ({ worklist: listText, filteredLinksArray });
}

function createListFromArray(arr){
  let i = arr.length - 1;
  let out = "";
  arr.forEach((v) => { out += `${v}${i!==0 ? "\n" : ""}`; i--; });
  return out;
}

/* =========================
   API v2
   ========================= */

// POST to v2 API with domains/urls + selected options
async function fetchDomainInfo({ endpoint = 'https://test.grasten.org/api/domains.php', options = [], debug = false } = {}) {
  const src =
    (typeof filteredLinksArray !== 'undefined' && Array.isArray(filteredLinksArray)) ? filteredLinksArray :
      (typeof window !== 'undefined' && Array.isArray(window.filteredLinksArray)) ? window.filteredLinksArray :
        [];

  const domains = [...new Set(src.map(s => String(s).trim()).filter(Boolean))];
  if (domains.length === 0) return { ok: true, items: [] };

  const body = { domains, options, ...(debug ? { debug: true } : {}) };

  const res = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });

  if (!res.ok) throw new Error(`HTTP ${res.status}`);

  return res.json();
}

/* =========================
   Formatting (v2 items[])
   ========================= */

function formatDomainInfoPretty(api, uiSelected = []) {
  const items = Array.isArray(api?.items) ? api.items : [];
  const want = new Set(uiSelected || []);
  const out = [];

  for (const it of items) {
    const d = it.domain || '';
    const f = it.fields || {};
    const block = [];

    // Domain line (append Reg_date if selected and present)
    if (want.has('Reg_date') && f.Reg_date) {
      block.push(`${d} - ${f.Reg_date}`);
    } else {
      block.push(d);
    }

    // IP / IP_org (single combined line)
    if (want.has('IP') || want.has('IP_org')) {
      const ips = Array.isArray(f.IP) ? f.IP : [];
      const orgs = Array.isArray(f.IP_org) ? f.IP_org : [];
      if (ips.length) {
        const orgStr = orgs.length ? ` - ${orgs.join(', ')}` : '';
        block.push(ips.map(ip => `${ip}${orgStr}`).join('; '));
      } else if (want.has('IP_org') && orgs.length) {
        block.push(orgs.join(', '));
      } else {
        block.push('- Not pointed');
      }
    }

    // NS (comma-separated)
    if (want.has('NS')) {
      const ns = Array.isArray(f.NS) ? f.NS : [];
      block.push(ns.length ? ns.join(', ') : '- No NS');
    }

    // MX (combine host with matching MX_org by index when possible)
    if (want.has('MX') || want.has('MX_org')) {
      const mxHosts = Array.isArray(f.MX) ? f.MX : [];
      const mxOrgs = Array.isArray(f.MX_org) ? f.MX_org : [];

      // Always show the MX header if either option is selected
      //block.push(`${mxHosts.length ? 'MX:' : '- No MX'}`);

      if (mxHosts.length && mxOrgs.length) {
        // Pair by index; if lengths differ, fall back gracefully
        const n = Math.max(mxHosts.length, mxOrgs.length);
        for (let i = 0; i < n; i++) {
          const host = mxHosts[i] ?? mxHosts[mxHosts.length - 1] ?? '';
          const org = mxOrgs[i] ?? '';
          if (host && org) block.push(`${host}: ${org}`);
          else if (host) block.push(host);
          else if (org) block.push(org);
        }
      } else if (mxHosts.length) {
        // Only hosts available
        mxHosts.forEach(h => block.push(h));
      } else if (mxOrgs.length) {
        // Only IP-org entries available
        mxOrgs.forEach(s => block.push(s));
      } else {
        block.push('- No MX');
      }
    }

    // IsSusp (exact phrasing)
    if (want.has('IsSusp')) {
      const holds = Array.isArray(f.IsSusp) ? f.IsSusp : [];
      block.push(holds.length ? `Suspended: ${holds.join(', ')}` : 'Not suspended');
    }

    // Regist
    if (want.has('Regist')) {
      block.push(f.Regist || 'Could not detect registry');
    }
    // HasContent
    if (want.has('HasContent')) {
      block.push(`${f.HasContent ? 'Content present' : '- No content'}`);
    }

    out.push(block.join('\n'));
  }

  return out.join('\n\n');
}

/* =========================
   Main button handler
   ========================= */

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
    // v2: send UI options directly
    const data = await fetchDomainInfo({ options: ui });

    const text = formatDomainInfoPretty(data, ui);
    document.getElementById('parserOutput').value = text;
    document.getElementById('parserOutputCounter').innerText =
      `Domains returned: ${Array.isArray(data.items) ? data.items.length : 0}`;
  } catch (e) {
    console.error(e);
  } finally {
    btn.innerText = "Fetch domains info";
  }
}

/* =========================
   Toolkit actions
   ========================= */

async function copyCommand(type){
  const domains = getDomains("domain").filteredLinksArray;
  const button = document.getElementById(`get${type}`);

  let tempDomains = "", text = "";
  if (type === "whois"){
    try {
      domains.forEach((domain, index) => {
        const line = `${domain}${index === domains.length-1 ? "" : "\n"}`;
        tempDomains += (line);
      });

      text = (`declare -a testStatus=(${tempDomains})
for i in ` + '"${testStatus[@]}"' + `; do
  echo -e "$i: $(whois "$i" | grep 'Status:')"
echo    
done`);

      await navigator.clipboard.writeText(text);
      button.innerHTML = "Copied!";
      setTimeout(() => { button.innerHTML = "Copy bulk Whois"; }, 1000);
    } catch (e) { console.log(e); }
  } else if (type === "dig"){
    try {
      domains.forEach((domain, index) => {
        const line = `${domain}${index === domains.length-1 ? "" : "\n"}`;
        tempDomains += (line);
      });

      text = (`declare -a testStatus=(${tempDomains})
for i in ` + '"${testStatus[@]}"' + `; do
  echo "=== $i ==="
  dig +trace +nodnssec "$i" | grep "$i" | tail -n 3
  echo    
done`);

      await navigator.clipboard.writeText(text);
      button.innerHTML = "Copied!";
      setTimeout(() => { button.innerHTML = `Copy bulk <br/> dig`; }, 1000);
    } catch (e) { console.log(e); }
  }
}

/* =========================
   Exports
   ========================= */

export function parseDomains(type){
  let links = {};
  const filter = document.getElementById("filterInput").value;

  switch(type){
    case "hostname": links = getDomains(type); break;
    case "domain":   links = getDomains(type); break;
    case "url":      links = getLinks();       break;
  }

  if (filter){
    links.filteredLinksArray = links.filteredLinksArray.filter((link) => link.includes(filter));
    links.worklist = createListFromArray(links.filteredLinksArray);
  }

  if (document.getElementById("checkboxSkip").checked){
    const temp = [];
    links.filteredLinksArray.forEach((domain) => {
      let skipDetected; const el = domain;
      skipDomains.forEach(skip => { if (el === skip){ skipDetected = true; } });
      if(!skipDetected){ temp.push(el); }
    });
    links.filteredLinksArray = [...new Set(temp)];
    links.worklist = createListFromArray(links.filteredLinksArray);
  }

  document.getElementById("parserOutput").value = links.worklist;
  document.getElementById("parserOutputCounter").innerText =
    `Number of links: ${links.filteredLinksArray.length}`;
  filteredLinksArray = links.filteredLinksArray;
}

export function openParsedDomains(){
  const button = document.getElementById(`openLinks`);
  if(!filteredLinksArray[0]){
    button.innerHTML = "No parsed links";
    setTimeout(() => { button.innerHTML = "Open parsed links"; }, 1000);
  } else {
    filteredLinksArray.forEach((el) => {
      linkify.match(el) ? window.open(`${el}`) : window.open(`https://${el}`);
    });
  }
}

export function findTargets(){
  const button = document.getElementById(`openTargets`);
  if(!filteredLinksArray[0]){
    button.innerHTML = "No parsed domains";
    setTimeout(() => { button.innerHTML = "Find possible targets"; }, 1000);
  }
  filteredLinksArray.forEach((el) => {
    window.open(`https://www.google.com/search?q=${el}`);
  });
}

export { copyCommand, handleFetch, toggleCheckbox };
