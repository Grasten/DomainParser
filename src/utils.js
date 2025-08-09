import {parse} from 'tldts';
import linkifyit from 'linkify-it';
import tlds from 'tlds';
import SLTLDs from "./SLTLDs.jsx";

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
const skipDomains = [
  "gmail.com",
  "yahoo.com",
  "hotmail.com",
  "outlook.com",
  "icloud.com",
  "mail.com",
  "aol.com",
  "protonmail.com",
  "zoho.com",
  "yandex.com",
  "gmx.com",
  "me.com",
  "tutanota.com",
  "live.com",
  "fastmail.com",
  "hushmail.com",
  "qq.com",
  "naver.com",
  "163.com",
  "rediffmail.com",
  "jellyfish.systems",
  "google.com",
  "namecheap.com",
  "1e100.net",
  "gappssmtp.com",
  "microsoft.com",
  "windows.net",
  "apple.com",
  "w3.org",
  "stratoserver.net",
  "radix.support",
  "freshemail.io",
  "freshdesk.com",
  "icann.org",
  "zohomail.com",
  "scamsurvivors.com",
  "zerofoxtakedowns.com",
  "takedownreporting.com",
  "wipo.int",
  "zerofox.com",
  "namecheaphosting.com",
  "office365.com",
  "enom.com",
  "mxrecord.io",
  "acidtool.com",
  "yahoo.co.uk",
  "engagement.ai",
  "withheldforprivacy.com",
  "legalmail.it",
  "nic.art",
  "mailgun.net",
  "fonts.googleapis.com",
  "gstatic.com",
  "amazonaws.com",
  "facebook.com",
  "linkedin.com",
  "tiktok.com",
  "salesforce.com",
  "registrar-servers.com",
  "spamcop.net",
  "googlegroups.com",
  "mailinblue.com",
  "comcast.net",
  "cloudflare.com",
  "openai.com",
  "github.com",
  "wikipedia.org",
  "bbc.co.uk",
]

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
// Assumes `filteredLinksArray` is an array of domain strings (or empty).
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

function handleFetch(){
  let buttonText = document.getElementById("fetchInfo");
  buttonText.innerText = "Running...";

  if (filteredLinksArray.length === 0){
    buttonText.innerText = "No links found";
    setTimeout(() => {
      buttonText.innerText = "Fetch domains info";
    }, 1000)
    return;
  }

  let infoArray = fetchDomainInfo();
  console.log(infoArray);

  buttonText.innerText = "Fetch domains info";
}

// Handles custom checkbox toggling
function toggleCheckbox(id){

  let el = document.getElementById(id);
  if (el.classList.contains("parser__options__checkModule__vis-checkbox--checked")) {
    console.log("removed");
    el.classList.remove("parser__options__checkModule__vis-checkbox--checked");
  } else {
    console.log("added");
    el.classList.add("parser__options__checkModule__vis-checkbox--checked");
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
