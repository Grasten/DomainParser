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

async function handleDigQuery() {
  const button = document.getElementById("runDig");
  button.innerText = "Running...";

  const domains = filteredLinksArray || [];
  if (!domains.length) {
    button.innerText = "No domains parsed";
    setTimeout(() => (button.innerText = "Run dig query"), 1000);
    return;
  }

  const selectedTypeElems = document.querySelectorAll(
    "#digTypeSelector input[type='checkbox']:checked"
  );
  const types = Array.from(selectedTypeElems).map((input) => input.value);
  const showRawA = document.getElementById("showRawDigA")?.checked ?? false;
  const enableIPWhois = document.getElementById("enableIPWhois")?.checked ?? true;

  const whoisCache = new Map();

  async function fetchIPWhois(ip) {
    if (whoisCache.has(ip)) return whoisCache.get(ip);
    try {
      const res = await fetch(`https://grasten.org/api/whois.php`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ targets: [ip] })
      });
      const json = await res.json();
      const result = json[ip] || null;
      whoisCache.set(ip, result);
      return result;
    } catch (e) {
      whoisCache.set(ip, null);
      console.error(e);
      return null;
    }
  }

  function getOrganizationName(info) {
    if (!info || typeof info !== "object") return "Unknown org";

    // 1. Top-level fields (fallbacks)
    const basic =
      info.organization ||
      info.orgName ||
      info.name ||
      info.autonomousSystemOrganization;

    // 2. Prioritize first "registrant" entity's vCard "fn"
    const entity = info.entities?.find(e => e.roles?.includes("registrant"));
    const fn = entity?.vcardArray?.[1]?.find(v => v[0] === "fn")?.[3];

    return fn || basic || "Unknown org";
  }


  try {
    const res = await fetch("https://grasten.org/api/dig.php", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        domains: domains,
        types: types,
        trace: false
      })
    });

    const data = await res.json();

    const entries = await Promise.all(
      Object.entries(data).map(async ([domain, recordMap]) => {
        if (typeof recordMap === "string") {
          return `=== ${domain} ===\n${recordMap}`;
        }

        const resultLines = [`=== ${domain} ===`];

        // --- A Records
        if (recordMap["A"] && !showRawA) {
          const ipMatches = Array.from(recordMap["A"].matchAll(/^.*\sIN\sA\s([\d.]+)$/gm));
          const ips = ipMatches.map((m) => m[1]);

          if (ips.length === 0) {
            resultLines.push("No IPs found");
          } else if (enableIPWhois) {
            for (const ip of ips) {
              const ipInfo = await fetchIPWhois(ip);
              const org = getOrganizationName(ipInfo);
              resultLines.push(`${ip} owned by ${org}`);
            }
          } else {
            resultLines.push(...ips);
          }
        } else if (recordMap["A"] && showRawA) {
          resultLines.push(recordMap["A"]);
        }

        // ⬇️ Add spacing only if NS is selected
        if (types.includes("NS")) {
          resultLines.push(""); // blank line before NS section
        }

        // --- NS Records
        if (recordMap["NS"]) {
          const lines = recordMap["NS"].split("\n");
          const nsList = [];
          const domainDot = domain.endsWith(".") ? domain : domain + ".";

          let inAnswer = false;
          for (const line of lines) {
            if (line.includes("ANSWER SECTION:")) {
              inAnswer = true;
              continue;
            }

            if (inAnswer) {
              if (line.trim() === "" || line.startsWith(";;")) break;

              const parts = line.trim().split(/\s+/);
              if (
                parts.length >= 5 &&
                parts[0].toLowerCase() === domainDot.toLowerCase() &&
                parts[3].toUpperCase() === "NS"
              ) {
                nsList.push(parts[4].replace(/\.$/, ""));
              }
            }
          }

          if (nsList.length) {
            resultLines.push(...nsList);
          } else {
            resultLines.push("No nameservers found");
          }
        }

        // --- MX Records
        const mxMatches = recordMap["MX"]
          ? Array.from(recordMap["MX"].matchAll(/^.*\sIN\sMX\s\d+\s([a-z0-9.-]+)\.?$/gmi))
          : [];

        if (types.includes("MX")) {
          resultLines.push(""); // spacing before MX
          if (mxMatches.length) {
            const mxs = mxMatches.map((m) => m[1]);
            resultLines.push("MX:");
            resultLines.push(...mxs);
          } else {
            resultLines.push("No mail servers found");
          }
        }

        return resultLines.join("\n");
      })
    );

    document.getElementById("parserOutput").value = entries.join("\n\n");
    document.getElementById("parserOutputCounter").innerText = `Number of dig results: ${domains.length}`;
    button.innerText = "Run dig query";
  } catch (err) {
    console.error("dig query failed", err);
    button.innerText = "Failed";
    setTimeout(() => (button.innerText = "Run dig query"), 1000);
  }
}

async function handleWhoisQuery() {
  const button = document.getElementById("runWhois");
  button.innerText = "Running...";

  const domains = filteredLinksArray || [];
  if (!domains.length) {
    button.innerText = "No domains parsed";
    setTimeout(() => button.innerText = "Run WHOIS Query", 1000);
    return;
  }

  try {
    const res = await fetch("https://grasten.org/api/whois.php", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ targets: domains })
    });

    const data = await res.json();
    console.log("WHOIS (RDAP) results", data);

    // Format structured RDAP response into a readable string
    document.getElementById("parserOutput").value = Object.entries(data)
      .map(([domain, info]) => {
        if (typeof info === "string") return `=== ${domain} ===\n${info}`;

        // Extract registrar
        let registrar = "N/A";
        if (info.entities && Array.isArray(info.entities)) {
          const registrarEntity = info.entities.find(entity =>
            entity.roles?.includes("registrar") && entity.vcardArray
          );

          if (registrarEntity?.vcardArray?.[1]) {
            const nameCard = registrarEntity.vcardArray[1].find(entry => entry[0] === "fn");
            if (nameCard) registrar = nameCard[3];
          }
        }

        // Extract creation date
        let created = "N/A";
        if (info.events && Array.isArray(info.events)) {
          const creationEvent = info.events.find(event => event.eventAction === "registration");
          if (creationEvent?.eventDate) {
            created = new Date(creationEvent.eventDate).toISOString().split("T")[0];
          }
        }

        const status = info.status?.join(", ") ?? "N/A";
        const ns = info.nameservers?.map(ns => ns.ldhName).join(", ") ?? "N/A";

        return `=== ${domain} ===
Registrar: ${registrar}
Created: ${created}
Status: ${status}
Nameservers: ${ns}`;
      })
      .join("\n\n");
    document.getElementById("parserOutputCounter").innerText = `Number of WHOIS (RDAP) results: ${domains.length}`;
    button.innerText = "Run WHOIS Query";
  } catch (err) {
    console.error("WHOIS query failed", err);
    button.innerText = "Failed";
    setTimeout(() => button.innerText = "Run WHOIS Query", 1000);
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
export { copyCommand, handleDigQuery, handleWhoisQuery };
