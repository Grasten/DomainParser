import { parse } from 'tldts';
import linkifyit from 'linkify-it';
const linkify = linkifyit();
import tlds from 'tlds';
linkify.tlds(tlds)

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
    if (el.isIcann){

      //exception so that it.com is treated as a tld and not as a domain
      if (el.domain === "it.com"){
        el.domain = el.hostname.match(/\w*.it.com/gm)[0];
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
    let el = parse(domain.text)
    if (el.isIcann){
      tempArray.push(domain.text);
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
    filteredLinksArray.forEach((el) => {
      (linkify.match(el)[0]).schema ? window.open(`${el}`) : window.open(`https://${el}`);
    })
}

// Searches for targets on Google
export function findTargets(){
    filteredLinksArray.forEach((el) => {
      window.open(`https://www.google.com/search?q=${el}`);
    })
}

// Copies to clipboard command from the template
export async function copyCommand(type){
  let domains = getDomains("domain").filteredLinksArray;
  if (!domains[0]) return;

  let tempDomains = "", text = "";
  if (type === "whois"){
    try {
      domains.forEach((domain, index) => {
        let line = `${domain}${index === domains.length-1 ? "" : "\n"}`;
        tempDomains += (line);
      })
      text = (`declare -a testStatus=(${tempDomains})` + "\nfor i in ${testStatus[*]}; do echo -e $i: `whois $i |grep 'Status:'`; done");
      console.log(text);
      await navigator.clipboard.writeText(text);
    }
    catch (e) {console.log(e)}
  }
}
