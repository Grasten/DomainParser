import { parse } from 'tldts';
import linkifyit from 'linkify-it';
const linkify = linkifyit();
import tlds from 'tlds';
linkify.tlds(tlds)

let filteredLinksArray = [];
const regBracketDotText = /(\s?\W\s?)dot(\s?\W\s?)/ig;
const regBracketDot = /(\s?\W\s?)\.(\s?\W\s?)/ig;
const regDomains = /(?<=^|[^a-z0-9])((?:[a-z0-9-]+\.)+[a-z]{2,})(?=[^a-z0-9]|$)/gi;
const regHttps = /hxxps\s*\[?\s*?:\s*?]?\s*\/{1,2}\s*/gi;
const regHttp = /hxxp\s*\[?\s*?:\s*?]?\s*\/{1,2}\s*/gi;
const mailerDomains = [
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
]

// --- BASE FUNCTIONS ---

// Returns input text with basic parsing (brackets, protocols)
function getInputText(){
  // Get domains from input
  let worklist = document.getElementById("parserInput").value;

  // Remove brackets, fix protocols
  worklist = worklist.replace(regBracketDot, ".");
  worklist = worklist.replace(regBracketDotText, ".");
  worklist = worklist.replace(regHttps, "https://");
  worklist = worklist.replace(regHttp, "http://");
  return worklist;
}

// Returns an array of verified domains from input
function getDomains(type) {
  // Get text from input
  let worklist = getInputText();

  // Search for links in text
  worklist = worklist.match(regDomains) || [];

  // Set them in array with unique values
  worklist = [...new Set(worklist)];

  // Validate domains and remove invalid
  let tempArray = [];

  worklist.forEach((domain) => {
    let el = parse(domain)
    if (el.isIcann){
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

  // If ignore mailers enabled, filter the array for it and update worklist
  if (document.getElementById("checkboxMail").checked){
    let tempArray = [];
    links.filteredLinksArray.forEach((domain) => {
      let mailerDetected, el = domain;
      mailerDomains.forEach(mailer => {
        if (el.match(`${mailer}`)){
          mailerDetected = true;
        }
      })
      if(!mailerDetected){tempArray.push(el)}
    });

    links.filteredLinksArray = [...new Set(tempArray)];
    links.worklist = createListFromArray(links.filteredLinksArray);
  }

  // Set values to front-end
  document.getElementById("parserOutput").value = links.worklist;
  document.getElementById("parserOutputCounter").innerText = `Number of links: ${links.filteredLinksArray.length}`;
}


// Opens parsed domains, can parse them first if needed
export function openParsedDomains(){
  // Check if there are parsed links
  if (document.getElementById("parserOutput").value) {
    filteredLinksArray.forEach((el) => {
      (linkify.match(el)[0]).schema ? window.open(`${el}`) : window.open(`https://${el}`);
    })
  } else {
    // If no links parsed, parse hostnames and open
    parseDomains("hostname");
    filteredLinksArray.forEach((el) => {
      (linkify.match(el)[0]).schema ? window.open(`${el}`) : window.open(`https://${el}`);
    })
  }
}

export function findTargets(){
  // Check if there are parsed links
  if (document.getElementById("parserOutput").value) {
    filteredLinksArray.forEach((el) => {
      window.open(`https://www.google.com/search?q=${el}`);
    })
  } else {
    // If no links parsed, parse hostnames and open
    parseDomains("domain");
    filteredLinksArray.forEach((el) => {
      window.open(`https://www.google.com/search?q=${el}`);
    })
  }
}
