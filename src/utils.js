import { parse } from 'tldts';

let filteredDomainsArray = [];
const regBracketDotText = /(\s?\W\s?)dot(\s?\W\s?)/ig;
const regBracketDot = /(\s?\W\s?)\.(\s?\W\s?)/ig;
const regDomains = /(?<=^|[^a-z0-9])((?:[a-z0-9-]+\.)+[a-z]{2,})(?=[^a-z0-9]|$)/gi;

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

// Returns an array of verified domains from input
function getUnfilteredDomains() {
  // Get domains from input
  let worklist = document.getElementById("parserInput").value;

  // Remove brackets
  worklist = worklist.replace(regBracketDot, ".");
  worklist = worklist.replace(regBracketDotText, ".");

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

  return(worklist);
}

// Accepts either "domain" or "hostname" as a param, sets filtered array and values to frontend
export function parseDomains(param){
  let worklist = getUnfilteredDomains();

  // Reset filtered array
  filteredDomainsArray = [];

  // Set domains into filtered array
  let tempArray = [];
  worklist.forEach((domain) => {
    tempArray.push(domain[param]);
  });
  filteredDomainsArray= [...new Set(tempArray)];

  // Get a text list from filtered array
  worklist = createListFromArray(filteredDomainsArray);

  // Set values to front-end
  document.getElementById("parserOutput").value = worklist;
  document.getElementById("parserOutputCounter").innerText = `Number of links: ${filteredDomainsArray.length}`;
}

// Opens parsed domains, can parse them first if needed
export function openParsedDomains(){
  console.log(document.getElementById("parserInput").value);
  // Check if there are parsed domains
  if (document.getElementById("parserOutput").value) {
    filteredDomainsArray.forEach((el) => {
      window.open(`https://${el}`);
    })
  } else {
    // Parse domains and open
    console.log("test")
    parseDomains("hostname");
    console.log(filteredDomainsArray)
    filteredDomainsArray.forEach((el) => {
      window.open(`https://${el}`);
    })
  }
}
