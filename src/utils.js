//import LinkifyIt from 'linkify-it';
//import tlds from 'tlds';
import { parse } from 'tldts';

//const linkify = new LinkifyIt();
//set({fuzzyEmail: false})
//linkify.tlds(tlds)

//let rawDomains, filteredDomainsString;
let filteredDomainsArray = [];
//const regBracketDot = /(\s?\W\s?\.\s?\W\s?)?(\s?\W\s?)\.(\s?\W\s?)?/ig;
const regBracketDotText = /(\s?\W\s?)dot(\s?\W\s?)/ig;
const regBracketDot = /(\s?\W\s?)\.(\s?\W\s?)/ig;
const regDomains = /(?<=^|[^a-z0-9])((?:[a-z0-9-]+\.)+[a-z]{2,})(?=[^a-z0-9]|$)/gi;

/*const testCases = [
  "Check this out: /google.com is cool.",
  "Visit us at www.example.org for more info.",
  "Here’s a weird one: ssomfeafqhtew$something.co.uk!",
  "What about inline?Trythisdomain.co.",
  "Go to abc.def.net and tell me what you see.",
  "Contact: email@example.com (should NOT match domain)",
  "Slash style: /sub.domain.info is often ignored.",
  "Trailing: This ends with domain.net!",
  "Leading: $$$money-site.biz is where it's at.",
  "In brackets [test-domain.co.uk] you go.",
  "URL style: https://blog.company.dev/posts",
  "Punycode style: xn--fsq.xn--0zwm56d (IDN domain)",
  "Subdomains? Try mail.portal.example.com now.",
  "MidwordlikeStringdomain.usisnotarealdomain",
  "Dot at the end: use something.ai.",
  "Wrong TLD: example.toolongtld (shouldn't match)",
  "Short TLD: check io.io or me.me",
  "Domain with dashes: go-to-this-site.com immediately.",
  "Fake URL: ftp://not.a.url.com/test.txt",
  "Sentence.with.dots.but.not.a.domain probably shouldn't match",
];*/


/*function removeBrackets(el){
  el = el.replace(regBracketDot, ".");
  el = el.replace(regBracketDotText, ".");
  return el;
}*/
/*function uniq(a) {
  const seen = {};
  return a.filter(function(item) {
    return Object.prototype.hasOwnProperty.call(seen, item) ? false : (seen[item] = true);
  });
}*/
/*function getDomainsArrayFromText(domains) {
  let domainsArray = [];
  domains.matchAll(regDomains).forEach((domain) => {
    console.log("found domain: ", domain[0]);
    domainsArray.push(domain[0]);
  });
  domainsArray = uniq(domainsArray)
  return domainsArray;
}*/
/*function getDomainsArrayFromText(domains) {
  let matches = domains.match(regDomains) || [];
  return [...new Set(matches)];
}*/
/*function getDomainsArray(domainString){
  linkify.match(domainString).forEach((domain) => {
    filteredDomainsArray.push(domain.text);
  });
  filteredDomainsArray = uniq(filteredDomainsArray)
  return filteredDomainsArray;
}*/

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

/*export function cleanDomains(){
  rawDomains = document.getElementById("parserInput").value;
  filteredDomainsArray = [];
  if (rawDomains !== null) {
    filteredDomainsString = createListFromArray(getDomainsArray(removeBrackets(rawDomains)));
    document.getElementById("parserOutput").value = filteredDomainsString;
    document.getElementById("parserOutputCounter").innerText = `Number of domains: ${filteredDomainsArray.length}`;
  }
}*/
/*export function testExtraction(){
  getUnfilteredDomains();

  rawDomains = document.getElementById("parserInput").value;
  filteredDomainsArray = [];
  if (rawDomains !== null) {
    let worklist = removeBrackets(rawDomains);
    worklist = getDomainsArrayFromText(worklist);
    filteredDomainsArray = worklist;
    // Created array of domains
    worklist = createListFromArray(worklist);

    document.getElementById("parserOutput").value = worklist;
    document.getElementById("parserOutputCounter").innerText = `Number of domains: ${filteredDomainsArray.length}`;
  }
}*/
/*export function openDomains() {
  cleanDomains();
  if (filteredDomainsString !== null) {
    filteredDomainsArray.forEach((el) => {
      window.open(`https://${el}`);
    })
  }
}*/
