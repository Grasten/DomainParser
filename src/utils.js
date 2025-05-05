import LinkifyIt from 'linkify-it';
import tlds from 'tlds';

const linkify = new LinkifyIt();
linkify.set({fuzzyEmail: false})
linkify.tlds(tlds)

let rawDomains, filteredDomainsString, filteredDomainsArray = [];
const regBracketDot = /(\s?\W\s?\.\s?\W\s?)?(\s?\W\s?)dot(\s?\W\s?)?/ig;
const regBracketDotText = /(\s?\W\s?\.\s?\W\s?)?(\s?\W\s?)\.(\s?\W\s?)?/ig;
//const regTld = /(\w{2,}\.\w{2,})(\.\w{1,2})?/g;

function removeBrackets(el){
  el = el.replace(regBracketDot, ".");
  el = el.replace(regBracketDotText, ".");
  console.log(el, "brackets");
  return el;
}

function uniq(a) {
  const seen = {};
  return a.filter(function(item) {
    return Object.prototype.hasOwnProperty.call(seen, item) ? false : (seen[item] = true);
  });
}

function getDomainsArray(domainString){
  linkify.match(domainString).forEach((domain) => {
    console.log(domain, "domain");
    filteredDomainsArray.push(domain.text);
  });
  filteredDomainsArray = uniq(filteredDomainsArray)
  console.log(filteredDomainsArray, "filteredDomainsArray");
  return filteredDomainsArray;
}

function createListFromArray(domainArray){
  let i = domainArray.length -1;
  let domainList = "";
  domainArray.forEach((domain) => {
    domainList+= `${domain}${i!==0?"\n":""}`;
    i--;
  })
  console.log(domainList, "domainList");
  return domainList;
}

export function cleanDomains(){
  console.log(linkify.match("/something.org"), "test match");
  rawDomains = document.getElementById("parserInput").value;
  filteredDomainsArray = [];
  if (rawDomains !== null) {
    filteredDomainsString = createListFromArray(getDomainsArray(removeBrackets(rawDomains)));
    document.getElementById("parserOutput").value = filteredDomainsString;
    document.getElementById("parserOutputCounter").innerText = `Number of domains: ${filteredDomainsArray.length}`;
  }
}

export function openDomains() {
  cleanDomains();
  if (filteredDomainsString !== null) {
    filteredDomainsArray.forEach((el) => {
      window.open(`https://${el}`);
    })
  }
}
