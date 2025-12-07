import './App.scss'
import {parseDomains, openParsedDomains, findTargets, handleFetch, toggleCheckbox, reparse} from "./utils.js";

function App() {

  let customCheckboxSVG = (<svg height="100%" width="100%" version="1.1" id="Capa_1" xmlns="http://www.w3.org/2000/svg" xmlnsXlink="http://www.w3.org/1999/xlink"
                   viewBox="0 0 32 32" xmlSpace="preserve">
                    <polygon points="11.941,28.877 0,16.935 5.695,11.24 11.941,17.486 26.305,3.123 32,8.818"/>
              </svg>);
//  const INCLUDE_OPTIONS = ['Reg_date', 'IP', 'IP_org', 'NS', 'MX', 'MX_org', 'IsSusp', 'Regist', 'HasContent'];
  const INCLUDE_OPTIONS = [
    {param: "Reg_date", name: "Reg Date", defaultChecked: true, method: "whois"},
    {param: "NS", name: "Nameservers", defaultChecked: true, method: "whois"},
    {param: "IP", name: "IP", defaultChecked: true, method: "dig"},
    {param: "IP_org", name: "IP org", defaultChecked: true, method: "addwhois"},
    {param: "MX", name: "MX records", defaultChecked: true, method: "dig"},
    {param: "MX_org", name: "MX org", defaultChecked: true, method: "addwhois"},
    {param: "IsSusp", name: "Is suspended", defaultChecked: true, method: "whois"},
    {param: "Regist", name: "Registry", defaultChecked: true, method: "whois"},
    {param: "HasContent", name: "Has content", defaultChecked: false, group: "curl"},
  ];
  const SECONDARY_OPTIONS = [
    {param: "SecondaryAND", name: "Use AND", defaultChecked: false},
    {param: "RegWithUs", name: "Reg with us", defaultChecked: false},
    {param: "RegUnclear", name: "Reg unclear", defaultChecked: false},
    {param: "NotReg", name: "Not registered", defaultChecked: false},
    {param: "UseOurMail", name: "Our mail", defaultChecked: false},
    {param: "HostedWithUs", name: "Hosted", defaultChecked: false},
    {param: "NotSuspended", name: "Not Suspended", defaultChecked: false},
  ];

  function renderCheckboxes(options) {
    let tempArray = [];
    options.map((opt) => {
      const inputId = `checkbox${opt.param}`;
      const visId = `checkbox${opt.param}Vis`;
      tempArray.push (
        <label key={opt.param} htmlFor={inputId} className="parser__options__checkModule">
          {opt.name}:
          <input
            type="checkbox"
            defaultChecked={opt.defaultChecked}
            value={opt.param}
            className="parser__options__checkModule__checkbox"
            id={inputId}
            onChange={(e) => toggleCheckbox(visId, e.target.checked)}
          />
          <div
            className={`parser__options__checkModule__vis-checkbox 
            ${opt.defaultChecked ? "parser__options__checkModule__vis-checkbox--checked" : ""}`}
            id={visId}
          >
            {customCheckboxSVG}
          </div>
        </label>
      );
    })
    return tempArray;
  }

  return (
    <>
      <link rel="preconnect" href="https://fonts.googleapis.com"/>
      <link rel="preconnect" href="https://fonts.gstatic.com"/>
      <link
        href="https://fonts.googleapis.com/css2?family=Bebas+Neue&family=Martian+Mono:wght@600&family=Roboto+Mono&display=swap"
        rel="stylesheet"/>
      <div className="parser">

        <div className="parser__topbar">
          <div className="parser__topbar__container">
            <h1 className="parser__topbar__container__title font-bebas">
              Domain parser
              <span className="parser__topbar__container__title__version">ver: 0.5: API adventures</span>
            </h1>
            <button className="parser__topbar__container__theme"
                    onClick={() => {
                      let el = document.getElementsByClassName("parser")[0];
                      if (el.classList.contains("parser--dark")) {
                        el.classList.remove("parser--dark");
                        document.getElementById("root").classList.remove("dark");
                        document.getElementsByClassName("parser__topbar__container__theme")[0].innerText = "dark";
                      } else {
                        el.classList.add("parser--dark");
                        document.getElementById("root").classList.add("dark");
                        document.getElementsByClassName("parser__topbar__container__theme")[0].innerText = "light";
                      }
                    }
                    }
            >light</button>
          </div>

          <div className="parser__topbar__inputs">
            <label htmlFor="parserInput" className="parser__topbar__inputs__label"></label>
            <div className="parser__topbar__inputs__box">
              <button className="parser__topbar__inputs__box__clear"
                      onClick={() => document.getElementById("parserInput").value = ""}>Clear</button>
              <textarea spellCheck="false" className="parser__topbar__inputs__box__input parser-fields" id="parserInput"
                        defaultValue=""></textarea>
            </div>

          </div>
          <div className="parser__topbar__buttons">
            <div className="parser__topbar__buttons__parsebox">
              <button className="parser__topbar__buttons__parsebox__button parser__topbar__buttons__button" id="parseDomains"
                      onClick={()=> parseDomains("domain")}>Parse domains</button>

              <button className="parser__topbar__buttons__parsebox__button parser__topbar__buttons__button" id="parseHostnames"
                      onClick={()=> parseDomains("hostname")}>Parse hostnames</button>

              <button className="parser__topbar__buttons__parsebox__button parser__topbar__buttons__button" id="parseURLs"
                      onClick={()=> parseDomains("url")}>Parse URLs</button>

              <button className="parser__topbar__buttons__parsebox__button parser__topbar__buttons__button" id="reparseReg"
                      onClick={()=> reparse("Regist", "RegWithUs")}>Reparse registered</button>

              <button className="parser__topbar__buttons__parsebox__button parser__topbar__buttons__button" id="reparseReg"
                      onClick={()=> reparse("IsSusp", "NotSuspended")}>Reparse not suspended</button>

              {/*<div className="parser__topbar__buttons__button parser__topbar__buttons__split
              parser__topbar__buttons__openbox__button" id="parseOpen">
                <button className="parser__topbar__buttons__button" id="getwhois"
                        onClick={() => copyCommand("whois")}>Copy bulk Whois
                </button>
                <button className="parser__topbar__buttons__button" id="getdig"
                        onClick={() => copyCommand("dig")}>Copy bulk {<br/>} dig
                </button>
              </div>*/}

              <fieldset id="secondarySelector" className="parser__topbar__buttons__fieldset">
                <p>Output filters</p>
                {renderCheckboxes(SECONDARY_OPTIONS)}
              </fieldset>

            </div>

            <div className="parser__topbar__buttons__openbox">
              <button className="parser__topbar__buttons__button parser__topbar__buttons__openbox__button"
                      id="openLinks"
                      onClick={openParsedDomains}>Open parsed links
              </button>

              <button className="parser__topbar__buttons__button parser__topbar__buttons__openbox__button"
                      id="openTargets"
                      onClick={findTargets}>Find possible targets
              </button>

              <button className="parser__topbar__buttons__button parser__topbar__buttons__openbox__button"
                      id="fetchInfo"
                      onClick={handleFetch}>Fetch domains info
              </button>

              <fieldset id="infoTypeSelector" className="parser__topbar__buttons__fieldset">
                <p>Fetch Options</p>
                {renderCheckboxes(INCLUDE_OPTIONS)}
              </fieldset>
            </div>
          </div>
        </div>

        <div className="parser__options">

          <label htmlFor="checkboxSkip" className="parser__options__checkModule">
            Skip common domains:
            <input defaultChecked="true" type="checkbox" className="parser__options__checkModule__checkbox"
                   id="checkboxSkip"
                   onChange={() => toggleCheckbox("checkboxSkipVis")}
            />
            <div
              className="parser__options__checkModule__vis-checkbox parser__options__checkModule__vis-checkbox--checked"
              id="checkboxSkipVis">
              {customCheckboxSVG}
            </div>
          </label>

          <div className="parser__options__filter parser__options__general">
            <p className="parser__options__filter__title">Filter:</p>
            <input type="text" className="parser__options__filter__input parser-fields" autoComplete="false" id="filterInput"/>
          </div>

          <div className="parser__options__filter parser__options__general">
            <p className="parser__options__filter__title">Output Filter:</p>
            <input type="text" className="parser__options__filter__input parser-fields" autoComplete="false" id="filterOutput"/>
          </div>

          <label htmlFor="checkboxParseURLsHostnames" className="parser__options__checkModule">
            Parse URLs include hostnames:
            <input defaultChecked="true" type="checkbox" className="parser__options__checkModule__checkbox"
                   id="checkboxParseURLsHostnames"
                   onChange={() => toggleCheckbox("checkboxParseURLsHostnamesVis")}
            />
            <div
              className="parser__options__checkModule__vis-checkbox parser__options__checkModule__vis-checkbox--checked"
              id="checkboxParseURLsHostnamesVis">
              {customCheckboxSVG}
            </div>
          </label>

        </div>

        <label>
          <textarea spellCheck="false" className="parser__output parser-fields" id="parserOutput"></textarea>
        </label>
        <p className="parser__output__counter" id="parserOutputCounter">Number of links:</p>

      </div>
    </>
  )
}

export default App
