import './App.scss'
import {parseDomains, openParsedDomains, findTargets, copyCommand, handleFetch, toggleCheckbox} from "./utils.js";

function App() {

  let customCheckboxSVG = (<svg height="100%" width="100%" version="1.1" id="Capa_1" xmlns="http://www.w3.org/2000/svg" xmlnsXlink="http://www.w3.org/1999/xlink"
                   viewBox="0 0 32 32" xmlSpace="preserve">
                    <polygon points="11.941,28.877 0,16.935 5.695,11.24 11.941,17.486 26.305,3.123 32,8.818"/>
              </svg>);
  const INCLUDE_OPTIONS = ['Reg_date', 'IP', 'IP_org', 'NS', 'MX', 'MX_org', 'IsSusp', 'Regist'];

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
              <span className="parser__topbar__container__title__version">ver: 0.4.2</span>
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
              <textarea className="parser__topbar__inputs__box__input parser-fields" id="parserInput"
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

              <div className="parser__topbar__buttons__button parser__topbar__buttons__split
              parser__topbar__buttons__openbox__button" id="parseOpen">
                <button className="parser__topbar__buttons__button" id="getwhois"
                        onClick={() => copyCommand("whois")}>Copy bulk Whois
                </button>
                <button className="parser__topbar__buttons__button" id="getdig"
                        onClick={() => copyCommand("dig")}>Copy bulk {<br/>} dig
                </button>
              </div>

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
                {INCLUDE_OPTIONS.map((opt) => {
                  const inputId = `checkbox${opt}`;
                  const visId = `checkbox${opt}Vis`;
                  return (
                    <label key={opt} htmlFor={inputId} className="parser__options__checkModule">
                      {opt}:
                      <input
                        type="checkbox"
                        defaultChecked
                      value={opt}
                      className="parser__options__checkModule__checkbox"
                      id={inputId}
                      onChange={(e) => toggleCheckbox(visId, e.target.checked)}
                      />
                      <div
                        className="parser__options__checkModule__vis-checkbox parser__options__checkModule__vis-checkbox--checked"
                        id={visId}
                      >
                        {customCheckboxSVG}
                      </div>
                    </label>
                  );
                })}
              </fieldset>
            </div>
          </div>
        </div>

        <div className="parser__options">

          <label htmlFor="checkboxSkip" className="parser__options__checkModule">
            Skip common domains (e.g. google.com):
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

        </div>

        <label>
          <textarea className="parser__output parser-fields" id="parserOutput"></textarea>
        </label>
        <p className="parser__output__counter" id="parserOutputCounter">Number of links:</p>

      </div>
    </>
  )
}

export default App
