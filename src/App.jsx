import './App.scss'
import {parseDomains, openParsedDomains, findTargets, copyCommand, handleDigQuery, handleWhoisQuery} from "./utils.js";

function App() {

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

              <button className="parser__topbar__buttons__button parser__topbar__buttons__openbox__button" id="runDig"
                      onClick={handleDigQuery}>Run Dig Query
              </button>

              <fieldset id="digTypeSelector" className="parser__options__checkModule">
                <legend>dig types:</legend>
                <label><input type="checkbox" value="A" defaultChecked/> A</label>
                <label><input type="checkbox" value="MX" defaultChecked/> MX</label>
                <label><input type="checkbox" value="NS" defaultChecked/> NS</label>
              </fieldset>

              <button className="parser__topbar__buttons__button parser__topbar__buttons__openbox__button" id="runWhois"
                      onClick={handleWhoisQuery}>Run WHOIS Query
              </button>

              <label className="parser__options__checkModule">
                MX IP owners:
                <input type="checkbox" id="enableMXWhois"/>
              </label>

            </div>

          </div>
        </div>

        <div className="parser__options">

          <label htmlFor="checkboxSkip" className="parser__options__checkModule">
            Skip common domains (e.g. google.com):
            <input defaultChecked="true" type="checkbox" className="parser__options__checkModule__checkbox"
                   id="checkboxSkip"
                   onChange={() => {
                     let el = document.getElementById("checkboxSkipVis");
                     if (el.classList.contains("parser__options__checkModule__vis-checkbox--checked")) {
                el.classList.remove("parser__options__checkModule__vis-checkbox--checked");
              } else {
                el.classList.add("parser__options__checkModule__vis-checkbox--checked");
              }
            }
            }
            />
            <div className="parser__options__checkModule__vis-checkbox parser__options__checkModule__vis-checkbox--checked"
                 id="checkboxSkipVis">
              <svg height="100%" width="100%" version="1.1" id="Capa_1" xmlns="http://www.w3.org/2000/svg" xmlnsXlink="http://www.w3.org/1999/xlink"
                   viewBox="0 0 32 32" xmlSpace="preserve">
                    <polygon points="11.941,28.877 0,16.935 5.695,11.24 11.941,17.486 26.305,3.123 32,8.818"/>
              </svg>
            </div>
          </label>

          <div className="parser__options__filter parser__options__general">
            <p className="parser__options__filter__title">Filter:</p>
            <input type="text" className="parser__options__filter__input parser-fields" autoComplete="false" id="filterInput"/>
          </div>

          {/*<div className="parser__options__general">
            Reset input on
            <label htmlFor="checkboxResetOnParse" className="parser__options__checkModule">
              parse:
              <input type="checkbox" className="parser__options__checkModule__checkbox" id="checkboxResetOnParse"
                     onChange={() => {
                       let el = document.getElementById("checkboxResetOnParseVis");
                       if (el.classList.contains("parser__options__checkModule__vis-checkbox--checked")) {
                         el.classList.remove("parser__options__checkModule__vis-checkbox--checked");
                       } else {
                         el.classList.add("parser__options__checkModule__vis-checkbox--checked");
                       }
                     }
                     }
              />
              <div className="parser__options__checkModule__vis-checkbox"
                   id="checkboxResetOnParseVis">
                <svg height="100%" width="100%" version="1.1" id="Capa_1" xmlns="http://www.w3.org/2000/svg" xmlnsXlink="http://www.w3.org/1999/xlink"
                     viewBox="0 0 32 32" xmlSpace="preserve">
                  <polygon points="11.941,28.877 0,16.935 5.695,11.24 11.941,17.486 26.305,3.123 32,8.818"/>
                </svg>
              </div>
            </label>
            <label htmlFor="checkboxResetOnOpen" className="parser__options__checkModule">
              open:
              <input type="checkbox" className="parser__options__checkModule__checkbox" id="checkboxResetOnOpen"
                     onChange={() => {
                       let el = document.getElementById("checkboxResetOnOpenVis");
                       if (el.classList.contains("parser__options__checkModule__vis-checkbox--checked")) {
                         el.classList.remove("parser__options__checkModule__vis-checkbox--checked");
                       } else {
                         el.classList.add("parser__options__checkModule__vis-checkbox--checked");
                       }
                     }
                     }
              />
              <div className="parser__options__checkModule__vis-checkbox"
                   id="checkboxResetOnOpenVis">
                <svg height="100%" width="100%" version="1.1" id="Capa_1" xmlns="http://www.w3.org/2000/svg" xmlnsXlink="http://www.w3.org/1999/xlink"
                     viewBox="0 0 32 32" xmlSpace="preserve">
                  <polygon points="11.941,28.877 0,16.935 5.695,11.24 11.941,17.486 26.305,3.123 32,8.818"/>
                </svg>
              </div>
            </label>
          </div>*/}

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
