import './App.scss'
import {parseDomains, openParsedDomains, findTargets} from "./utils.js";

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
          <h1 className="parser__topbar__title font-bebas">
            Domain parser
            <span className="parser__topbar__title__version">ver: 0.3</span>
          </h1>
          <div className="parser__topbar__inputs">
            <label htmlFor="parserInput" className="parser__topbar__inputs__label"></label>
            <textarea className="parser__topbar__inputs__input parser-fields" id="parserInput"
                      defaultValue=""></textarea>
          </div>
          <div className="parser__topbar__buttons">
            <div className="parser__topbar__buttons__parsebox">
              <button className="parser__topbar__buttons__parsebox__button parser__topbar__buttons__button" id="parseDomains"
                      onClick={()=> parseDomains("domain")}>Parse domains</button>

              <button className="parser__topbar__buttons__parsebox__button parser__topbar__buttons__button" id="parseHostnames"
                      onClick={()=> parseDomains("hostname")}>Parse hostnames</button>

              <button className="parser__topbar__buttons__parsebox__button parser__topbar__buttons__button" id="parseURLs"
                      onClick={()=> parseDomains("url")}>Parse URLs</button>
            </div>

            <div className="parser__topbar__buttons__openbox">
              <button className="parser__topbar__buttons__button parser__topbar__buttons__openbox__button" id="parseOpen"
                      onClick={() => openParsedDomains()}>Open parsed links</button>

              <button className="parser__topbar__buttons__button parser__topbar__buttons__openbox__button" id="parseOpen"
                      onClick={() => findTargets()}>Find possible targets</button>
            </div>

          </div>
        </div>

        <div className="parser__options">
          <label htmlFor="checkboxMail" className="parser__options__mail">
            Ignore mailer domains (e.g. gmail.com):
            <input type="checkbox" className="parser__options__mail__checkbox" id="checkboxMail"
            onChange={() => {
              let el = document.getElementById("checkboxMailVis");
              if (el.classList.contains("parser__options__mail__vis-checkbox--checked")) {
                el.classList.remove("parser__options__mail__vis-checkbox--checked");
              } else {
                el.classList.add("parser__options__mail__vis-checkbox--checked");
              }
            }
            }
            />
            <div className="parser__options__mail__vis-checkbox" id="checkboxMailVis">
              <svg height="100%" width="100%" version="1.1" id="Capa_1" xmlns="http://www.w3.org/2000/svg" xmlnsXlink="http://www.w3.org/1999/xlink"
                   viewBox="0 0 32 32" xmlSpace="preserve">
                    <polygon points="11.941,28.877 0,16.935 5.695,11.24 11.941,17.486 26.305,3.123 32,8.818"/>
              </svg>
            </div>
          </label>

          <div className="parser__options__filter">
            <p className="parser__options__filter__title">Filter:</p>
            <input type="text" className="parser__options__filter__input" autoComplete="false" id="filterInput"/>
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
