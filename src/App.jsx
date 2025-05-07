import './App.scss'
import {parseDomains, openParsedDomains} from "./utils.js";

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
            <span className="parser__topbar__title__version">ver: 0.2</span>
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
              <div className="parser__topbar__buttons__openbox__filter">
                <p className="parser__topbar__buttons__openbox__filter__title">Filter for pattern:</p>
                <input type="text" className="parser__topbar__buttons__openbox__filter__input" id="filterInput"/>
              </div>

            </div>

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
