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
          <h1 className="parser__topbar__title font-bebas">Glorious domain parser</h1>
          <div className="parser__topbar__inputs">
            <label htmlFor="parserInput" className="parser__topbar__inputs__label"></label>
            <textarea className="parser__topbar__inputs__input parser-fields" id="parserInput"></textarea>
          </div>
          <div className="parser__topbar__buttons">
            <button className="parser__topbar__buttons__button" onClick={()=> parseDomains("domain")}>Parse domains</button>
            <button className="parser__topbar__buttons__button" onClick={openParsedDomains}>Open parsed links</button>
            <button className="parser__topbar__buttons__button" onClick={()=> parseDomains("hostname")}>Parse hostnames</button>
            <p className="parser__topbar__buttons__note">"Open parsed links" will open hostnames by default if nothing is parsed</p>
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
