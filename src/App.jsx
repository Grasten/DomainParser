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
            <span className="parser__topbar__title__version">ver: 0.1</span>
          </h1>
          <div className="parser__topbar__inputs">
            <label htmlFor="parserInput" className="parser__topbar__inputs__label"></label>
            <textarea className="parser__topbar__inputs__input parser-fields" id="parserInput"
                      defaultValue="hXXps://domain [.] com/
Domain TLD Source Category Suspension Date quaes[dot]store store Google Safe Browsing Social
Engineering 2025-04-06 12:57:48 soulvibe[dot]store store Netcraft Scam 2025-04-06 14:00:42
https://bradford.sttzik.icu/Xf?xf9=26-90
                      ">

            </textarea>
          </div>
          <div className="parser__topbar__buttons">
            <button className="parser__topbar__buttons__button" onClick={()=> parseDomains("domain")}>Parse domains</button>
            <button className="parser__topbar__buttons__button" onClick={openParsedDomains}>Open parsed links</button>
            <button className="parser__topbar__buttons__button" onClick={()=> parseDomains("hostname")}>Parse hostnames</button>
            <button className="parser__topbar__buttons__button" onClick={()=> parseDomains("url")}>Parse URLs</button>
            <button className="parser__topbar__buttons__button" onClick={()=> console.clear()}>clear</button>
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
