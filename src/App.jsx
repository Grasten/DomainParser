import './App.scss'
import {cleanDomains, openDomains} from "./utils.js";

function App() {

  return (
    <>
      <link rel="preconnect" href="https://fonts.googleapis.com"/>
      <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="true"/>
      <link href="https://fonts.googleapis.com/css2?family=Bebas+Neue&family=Fleur+De+Leah&display=swap"
            rel="stylesheet"/>
      <div className="parser">
        <div className="parser__topbar">
          <h1 className="parser__topbar__title font-bebas">Glorious domain parser</h1>
          <div className="parser__topbar__inputs">
            <label htmlFor="parserInput" className="parser__topbar__inputs__label"></label>
            <textarea className="parser__topbar__inputs__input parser-fields" id="parserInput"></textarea>
          </div>
          <div className="parser__topbar__buttons">
              <button className="parser__topbar__buttons__button" onClick={cleanDomains}>Get domains</button>
            <button className="parser__topbar__buttons__button" onClick={openDomains}>Open domains</button>
            <button className="parser__topbar__buttons__button" onClick={cleanDomains}>Clean</button>
            <button className="parser__topbar__buttons__button" onClick={openDomains}>Open</button>
          </div>
        </div>
        <label>
          <textarea className="parser__output parser-fields" id="parserOutput"></textarea>
          <p className="parser__output__counter" id="parserOutputCounter"></p>
        </label>
      </div>
    </>
  )
}

export default App
