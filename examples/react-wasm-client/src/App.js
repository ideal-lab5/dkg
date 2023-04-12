/* global BigInt */
import './App.css';
import { useEffect } from 'react';
// import { useWasm } from './useWasm';
// import { keygen } from 'dkg';
import * as wasm from "dkg";


function App() {

  // const instance = useWasm();

  return (
    <div className="App">
      <div>
        <h2>DKG Wasm Example</h2>
      </div>
      <div>
        { wasm.keygen(BigInt(2), 3, BigInt(3), BigInt(3)) }
        {/* { instance && instance.exports.keygen(BigInt(2), 3, BigInt(4), BigInt(5)) } */}
      </div>
    </div>
  );
}

export default App;
