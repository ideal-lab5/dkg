/* global BigInt */

import logo from './logo.svg';
import './App.css';
import { keygen } from 'dkg';
import { useEffect } from 'react';

function App() {

  useEffect(() => {
    // init().then(() => {
      // keygen(BigInt(23), 3);
    // });
  }, []);

  return (
    <div className="App">
      <div>
        <h2>DKG Wasm Example</h2>
      </div>
    </div>
  );
}

export default App;
