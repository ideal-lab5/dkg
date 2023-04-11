import './App.css';
import { useState, useEffect } from 'react';

function App() {

  const[wasm, setWasm] = useState(null);

  useEffect(() => {
    async function set_wasm() {
      setWasm(await import("dkg/dkg.js"));
    }
    set_wasm();
  }, []);

  return (
    <div className="App">
        <div>
          DKG Wasm Example
        </div>
        <div>
          {wasm ? wasm.greet('hello') : 'wasm not loaded'}
        </div>
    </div>
  );
}

export default App;