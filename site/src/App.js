import logo from './logo.svg';
import './App.css';
import { useEffect, useState } from 'react';

function App() {

  const [wasm, setWasm] = useState(null);

  useEffect(() => {
    setup();
  }, []);  

  // let wasm;
  const setup = () => {
      import("dkg/dkg")
        .then((js) => {
          console.log("wasm is ready");
          setWasm(js);
      });
  }
  
  /**
   * Generate a secret polynomial
   * @param {*} seed A seed to generate the random number gen from
   * @param {*} threshold The threshold value (i.e. degree) to use when creating the polynomial
   */
  const keygen = (seed, threshold) => {
      if (wasm == null) {
          alert("wasm blob is null");
      } else {
          return wasm.keygen(BigInt(seed), threshold);
      }
  }

  return (
    <div className="App">
        <div>
            <h2>
              DKG Wasm Example
            </h2>
        </div>
        <div>
          <button>
            Submit
          </button>
        </div>
    </div>
  );
}

export default App;
