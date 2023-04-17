/* global BigInt */
import './App.css';
import { w_keygen, w_calculate_secret, 
    w_calculate_pubkey, w_combine_pubkeys,
    w_combine_secrets, w_encrypt, w_threshold_decrypt
} from "dkg";
import { useWasm } from './useWasm';
import { useState } from 'react';


function App() {
  // make sure the wasm blob is loaded
  useWasm();

  const [societySize, setSocietySize] = useState(0);
  const [threshold, setThreshold] = useState(0);
  const [society, setSociety] = useState([]);

  const handleKeygen = () => {
    // each participant must agree on two numbers
    let r1 = 45432;
    let r2 = 48484;
    let results = [];
    // each participant independently generates a polynomial and calulates their keys
    for (let i = 0; i < societySize; i++) {
      // generate random number 
      let r = 23;
      let poly = w_keygen(BigInt(r), threshold);
      let secret = w_calculate_secret(poly.coeffs);
      let pubkey = w_calculate_pubkey(BigInt(r1), BigInt(r2), secret)
      results.push({
        i: i,
        pubkey: pubkey,
        secret: secret,
      });
    };
    setSociety(results);
  }

  const calculateGroupPublicKey = () => {
    return society.reduce((a, b) => w_combine_pubkeys(a.pubkey, b.pubkey));
  }

  const calculateGroupSecretKey = () => {
    return society.reduce((a, b) => w_combine_secrets(a.secret, b.secret));
  }



  return (
    <div className="App">
      <div>
        <h2>DKG Wasm Example</h2>
        <p>Generate keys, encrypt and decrypt messages</p>
      </div>
      <div className='body'>
        { society.length === 0 ? 
        <div className='section'>
          <span>
            Generate keys
          </span>
          <label htmlFor='society-size-input'>Set number of participants</label>
          {societySize}
          <input id='society-size-input' type='number' value={societySize} onChange={(e) => setSocietySize(e.target.value)} />
          <label htmlFor='threshold-input'>Set threshold</label>
          <input id='threshold-input' type='number' value={threshold} onChange={(e) => setThreshold(e.target.value)} />
          <button onClick={handleKeygen}> Keygen
          </button>
        </div>
        : 
        <div className='section'>
          <span>There are `{society.length}` participants.</span>
          <span>The group secret key is `{JSON.stringify(calculateGroupSecretKey())}` </span>
          <span>The group public key is `{JSON.stringify(calculateGroupPublicKey())}`</span>
        </div>
        }
      </div>
    </div>
  );
}

export default App;
