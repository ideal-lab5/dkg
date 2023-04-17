import { useEffect, useState } from 'react';
import init from "dkg";

export const useWasm = () => {
  const [state, setState] = useState(null);
  useEffect(() => { 
    init().then(dkg => {
        setState(dkg);
    });
  }, []);
  return state;
}

