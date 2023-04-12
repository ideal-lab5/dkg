// import { useEffect, useState } from 'react';
// import { AsBind } from 'as-bind';

// export const useWasm = () => {
//   const [state, setState] = useState(null);
//   useEffect(() => { 
//     const fetchWasm = async () => {
//       const wasm = await fetch('dkg.wasm');
//       const instance = await AsBind.instantiate(wasm, {});
//       setState(instance);
//     };
//     fetchWasm();
//   }, []);
//   return state;
// }

