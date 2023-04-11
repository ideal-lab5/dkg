import("./node_modules/dkg/dkg.js").then((js) => {
    js.keygen(BigInt(23), 3);
  });
  