// This middleware validates the logout token as defined here:
// https://openid.net/specs/openid-connect-backchannel-1_0.html#Validation

const jose = require('jose');

async function requiresValidLogoutToken(req, res, next) {

  // get remote key set for token verification
//  const JWKS = jose.createRemoteJWKSet(
 ////   new URL(process.env.ISSUER_BASE_URL + '/.well-known/jwks.json')
  //);

  const JWKS = jose.createLocalJWKSet({
    keys: [
      {
        kty: "RSA",
        e: "AQAB",
        use: "sig",
        kid: "rRA9yjBPdbrrSznPHLJbiVyCQjeUDQHXw0vHrA5_Gs0",
        alg: "RS256",
        n: "5IuBN8BoSFYISlu2_gzcucNJpP93TZEFkrJoKqfdImN9h7l9l6tSLjG4H-jENJ_8dzukkjTFnNTiMA5gWa4g9mI4i1vh5npddnGM5inoUPPoivaSmtYSndJNZdbZZoOESYepy0PdBIBqy8j3Y_Ddrt6PRIrwWN0lSIAxUhgyDTjjxT0U65RZq63MdFHBVowIle05cB0hoVdO9AJiN4gu2zN-aQMwMRlZ3sgo4tnvdsXf6tXnOGeFzEphfNuqwSkyvnIuZNe8DLtdV5bS97CWyPp-uPtAXnz3ABV6dz7OMGrtpI32YcBBHeefOusHoENhquHz-oL_QM9RccemmALXjw"
    },
    ],
  })

  const logoutToken = req.body.logout_token;

  if (!logoutToken) {
    res.status(400).send('Need logout token');
  }

  try {
    const { payload, protectedHeader } = await jose.jwtVerify(
      logoutToken,
      JWKS,
      {
        issuer: process.env.ISSUER_BASE_URL + '/',
        audience: process.env.CLIENT_ID,
        typ: 'JWT',
        maxTokenAge: '10 minutes',
      }
    );

    // Verify that the Logout token contains a sub claim, a sid claim, or both
    if (!payload.sub && !payload.sid) {
      res
        .status(400)
        .send(
          'Error: Logout token must contain either sub claim or sid claim, or both'
        );
    }

    // Verify that the logout token contains an events claim
    // whose value is a JSON object containing the member name http://schemas.openid.net/event/backchannel-logout
    if (!payload.events['http://schemas.openid.net/event/backchannel-logout']) {
      res
        .status(400)
        .send(
          'Error: Logout token must contain events claim with correct schema'
        );
    }

    // Verify that the Logout token does not contain a nonce claim.
    if (payload.nonce) {
      res
        .status(400)
        .send('Error: Logout token must not contain a nonce claim');
    }
    
    // attach valid logout token to request object
    req.logoutToken = payload;
    
    // token is valid, call next middleware
    next();
  } catch (error) {
    res.status(400).send(`Error:  ${error.message}`);
  }
}

module.exports = requiresValidLogoutToken;