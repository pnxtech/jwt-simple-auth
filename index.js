const jwt = require('jsonwebtoken');
const fs = require('fs');
const crypto = require('crypto');

/**
* @name JWTToken
*/
class JWTToken {
  /**
  * @name constructor
  * @summary JWTToken constructor
  * @return {undefined}
  */
  constructor() {
    this.privateCert = null;
    this.publicCert = null;
    this.options = {
      accessTokenExpirationInSeconds: 3600,
      refreshTokenExpirationInSeconds: 2419200
    };
  }

  /**
  * @name init
  * @summary initialize JWTToken
  * @param {object} options - overrides for default options
  * @return {undefined}
  */
  init(options) {
    this.options = Object.assign(this.options, options);
    console.log('this.options', this.options);
  }

  /**
  * @name getOptions
  * @summary Retrieve the module options
  * @return {object} options - module options
  */
  getOptions() {
    return this.options;
  }

  /**
  * @name loadCerts
  * @summary Load security certificates
  * @param {string} privateCertPath - path to private certificate
  * @param {string} publicCertPath - path to public certificate
  * @return {object} promise -
  */
  loadCerts(privateCertPath, publicCertPath) {
    return new Promise((resolve, reject) => {
      try {
        if (privateCertPath) {
          this.privateCert = fs.readFileSync(privateCertPath);
        }
        if (publicCertPath) {
          this.publicCert = fs.readFileSync(publicCertPath);
        }
        resolve(true);
      } catch (e) {
        reject(e);
      }
    });
  }

  /**
  * @name getPrivateCert
  * @summary Return the loaded private cert
  * @return {string} private cert or null
  */
  getPrivateCert() {
    return this.privateCert;
  }

  /**
  * @name getPublicCert
  * @summary Return the loaded public cert
  * @return {string} private cert or null
  */
  getPublicCert() {
    return this.publicCert;
  }

  /**
  * @name generateUniqueID
  * @summary Generate a unique ID
  * @return {String} ID - unique ID
  */
  generateUniqueID() {
    return `${(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER)).toString(36)}${new Date().getMilliseconds()}`;
  }

  /**
  * @name createToken
  * @summary Create a signed JSON web token
  * @param {object} payload - user level payload to merge into token
  * @param {string} type - 'access' | 'refresh'
  * @param {string} jti - optional JWT Token ID
  * @return {object} promise -
  */
  createToken(payload, type, jti) {
    return new Promise((resolve, reject) => {
      if (!this.privateCert) {
        reject(new Error('Private certificate wasn\'t loaded in loadCerts call.'));
        return;
      }
      let offsetSeconds = (type === 'access') ?
        this.options.accessTokenExpirationInSeconds :
        this.options.refreshTokenExpirationInSeconds;
      let nowSeconds = Math.floor(Date.now() / 1000);
      let newJTI = (jti) ? jti : this.generateUniqueID();
      payload = Object.assign(payload, {
        iss: 'urn:auth',
        type,
        jti: newJTI,
        iat: nowSeconds,
        exp: nowSeconds + offsetSeconds
      });
      jwt.sign(payload, this.privateCert, {algorithm: 'RS256'}, (err, token) => {
        if (err) {
          reject(err);
        } else {
          resolve(token);
        }
      });
    });
  }

  /**
  * @name verifyToken
  * @summary Verify a token.
  * @param {string} token - JSON web token
  * @return {object} promise - if successful resolves to the decoded payload
  */
  verifyToken(token) {
    return new Promise((resolve, reject) => {
      if (!this.publicCert) {
        reject(new Error('Public certificate wasn\'t loaded in loadCerts call.'));
        return;
      }
      jwt.verify(token, this.publicCert, (err, decoded) => {
        if (err) {
          reject(err);
        } else {
          resolve(decoded);
        }
      });
    });
  }

  /**
  * @name refreshToken
  * @summary Refresh a valid token
  * @param {string} token - JSON web token
  * @param {stdring} jti - JWT token ID to use of undefined to generate a new one
  * @return {object} promise -
  */
  refreshToken(token, jti) {
    return new Promise((resolve, reject) => {
      return this.verifyToken(token)
        .then((data) => {
          if (data.type !== 'refresh') {
            reject(new Error('Invalid token type'));
            return;
          }
          return this.createToken(data, 'access', jti)
            .then((newToken) => {
              resolve(newToken);
            })
            .catch((err) => {
              reject(err);
            });
        })
        .catch((err) => {
          reject(err);
        });
    });
  }

  /**
  * @name getTokenHash
  * @summary Return a Sha1 hash of the token
  * @param {string} token - JSON web token
  * @return {string} sha1 hash - in string hex format
  */
  getTokenHash(token) {
    let sha1 = crypto.createHash('sha1');
    sha1.update(token);
    return sha1.digest('hex');
  }
}

module.exports = new JWTToken();
