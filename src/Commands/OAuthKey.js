'use strict'

const { Command } = require('@adonisjs/ace')
const { generateKeyPair } = require('crypto');
const fs = require('fs')
const path = require('path')
const Config = use('Config')

class OAuthKey extends Command {
  static get signature () {
    return `oauth2:key
    { --force? : Force replace files }
    `
  }

  static get description () {
    return 'Create the encryption keys for OAuth2 API authentication'
  }

  async generateKeys() {
    await generateKeyPair('rsa', {
      modulusLength: 4096,
      publicExponent: 65537,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
      },
      privateKeyEncoding: {
        type: 'pkcs1',
        format: 'pem'
      }
    }, (err, publicKey, privateKey) => {
      if (!err) {
        fs.writeFileSync(this.pubKey, publicKey)
        fs.writeFileSync(this.privKey, privateKey)
        this.info('Encryption keys generated successfully.')
        this.info(this.pubKey)
        this.info(this.privKey)
      } else {
        this.error(err.message)
      }
    })
  }

  async handle (args, options) {

    this.appKey = Config.get('app.appKey')
    this.keysDir = Config.get('auth.oauth2.keysPath', './authkeys')
    this.pubKey = path.join(this.keysDir, 'oauth-public.key')
    this.privKey = path.join(this.keysDir, 'oauth-private.key')

    if (!fs.existsSync(this.keysDir)) {
      this.info('Creating Dir: ' + this.keysDir)
      fs.mkdirSync(this.keysDir)
    }

    if (fs.existsSync(this.pubKey) || fs.existsSync(this.privKey)) {
      if (!options.force) {
        this.error('Encryption oauth2 keys already exist. Use the --force option to overwrite them.')
      } else {
        this.info('Replacing Keys')
        this.generateKeys()
      }
    } else {
      this.info('Generating Keys')
      this.generateKeys()
    }
  }
}

module.exports = OAuthKey
