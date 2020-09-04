'use strict'

const { ServiceProvider } = require('@adonisjs/fold')

const { oauth2 } = require('../src/Schemes')
const { databaseOAuth2, lucidOAuth2 } = require('../src/Serializers')

class OAuth2Provider extends ServiceProvider {

  _registerSerializers() {
    this.app.extend('Adonis/Src/Auth', 'databaseOAuth2', () => {
      return databaseOAuth2
    }, 'serializer')
    this.app.extend('Adonis/Src/Auth', 'lucidOAuth2', () => {
      return lucidOAuth2
    }, 'serializer')
  }

  _registerSchemes() {
    this.app.extend('Adonis/Src/Auth', 'oauth2', () => {
      return oauth2
    }, 'scheme')
  }

  _registerCommands () {
    this.app.bind('OAuth2/Commands/OAuth2Key', () => require('../src/Commands/OAuthKey'))
  }

  _addCommands () {
    const ace = require('@adonisjs/ace')
    ace.addCommand('OAuth2/Commands/OAuth2Key')
  }

  _addRoutes() {
    const Route = use('Route')
    const Config = use('Config')
    const use_routes = Config.get('auth.oauth2.routes_config.register_routes')
    const use_prefix = Config.get('auth.oauth2.routes_config.use_prefix')
    const prefix = Config.get('auth.oauth2.routes_config.prefix')
    if (use_routes) {
      const oauth_prefix = (use_prefix && prefix) ? (prefix.trim() + '/oauth') : 'oauth'
      Route.group('oauth', () => {
        Route.post('token', ({ auth }) => {
          return auth.token()
        })
      }).prefix(oauth_prefix)
    }
  }

  register() {
    this._registerSerializers()
    this._registerSchemes()
    this._registerCommands()
  }

  /**
   * Boot the provider
   *
   * @method boot
   *
   * @return {void}
   */
  boot () {
    this._addCommands()
    this._addRoutes()
  }
}

module.exports = OAuth2Provider
