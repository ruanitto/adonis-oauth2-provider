'use strict'

const { ServiceProvider } = require('@adonisjs/fold')

class OAuth2Provider extends ServiceProvider {

  _addRoutes() {
    const Route = use('Route')
    Route.group('oauth', () => {
      Route.post('token', ({ auth }) => {
        return auth.token()
      })
    }).prefix('oauth')
  }

  register() {
  }

  /**
   * Boot the provider
   *
   * @method boot
   *
   * @return {void}
   */
  boot () {
    this._addRoutes()
  }
}

module.exports = OAuth2Provider
