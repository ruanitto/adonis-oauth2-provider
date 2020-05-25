'use strict'

/** @type {typeof import('@adonisjs/lucid/src/Lucid/Model')} */
const Model = use('Model')
const Config = use('Config')

class OauthAccessToken extends Model {

  client() {
    return this.belongsTo('App/Models/OauthClient', 'client_id')
  }

  user() {
    const authenticator = Config.get('auth.authenticator')

    return this.belongsTo(Config.get(`auth.${authenticator}.model`), 'user_id')
  }

  transient() {
    return false
  }

  refreshToken() {
    return this.hasOne('App/Models/OauthRefreshToken')
  }
}

module.exports = OauthAccessToken
