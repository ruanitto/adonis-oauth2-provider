'use strict'

/** @type {typeof import('@adonisjs/lucid/src/Lucid/Model')} */
const Model = use('Model')

class OauthClient extends Model {

  authCodes() {
    return this.hasMany('App/Models/OaccessAuthCode', 'client_id')
  }

  tokens() {
    return this.hasMany('App/Models/OauthAccessToken', 'client_id')
  }

  firstParty() {
    return this.personal_access_client || this.password_client
  }
}

module.exports = OauthClient
