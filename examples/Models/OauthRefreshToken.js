'use strict'

/** @type {typeof import('@adonisjs/lucid/src/Lucid/Model')} */
const Model = use('Model')

class OauthRefreshToken extends Model {
  static boot() {
    super.boot()
    this.addTrait('NoTimestamp')
  }

  token() {
    return this.hasOne('App/Models/OauthAccessToken', 'access_token_id', 'id')
  }
}

module.exports = OauthRefreshToken
