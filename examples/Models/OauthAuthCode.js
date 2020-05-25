'use strict'

/** @type {typeof import('@adonisjs/lucid/src/Lucid/Model')} */
const Model = use('Model')

class OauthAuthCode extends Model {

  client() {
    return this.hasMany('App/Models/OauthClient')
  }
}

module.exports = OauthAuthCode
