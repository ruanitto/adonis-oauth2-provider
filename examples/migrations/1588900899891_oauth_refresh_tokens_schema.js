'use strict'

/** @type {import('@adonisjs/lucid/src/Schema')} */
const Schema = use('Schema')

class OauthRefreshTokensSchema extends Schema {
  up () {
    this.create('oauth_refresh_tokens', (table) => {
      table.string('id', 100).primary()
      table.string('access_token_id', 100).index()
      table.boolean('revoked')
      table.datetime('expires_at').nullable()
    })
  }

  down () {
    this.drop('oauth_refresh_tokens')
  }
}

module.exports = OauthRefreshTokensSchema
