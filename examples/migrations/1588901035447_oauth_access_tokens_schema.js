'use strict'

/** @type {import('@adonisjs/lucid/src/Schema')} */
const Schema = use('Schema')

class OauthAccessTokensSchema extends Schema {
  up () {
    this.create('oauth_access_tokens', (table) => {
      table.string('id', 100).primary()
      table.integer('user_id').index().nullable()
      table.integer('client_id');
      table.string('name').nullable()
      table.text('scopes').nullable()
      table.boolean('revoked')
      table.timestamps()
      table.datetime('expires_at').nullable()
    })
  }

  down () {
    this.drop('oauth_access_tokens')
  }
}

module.exports = OauthAccessTokensSchema
