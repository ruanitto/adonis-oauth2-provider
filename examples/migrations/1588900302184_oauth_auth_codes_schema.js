'use strict'

/** @type {import('@adonisjs/lucid/src/Schema')} */
const Schema = use('Schema')

class OauthAuthCodesSchema extends Schema {
  up () {
    this.create('oauth_auth_codes', (table) => {
      table.string('id', 100).primary()
      table.integer('user_id')
      table.integer('client_id')
      table.text('scopes').nullable()
      table.boolean('revoked').defaultTo(false)
      table.datetime('expires_at').nullable()
    })
  }

  down () {
    this.drop('oauth_auth_codes')
  }
}

module.exports = OauthAuthCodesSchema
