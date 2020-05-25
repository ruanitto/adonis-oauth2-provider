'use strict'

/** @type {import('@adonisjs/lucid/src/Schema')} */
const Schema = use('Schema')

class OauthClientsSchema extends Schema {
  up () {
    this.create('oauth_clients', (table) => {
      table.increments()
      table.integer('user_id').index().nullable()
      table.string('name')
      table.string('secret', 100)
      table.text('redirect')
      table.boolean('personal_access_client')
      table.boolean('password_client')
      table.boolean('revoked')
      table.timestamps()
    })
  }

  down () {
    this.drop('oauth_clients')
  }
}

module.exports = OauthClientsSchema
