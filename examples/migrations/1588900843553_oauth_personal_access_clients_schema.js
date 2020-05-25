'use strict'

/** @type {import('@adonisjs/lucid/src/Schema')} */
const Schema = use('Schema')

class OauthPersonalAccessClientsSchema extends Schema {
  up () {
    this.create('oauth_personal_access_clients', (table) => {
      table.increments()
      table.integer('client_id').index()
      table.timestamps()
    })
  }

  down () {
    this.drop('oauth_personal_access_clients')
  }
}

module.exports = OauthPersonalAccessClientsSchema
