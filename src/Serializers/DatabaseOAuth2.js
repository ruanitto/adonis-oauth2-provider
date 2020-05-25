'use strict'

/*
 * adonis-auth
 *
 * (c) Harminder Virk <virk@adonisjs.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
*/

const _ = require('lodash')
const { ioc } = require('@adonisjs/fold')
const debug = require('debug')('adonis:auth')

/**
 * Database serializer uses the Database provider to fetch
 * user and tokens from the database.
 *
 * @class DatabaseSerializer
 * @constructor
 * @module Lucid
 *
 * @param {Object} Hash Hash provider
 */
class DatabaseOAuth2Serializer {
  constructor (Hash) {
    this.Hash = Hash
    this._config = null
    this._queryCallback = null
    this._Db = ioc.use('Adonis/Src/Database')
  }

  /* istanbul ignore next */
  /**
   * Dependencies to be injected by Ioc container
   *
   * @attribute inject
   * @type {Array}
   * @readOnly
   *
   * @ignore
   * @static
   */
  static get inject () {
    return ['Adonis/Src/Hash']
  }

  /**
   * Returns an instance of the model query
   *
   * @method _getQuery
   *
   * @return {Object}
   *
   * @private
   */
  _getQuery () {
    const query = this._Db.connection(this.connection).table(this.table)

    if (typeof (this._queryCallback) === 'function') {
      this._queryCallback(query)
      this._queryCallback = null
    }

    return query
  }

  /**
   * Returns the query builder instance for the tokens table
   *
   * @method _getTokensQuery
   *
   * @return {Object}
   *
   * @private
   */
  _getTokensQuery () {
    return this._Db.connection(this.connection).table(this.tokensTable)
  }

  /**
   * Returns a query by selecting the right set of tokens
   * for a given user.
   *
   * @method _selectTokens
   *
   * @param  {Object}        user
   * @param  {Array}         [tokens]             - Scope to given tokens only
   * @param  {Boolean}       [inverse = false]    - Inverse the scope
   *
   * @return {Object}
   *
   * @private
   */
  _selectTokens (user, tokens, inverse) {
    const query = this._getTokensQuery().where(this.foreignKey, user[this.primaryKey])

    const tokensList = _.compact(_.castArray(tokens))
    if (!_.size(tokensList)) {
      return query
    }

    const method = inverse ? 'whereNotIn' : 'whereIn'
    debug('creating query: tokens.query.%s(\'token\', %j)', method, tokensList)
    query[method]('token', tokensList)

    return query
  }

  /**
   * Connection to be used for making Database queries. This property
   * is a reference to the `connection` key inside the config file.
   *
   * @attribute connection
   * @type {String}
   * @readOnly
   */
  get connection () {
    return this._config.connection || ''
  }

  /**
   * The table name for fetching users. This property is a reference
   * to the `table` key inside the config file.
   *
   * @attribute table
   * @type {String}
   * @readOnly
   */
  get table () {
    return this._config.table
  }

  /**
   * The primary key to be used for finding the unique value for a give
   * user. This property is a reference to the `primaryKey` key inside
   * the config file.
   *
   * @attribute primaryKey
   * @type {String}
   * @readOnly
   */
  get primaryKey () {
    return this._config.primaryKey
  }

  /**
   * The foreign key to be used for building a relation between user and
   * the tokens table. This property is a reference to the `foreignKey`
   * key inside the config file.
   *
   * @attribute foreignKey
   * @type {String}
   * @readOnly
   */
  get foreignKey () {
    return this._config.foreignKey
  }

  /**
   * Name of table where tokens are stored. This property is a
   * reference to the `tokensTable` key inside the config file.
   *
   * @attribute tokensTable
   * @type {String}
   * @readOnly
   */
  get tokensTable () {
    return this._config.tokensTable
  }

  /**
   * Sets the config based upon the authenticator in use. The Auth
   * facade calls this method and passes the config.
   *
   * @method setConfig
   *
   * @param  {Object}  config
   *
   * @return {void}
   */
  setConfig (config) {
    this._config = config
  }

  /**
   * Add runtime constraints to the query builder. It
   * is helpful when auth has extra constraints too.
   *
   * The `query` method called directly on the auth instance, which
   * internally calls this method on the serializer.
   *
   * @method query
   *
   * @param  {Function} callback
   *
   * @chainable
   *
   * @example
   *
   * ```js
   * auth.query((builder) => {
   *   builder.status('active')
   * }).attempt()
   * ```
   */
  query (callback) {
    this._queryCallback = callback
    return this
  }

  /**
   * Returns a user instance using the primary
   * key.
   *
   * @method findById
   * @async
   *
   * @param  {Number|String} id
   *
   * @return {Object|Null}
   */
  async findById (id) {
    debug('finding user with primary key as %s', id)
    return this._getQuery().where(this.primaryKey, id).first()
  }

  /**
   * Finds a user using the uid field
   *
   * @method findByUid
   * @async
   *
   * @param  {String}  uid
   *
   * @return {Object|Null}
   */
  async findByUid (uid) {
    debug('finding user with %s as %s', this._config.uid, uid)
    return this._getQuery().where(this._config.uid, uid).first()
  }

  /**
   * Validates the password field on the user model instance. This
   * method will make use of the `Hash` provider.
   *
   * @method validateCredentails
   * @async
   *
   * @param  {Model}             user
   * @param  {String}            password
   *
   * @return {Boolean}
   */
  async validateCredentails (user, password) {
    if (!user || !user[this._config.password]) {
      return false
    }
    return this.Hash.verify(password, user[this._config.password])
  }

  /**
   * Finds a user with token.
   *
   * @method findByToken
   * @async
   *
   * @param  {String}    token
   * @param  {String}    type
   *
   * @return {Object|Null}
   */
  async findByToken (token, type) {
    debug('finding user for %s token', token)
    const query = this._getQuery()

    const lhs = query.client.formatter(query).columnize(`${this._config.table}.${this.primaryKey}`)
    const rhs = query.client.formatter(query).columnize(`${this.tokensTable}.${this.foreignKey}`)
    const tokensTable = this.tokensTable

    return query
      .whereExists(function () {
        this
          .from(tokensTable)
          .where({ token, type, is_revoked: false })
          .whereRaw(`${lhs} = ${rhs}`)
      }).first()
  }

  /**
   * Save token for a user.
   *
   * @method saveToken
   * @async
   *
   * @param  {Object}  user
   * @param  {String}  token
   * @param  {String}  type
   *
   * @return {void}
   */
  async saveToken (user, token, type) {
    const foreignKeyValue = user[this.primaryKey]

    const insertPayload = {
      token,
      type,
      is_revoked: false,
      [this.foreignKey]: foreignKeyValue
    }

    debug('saving token for %s user with %j payload', foreignKeyValue, insertPayload)
    await this._getTokensQuery().insert(insertPayload)
  }

  /**
   * Revoke token(s) or all tokens for a given user
   *
   * @method revokeTokens
   * @async
   *
   * @param  {Object}           user
   * @param  {Array|String}     [tokens = null] - If defined all these tokens are taken into account
   * @param  {Boolean}          [inverse = false] - If `true`, all tokens except the given tokens will be revoked
   *
   * @return {Number}           Number of impacted rows
   */
  async revokeTokens (user, tokens = null, inverse = false) {
    const query = this._selectTokens(user, tokens, inverse)
    return query.update({ is_revoked: true })
  }

  /**
   * Delete token(s) or all tokens for a given user
   *
   * @method deleteTokens
   * @async
   *
   * @param  {Object}           user
   * @param  {Array|String}     [tokens = null] - If defined all these tokens are taken into account
   * @param  {Boolean}          [inverse = false] - If `true`, all tokens except the given tokens will be removed
   *
   * @return {Number}           Number of impacted rows
   */
  async deleteTokens (user, tokens = null, inverse = false) {
    const query = this._selectTokens(user, tokens, inverse)
    return query.delete()
  }

  /**
   * Returns all non-revoked list of tokens for a given user.
   *
   * @method listTokens
   * @async
   *
   * @param  {Object}   user
   * @param  {String}   type
   *
   * @return {Object}
   * - { rows: rows, toJSON: function () {} }
   */
  async listTokens (user, type) {
    const query = this._getTokensQuery()

    const rows = await query
      .where({ type, is_revoked: false })
      .where(this.foreignKey, user[this.primaryKey])

    return {
      rows: rows,
      toJSON () {
        return this.rows || []
      }
    }
  }
}

module.exports = DatabaseOAuth2Serializer
