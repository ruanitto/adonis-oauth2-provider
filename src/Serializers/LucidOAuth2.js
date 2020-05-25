'use strict'

/*
 * adonis-lucid
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
 * Database serializer uses the Lucid models provider to fetch
 * user and tokens from the database.
 *
 * @class LucidSerializer
 * @constructor
 * @module Lucid
 *
 * @param {Object} Hash Hash provider
 */
class LucidOAuth2Serializer {
  constructor(Hash) {
    this.Hash = Hash
    this.OauthClient = ioc.use('App/Models/OauthClient')
    this.OauthAccessToken = ioc.use('App/Models/OauthAccessToken')
    this.OauthRefreshToken = ioc.use('App/Models/OauthRefreshToken')
    this._config = null
    this._Model = null
    this._queryCallback = null
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
  static get inject() {
    return ['Adonis/Src/Hash']
  }

  /**
   * Returns an instance of the model query
   *
   * @method _getQuery
   *
   * @param  {String} [table = this.table]
   *
   * @return {Object}
   *
   * @private
   */
  _getQuery() {
    const query = this._Model.query()
    if (typeof (this._queryCallback) === 'function') {
      this._queryCallback(query)
      this._queryCallback = null
    }
    return query
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
  _selectTokens(user, tokens, inverse) {
    const query = user.tokens()
    const method = inverse ? 'whereNotIn' : 'whereIn'

    const tokensList = _.compact(_.castArray(tokens))
    if (!_.size(tokensList)) {
      return query
    }

    debug('creating query: tokens.query.%s(\'token\', %j)', method, tokensList)
    query[method]('token', tokensList)

    return query
  }

  /**
   * Reference to the primary key used for fetching the unique value
   * for a given user.
   *
   * @attribute primaryKey
   * @type {String}
   * @readOnly
   */
  get primaryKey() {
    return this._Model.primaryKey
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
  setConfig(config) {
    this._config = config
    this._Model = ioc.make(this._config.model)
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
  query(callback) {
    this._queryCallback = callback
    return this
  }

  async getUser(uid) {
    if (this._getQuery().findForOAuth2) {
      debug('finding client for clientId %s', uid)
      return this._getQuery().findForOAuth2(uid).first()
    } else {
      return this.findByUid(uid)
    }
  }

  async getClient(clientId, clientSecret) {
    debug('finding client for clientId: %s', clientId)
    return this.OauthClient.query()
      .where(builder => {
        builder.where('id', clientId)
        if (clientSecret) {
          builder.where('secret', clientSecret)
        }
      })
      .first()
  }

  async getRefreshToken(refreshToken) {
    debug('finding data for %s refreshToken', refreshToken)
    return this.OauthRefreshToken.query()
      // .with('token', builder => {
      //   builder.with('client')
      //   builder.with('user')
      // })
      .where('id', refreshToken)
      .where('revoked', 0)
      .first()
  }

  /**
   * Returns a user instance using the primary
   * key
   *
   * @method findById
   * @async
   *
   * @param  {Number|String} id
   *
   * @return {User|Null}
   */
  async findById(id) {
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
   * @return {Model|Null} The model instance or `null`
   */
  async findByUid(uid) {
    debug('finding user with %s as %s', this._config.uid, uid)
    return this._getQuery().where(this._config.uid, uid).first()
  }

  /**
   * Validates the password field on the user model instance
   *
   * @method validateCredentails
   * @async
   *
   * @param  {Model}            user
   * @param  {String}           password
   *
   * @return {Boolean}
   */
  async validateCredentails(user, password) {
    if (!user || !user[this._config.password]) {
      return false
    }

    if (user.validateForOAuth2) {
      return user.validateForOAuth2(password)
    }
    return this.Hash.verify(password, user[this._config.password])
  }

  /**
   * Finds a user with token
   *
   * @method findByToken
   * @async
   *
   * @param  {String}    token
   * @param  {String}    type
   *
   * @return {Object|Null}
   */
  async findByToken(token, type) {
    debug('finding user for %s token', token)

    return this
      ._getQuery()
      .whereHas('tokens', function (builder) {
        builder.where({ token, type, is_revoked: false })
      }).first()
  }

  /**
   * Save token for a user. Tokens are usually secondary
   * way to login a user when their primary login is
   * expired
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
  async saveToken(user, client, scope, token, refreshToken, expires) {
    const insertToken = {
      id: token,
      user_id: user.primaryKeyValue,
      client_id: client.primaryKeyValue,
      scopes: scope,
      revoked: false,
      expires_at: expires.token_expire_at
    } // Corrigir
    await this.OauthAccessToken.create(insertToken)
    debug('saving token for %s user with %j payload', user.primaryKeyValue, token)
    const insertRefreshToken = {
      id: refreshToken,
      access_token_id: token,
      revoked: false,
      expires_at: expires.refreshtoken_expire_at
    } // Corrigir
    await this.OauthRefreshToken.create(insertRefreshToken)
  }

  async revokeToken(token) {
    await this.OauthAccessToken.query()
      .where('id', token.id)
      .update({ revoked: true})

    await this.OauthRefreshToken.query()
      .where('access_token_id', token.id)
      .update({ revoked: true})

    return true
  }

  /**
   * Revoke token(s) or all tokens for a given user
   *
   * @method revokeTokens
   *
   * @param  {Object}           user
   * @param  {Array|String}     [tokens = null] - If defined all these tokens are taken into account
   * @param  {Boolean}          [inverse = false] - If `true`, all tokens except the given tokens will be revoked
   *
   * @return {Number}           Number of impacted rows
   */
  async revokeTokens(user, tokens = null, inverse = false) {
    const query = this._selectTokens(user, tokens, inverse)
    return query.update({ is_revoked: true })
  }

  /**
   * Delete token(s) or all tokens for a given user
   *
   * @method deleteTokens
   *
   * @param  {Object}           user
   * @param  {Array|String}     [tokens = null] - If defined all these tokens are taken into account
   * @param  {Boolean}          [inverse = false] - If `true`, all tokens except the given tokens will be removed
   *
   * @return {Number}           Number of impacted rows
   */
  async deleteTokens(user, tokens = null, inverse = false) {
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
   */
  async listTokens(user, type) {
    return user.tokens().where({ type, is_revoked: false }).fetch()
  }
}

module.exports = LucidOAuth2Serializer
