'use strict'

/*
 * oauth2-scheme
 *
 * (c) Rafael Gomes <madrafael.gsilva@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
*/

const Resetable = require('resetable')
const jwt = require('jsonwebtoken')
const uuid = require('uuid')
const _ = require('lodash')
const util = require('util')
const GE = require('@adonisjs/generic-exceptions')

const auth = require('basic-auth')
const is = require('../validator/is');
const crypto = require('crypto')
const ms = require('ms')
const moment = require('moment')

const CE = require('@adonisjs/auth/src/Exceptions')
const BaseTokenScheme = require('@adonisjs/auth/src/Schemes/BaseToken')

const Request = require('@adonisjs/framework/src/Request')
const Response = require('@adonisjs/framework/src/Response')

const signToken = util.promisify(jwt.sign)
const verifyToken = util.promisify(jwt.verify)

var grantTypes = {
  authorization_code: '_authCodeGrantType',
  client_credentials: '_clientCredentialsGrantType',
  password: '_passwordGrantType',
  refresh_token: '_refreshTokenGrantType',
}

/**
 * This scheme allows to make use of JWT tokens to authenticate the user.
 *
 * The user sends a token inside the `Authorization` header as following.
 *
 * ```
 * Authorization=Bearer JWT-TOKEN
 * ```
 *
 * ### Note
 * Token will be encrypted using `EncryptionProvider` before sending it to the user.
 *
 * @class OAuth2Scheme
 * @extends BaseScheme
 */
class OAuth2Scheme extends BaseTokenScheme {
  constructor(Encryption) {
    super(Encryption)
    this._generateRefreshToken = new Resetable(false)

    let options = _.get(this._config, 'options', null)

    this.accessTokenLifetime = _.get(options, 'expiresIn', '1h') // 1 hour
    this.refreshTokenLifetime = _.get(this._config, 'refreshTokenLifetime', '14d')  // 2 weeks.
    this.allowExtendedTokenAttributes = _.get(this._config, 'allowExtendedTokenAttributes', false)
    this.requireClientAuthentication = _.get(this._config, 'requireClientAuthentication', {})
    this.grantTypes = grantTypes
    this.alwaysIssueNewRefreshToken = false
  }

  /**
   * An object of oauth2 options directly
   * passed to `jsonwebtoken` library
   *
   * @attribute oauth2Options
   * @type {Object|Null}
   * @readOnly
   */
  get oauth2Options() {
    return _.get(this._config, 'options', null)
  }

  /**
   * The jwt secret
   *
   * @attribute oauth2Secret
   * @type {String|Null}
   * @readOnly
   */
  get oauth2Secret() {
    return _.get(this.oauth2Options, 'secret', null)
  }

  /**
   * The jwt public
   *
   * @attribute oauth2Public
   * @type {String|Null}
   * @readOnly
   */
  get oauth2Public() {
    return _.get(this.oauth2Options, 'public', null)
  }

  /**
   * Signs payload with oauth2Secret using {{#crossLink "OAuth2Scheme/oauth2Options:attribute"}}{{/crossLink}}
   *
   * @method _signToken
   * @async
   *
   * @param  {Object}   payload
   *
   * @returns  {String}
   *
   * @private
   */
  _signToken(payload, options) {
    options = _.size(options) && _.isPlainObject(options) ? options : _.omit(this.oauth2Options, ['secret', 'public'])
    return signToken(payload, this.oauth2Secret, options)
  }

  /**
   * Verifies the jwt token by decoding it
   *
   * @method _verifyToken
   * @async
   *
   * @param  {String}     token
   *
   * @return {Object}
   *
   * @private
   */
  _verifyToken(token) {
    const options = _.omit(this.oauth2Options, ['secret', 'public'])
    const secretOrPublicKey = this.oauth2Public !== null ? this.oauth2Public : this.oauth2Secret
    return verifyToken(token, secretOrPublicKey, options)
  }

  /**
   * Saves jwt refresh token for a given user
   *
   * @method _saveRefreshToken
   *
   * @param  {Object}          user
   *
   * @return {String}
   *
   * @private
   */
  async _saveRefreshToken(user, client, scope, token) {
    const refreshToken = crypto.randomBytes(40).toString('hex')
    const expires = {
      token_expire_at: this.getAccessTokenExpiresAt(),
      refreshtoken_expire_at: this.getRefreshTokenExpiresAt()
    }
    await this._serializerInstance.saveToken(user, client, scope, token, refreshToken, expires)
    return refreshToken
  }

  getAccessTokenExpiresAt() {
    var expires = new Date()
    expires.setSeconds(expires.getSeconds() + ms(this.accessTokenLifetime))
    return expires
  }

  getRefreshTokenExpiresAt() {
    var expires = new Date()
    expires.setSeconds(expires.getSeconds() + ms(this.refreshTokenLifetime))
    return expires
  }

  async _getUser() {
    if (!this._ctx.request.body.username) {
      throw new GE.HttpException('Missing parameter: `username`', 400, 'E_INVALID_REQUEST')
    }

    if (!this._ctx.request.body.password) {
      throw new GE.HttpException('Missing parameter: `password`', 400, 'E_INVALID_REQUEST')
    }

    if (!is.uchar(this._ctx.request.body.username)) {
      throw new GE.HttpException('Invalid parameter: `username`', 400, 'E_INVALID_REQUEST')
    }

    if (!is.uchar(this._ctx.request.body.password)) {
      throw new GE.HttpException('Invalid parameter: `password`', 400, 'E_INVALID_REQUEST')
    }

    const user = await this._serializerInstance.getUser(this._ctx.request.body.username)

    if (!user) {
      throw this.missingUserFor(this._ctx.request.body.username)
    }

    const validated = await this._serializerInstance.validateCredentails(user, this._ctx.request.body.password)
    if (!validated) {
      throw this.invalidPassword()
    }

    return user
  }

  async _getRefreshToken(client) {

    if (!this._ctx.request.body.refresh_token) {
      throw new GE.HttpException('Missing parameter: `refresh_token`', 400, 'E_INVALID_REQUEST')
    }

    if (!is.vschar(this._ctx.request.body.refresh_token)) {
      throw new GE.HttpException('Invalid parameter: `refresh_token`')
    }

    const refreshToken = await this._serializerInstance.getRefreshToken(this.Encryption.decrypt(this._ctx.request.body.refresh_token))
    if (!refreshToken) {
      throw CE.InvalidRefreshToken.invoke(this._ctx.request.body.refresh_token)
    }

    if (refreshToken.expires_at && !(refreshToken.expires_at instanceof Date)) {
      throw new GE.HttpException('Server error: `refreshTokenExpiresAt` must be a Date instance', 503, 'E_INTERNAL_ERROR');
    }

    if (refreshToken.expires_at && refreshToken.expires_at < new Date()) {
      throw CE.InvalidJwtToken.invoke('Invalid grant: refresh token has expired')
    }

    const token = await refreshToken.token().first()

    if (!token) {
      throw CE.InvalidRefreshToken.invoke(this._ctx.request.body.refresh_token)
    }

    let returnToken = token.toJSON()
    returnToken.client = await token.client().first()
    returnToken.user = await token.user().first()

    if (!returnToken.client) {
      throw new GE.HttpException('Server error: `getRefreshToken()` did not return a `client` object', 503, 'E_INTERNAL_ERROR')
    }

    if (!returnToken.user) {
      throw new GE.HttpException('Server error: `getRefreshToken()` did not return a `user` object', 503, 'E_INTERNAL_ERROR')
    }

    if (returnToken.client.id !== client.id) {
      throw CE.InvalidJwtToken.invoke('Invalid grant: refresh token is invalid')
    }

    return returnToken
  }

  async _revokeToken(token) {
    if (this.alwaysIssueNewRefreshToken === false) {
      return token
    }

    await this._serializerInstance.revokeToken(token)

    return token
  }

  async _validateScope(user, client, scope) {
    // TODO
    // if (this.model.validateScope) {
    //   return promisify(this.model.validateScope, 3).call(this.model, user, client, scope)
    //     .then(function (scope) {
    //       if (!scope) {
    //         throw new InvalidScopeError('Invalid scope: Requested scope is invalid');
    //       }

    //       return scope;
    //     });
    // } else {
    //   return scope;
    // }
    return scope
  }

  _getScope() {
    if (!is.nqschar(this._ctx.request.body.scope)) {
      throw GE.InvalidArgumentException.invalidParameter('Invalid parameter: `scope`')
    }

    return this._ctx.request.body.scope || "[]"
  }

  async _saveToken(user, client, scope) {

    const token = crypto.randomBytes(40).toString('hex')

    const plainRefreshToken = await this._saveRefreshToken(user, client, scope, token)
    const refreshToken = plainRefreshToken ? this.Encryption.encrypt(plainRefreshToken) : null
    const bearerToken = await this.generate(user, { jti: token, aud: client.id.toString(), scope })

    const claim = JSON.parse(
      Buffer.from(bearerToken.token.split('.')[1], 'base64').toString()
    )

    return {
      access_token: bearerToken.token,
      token_type: bearerToken.type,
      expires_in: claim.exp - moment().unix(),
      refresh_token: refreshToken
    }
  }

  async _passwordGrantType(client) {

    if (!this._serializerInstance.getUser) {
      throw GE.InvalidArgumentException.invalidParameter('Invalid argument: serializer does not implement `getUser()`')
    }

    if (!this._serializerInstance.saveToken) {
      throw GE.InvalidArgumentException.invalidParameter('Invalid argument: serializer does not implement `saveToken()`')
    }

    if (!client) {
      throw GE.InvalidArgumentException.missingParameter('_passwordGrantType', '`client`', 1)
    }

    let scope = this._getScope()

    const user = await this._getUser()

    scope = await this._validateScope(user, client, scope)

    return this._saveToken(user, client, scope)
  }

  async _refreshTokenGrantType(client) {

    if (!this._serializerInstance.getRefreshToken) {
      throw GE.InvalidArgumentException.invalidParameter('Invalid argument: serializer does not implement `getRefreshToken()`')
    }

    if (!this._serializerInstance.revokeToken) {
      throw GE.InvalidArgumentException.invalidParameter('Invalid argument: serializer does not implement `revokeToken()`')
    }

    if (!this._serializerInstance.saveToken) {
      throw GE.InvalidArgumentException.invalidParameter('Invalid argument: serializer does not implement `saveToken()`')
    }

    if (!client) {
      throw GE.InvalidArgumentException.missingParameter('_passwordGrantType', '`client`', 1)
    }

    const token = await this._getRefreshToken(client)

    await this._revokeToken(token)

    return this._saveToken(token.user, client, token.scopes)
  }

  _handlesGrant(client, grantType) {
    switch (grantType) {
      case 'authorization_code':
        return !(client.personal_access_client || client.password_client)
      case 'personal_access':
        return client.personal_access_client
      case 'password':
        return client.password_client
      default:
        return true
    }
  }

  _handleGrantType(client) {
    const grantType = this._ctx.request.body.grant_type;

    if (!grantType) {
      throw GE.InvalidArgumentException.missingParameter('_handleGrantType', '`grant_type`', 1)
    }

    if (!is.nchar(grantType) && !is.uri(grantType)) {
      throw GE.InvalidArgumentException.invalidParameter('Invalid parameter: `grant_type`')
    }

    if (!_.has(this.grantTypes, grantType)) {
      throw new GE.HttpException('Unsupported grant type: `grant_type` is invalid', 400, 'E_UNSUPORTED_GRAT')
    }

    if (!this._handlesGrant(client, grantType)) {
      throw new GE.HttpException('Unauthorized client: `grant_type` is invalid', 401, 'E_UNAUTHORIZED_CLIENT')
    }

    var Type = this.grantTypes[grantType]

    return this[Type](client)
  }

  _isClientAuthenticationRequired(grantType) {
    if (Object.keys(this.requireClientAuthentication).length > 0) {
      return (typeof this.requireClientAuthentication[grantType] !== 'undefined') ? this.requireClientAuthentication[grantType] : true
    } else {
      return true;
    }
  }

  _getClientCredentials() {
    const authString = this._ctx.request.header('authorization') || this._ctx.request.input('basic')
    const credentials = auth.parse(authString)
    const grantType = this._ctx.request.body.grant_type;

    if (credentials) {
      return { clientId: credentials.name, clientSecret: credentials.pass }
    }

    if (this._ctx.request.body.client_id && this._ctx.request.body.client_secret) {
      return { clientId: this._ctx.request.body.client_id, clientSecret: this._ctx.request.body.client_secret }
    }

    if (!this._isClientAuthenticationRequired(grantType)) {
      if (this._ctx.request.body.client_id) {
        return { clientId: this._ctx.request.body.client_id }
      }
    }

    // Criar Exceptions para provider
    // throw new InvalidClientError('Invalid client: cannot retrieve client credentials');
    throw new GE.HttpException('Invalid client: cannot retrieve client credentials', 400, 'E_INVALID_CLIENT')
  }

  async _getClient() {
    const credentials = this._getClientCredentials()
    const grantType = this._ctx.request.body.grant_type;

    if (!credentials.clientId) {
      throw new GE.HttpException('Missing parameter: `client_id`', 400, 'E_INVALID_REQUEST')
    }

    if (this._isClientAuthenticationRequired(grantType) && !credentials.clientSecret) {
      throw new GE.HttpException('Missing parameter: `client_secret`', 400, 'E_INVALID_REQUEST')
    }

    if (!is.vschar(credentials.clientId)) {
      throw new GE.HttpException('Invalid parameter: `client_id`', 400, 'E_INVALID_REQUEST')
    }

    if (credentials.clientSecret && !is.vschar(credentials.clientSecret)) {
      throw new GE.HttpException('Invalid parameter: `client_secret`', 400, 'E_INVALID_REQUEST')
    }

    return this._serializerInstance.getClient(credentials.clientId, credentials.clientSecret).then(client => {
      if (!client) {
        throw new GE.HttpException('Invalid client: client is invalid', 400, 'E_INVALID_CLIENT')
      }

      // Comentado por enquanto
      // if (!client.grants) {
      //   throw new ServerError('Server error: missing client `grants`');
      // }

      // if (!(client.grants instanceof Array)) {
      //   throw new ServerError('Server error: `grants` must be an array');
      // }

      return client
    })
    // .catch(function(e) { // TODO
    //   // Include the "WWW-Authenticate" response header field if the client
    //   // attempted to authenticate via the "Authorization" request header.
    //   //
    //   // @see https://tools.ietf.org/html/rfc6749#section-5.2.
    //   if ((e instanceof InvalidClientError) && request.get('authorization')) {
    //     response.set('WWW-Authenticate', 'Basic realm="Service"');

    //     throw new InvalidClientError(e, { code: 401 });
    //   }

    //   throw e;
    // })
  }

  /**
   * Instruct class to generate a refresh token
   * when generating the jwt token.
   *
   * @method withRefreshToken
   *
   * @chainable
   *
   * @example
   * ```js
   * await auth
   *   .withRefreshToken()
   *   .generate(user)
   *
   * // or
   * await auth
   *   .withRefreshToken()
   *   .attempt(username, password)
   * ```
   */
  withRefreshToken() {
    this._generateRefreshToken.set(true)
    return this
  }

  /**
   * When issuing a new JWT token from the refresh token, this class will
   * re-use the old refresh token.
   *
   * If you want, you can instruct the class to generate a new refresh token
   * as well and remove the existing one from the DB.
   *
   * @method newRefreshToken
   *
   * @chainable
   *
   * @example
   * ```js
   * await auth
   *   .newRefreshToken()
   *   .generateForRefreshToken(token)
   * ```
   */
  newRefreshToken() {
    return this.withRefreshToken()
  }

  async token(options) {
    options = _.assign({
      accessTokenLifetime: this.accessTokenLifetime,
      refreshTokenLifetime: this.refreshTokenLifetime,
      allowExtendedTokenAttributes: this.allowExtendedTokenAttributes,
      requireClientAuthentication: this.requireClientAuthentication
    }, this._config, options)

    if (!options.accessTokenLifetime) {
      throw GE.RuntimeException.incompleteConfig(['accessTokenLifetime'], 'config/auth.js', 'oauth2')
    }

    if (!options.serializer) {
      throw GE.RuntimeException.incompleteConfig(['serializer'], 'config/auth.js', 'oauth2')
    }

    if (!options.refreshTokenLifetime) {
      throw GE.RuntimeException.incompleteConfig(['refreshTokenLifetime'], 'config/auth.js', 'oauth2')
    }

    if (!this._serializerInstance.getClient) {
      throw GE.InvalidArgumentException.invalidParameter('Invalid argument: serializer does not implement `getClient()`');
    }

    this.accessTokenLifetime = options.accessTokenLifetime;
    this.grantTypes = _.assign({}, grantTypes, options.extendedGrantTypes);
    this.refreshTokenLifetime = options.refreshTokenLifetime;
    this.allowExtendedTokenAttributes = options.allowExtendedTokenAttributes;
    this.requireClientAuthentication = options.requireClientAuthentication || {};
    this.alwaysIssueNewRefreshToken = options.alwaysIssueNewRefreshToken !== false;

    if (!(this._ctx.request instanceof Request)) {
      throw GE.InvalidArgumentException.invalidParameter('Invalid argument: `request` must be an instance of Request');
    }

    if (!(this._ctx.response instanceof Response)) {
      throw GE.InvalidArgumentException.invalidParameter('Invalid argument: `response` must be an instance of Response');
    }

    if (this._ctx.request.intended() !== 'POST') {
      throw new GE.HttpException('Invalid request: method must be POST', 400, 'E_REQUEST_METHOD');
    }

    if (!this._ctx.request.is('application/x-www-form-urlencoded')) {
      throw new GE.HttpException('Invalid request: content must be application/x-www-form-urlencoded', 400, 'E_rEQUEST_CONTENT');
    }

    let client = await this._getClient()
    return this._handleGrantType(client)
    // return Promise.bind(this)
    //   .then(function (client) {
    //     return this.handleGrantType(request, client);
    //   })
    //   .tap(function (data) {
    //     var model = new TokenModel(data, { allowExtendedTokenAttributes: this.allowExtendedTokenAttributes });
    //     var tokenType = this.getTokenType(model);

    //     this.updateSuccessResponse(response, tokenType);
    //   }).catch(function (e) {
    //     if (!(e instanceof OAuthError)) {
    //       e = new ServerError(e);
    //     }

    //     this.updateErrorResponse(response, e);

    //     throw e;
    //   });
  }

  /**
   * Attempt to valid the user credentials and then generate a JWT token.
   *
   * @method attempt
   * @async
   *
   * @param  {String} uid
   * @param  {String} password
   * @param  {Object|Boolean} [oauth2Payload]  Pass true when want to attach user object in the payload
   *                                        or set a custom object.
   * @param  {Object}         [oauth2Options]  Passed directly to https://www.npmjs.com/package/jsonwebtoken
   *
   * @return {Object}
   * - `{ type: 'bearer', token: 'xxxx', refreshToken: 'xxxx' }`
   *
   * @example
   * ```js
   * try {
   *   const token = auth.attempt(username, password)
   * } catch (error) {
   *    // Invalid credentials
   * }
   * ```
   *
   * Attach user to the JWT payload
   * ```
   * auth.attempt(username, password, true)
   * ```
   *
   * Attach custom data object to the JWT payload
   * ```
   * auth.attempt(username, password, { ipAddress: '...' })
   * ```
   */
  async attempt(uid, password, oauth2Payload, oauth2Options) {
    const user = await this.validate(uid, password, true)
    return this.generate(user, oauth2Payload, oauth2Options)
  }

  /**
   * Generates a jwt token for a given user. This method doesn't check the existence
   * of the user in the database.
   *
   * @method generate
   * @async
   *
   * @param  {Object} user
   * @param  {Object|Boolean} [oauth2Payload]  Pass true when want to attach user object in the payload
   *                                        or set a custom object.
   * @param  {Object}         [oauth2Options]  Passed directly to https://www.npmjs.com/package/jsonwebtoken
   *
   * @return {Object}
   * - `{ type: 'bearer', token: 'xxxx', refreshToken: 'xxxx' }`
   *
   * @throws {RuntimeException} If jwt secret is not defined or user doesn't have a primary key value
   *
   * @example
   * ```js
   * try {
   *   await auth.generate(user)
   * } catch (error) {
   *   // Unexpected error
   * }
   * ```
   *
   * Attach user to the JWT payload
   * ```
   * auth.auth.generate(user, true)
   * ```
   *
   * Attach custom data object to the JWT payload
   * ```
   * auth.generate(user, { ipAddress: '...' })
   * ```
   */
  async generate(user, oauth2Payload, oauth2Options) {
    /**
     * Throw exception when trying to generate token without
     * jwt secret
     */
    if (!this.oauth2Secret) {
      throw GE.RuntimeException.incompleteConfig(['secret'], 'config/auth.js', 'jwt')
    }

    /**
     * Throw exception when user is not persisted to
     * database
     */
    const userId = user[this.primaryKey]
    if (!userId) {
      throw GE.RuntimeException.invoke('Primary key value is missing for user')
    }

    /**
     * The jwt payload
     *
     * @type {Object}
     */
    let payload = { uid: userId, sub: userId }

    if (oauth2Payload === true) {
      /**
       * Attach user as data object only when
       * oauth2Payload is true
       */
      const data = typeof (user.toJSON) === 'function' ? user.toJSON() : user

      /**
       * Remove password from jwt data
       */
      payload.data = _.omit(data, this._config.password)
    } else if (_.isPlainObject(oauth2Payload)) {
      /**
       * Attach payload as it is when it's an object
       */
      payload = _.assign(payload, oauth2Payload)
    }

    /**
     * Return the generate token
     */
    const token = await this._signToken(payload, oauth2Options)

    return { type: 'Bearer', token, refreshToken: null }
  }

  /**
   * Generate a new JWT token using the refresh token.
   *
   * If chained with {{#crossLink "JwtScheme/newRefreshToken"}}{{/crossLink}},
   * this method will remove the existing refresh token from database and issues a new one.
   *
   * @method generateForRefreshToken
   * @async
   *
   * @param {String} refreshToken
   * @param  {Object|Boolean} [oauth2Payload]  Pass true when want to attach user object in the payload
   *                                        or set a custom object.
   * @param  {Object}         [oauth2Options]  Passed directly to https://www.npmjs.com/package/jsonwebtoken
   *
   * @return {Object}
   * - `{ type: 'bearer', token: 'xxxx', refreshToken: 'xxxx' }`
   *
   * @example
   * ```js
   * await auth.generateForRefreshToken(refreshToken)
   *
   * // create a new refresh token too
   * await auth
   *   .newRefreshToken()
   *   .generateForRefreshToken(refreshToken)
   * ```
   */
  async generateForRefreshToken(refreshToken, oauth2Payload, oauth2Options) {
    const user = await this._serializerInstance.findByToken(this.Encryption.decrypt(refreshToken), 'jwt_refresh_token')
    if (!user) {
      throw CE.InvalidRefreshToken.invoke(refreshToken)
    }

    const token = await this.generate(user, oauth2Payload, oauth2Options)

    /**
     * If user generated a new refresh token, in that case we
     * should revoke the old one, otherwise we should
     * set the refreshToken as the existing refresh
     * token in the return payload
     */
    if (!token.refreshToken) {
      token.refreshToken = refreshToken
    } else {
      await this.revokeTokensForUser(user, [refreshToken], true)
    }

    return token
  }

  /**
   * Check if user is authenticated for the current HTTP request or not. This
   * method will read the token from the `Authorization` header or fallbacks
   * to the `token` input field.
   *
   * Consider user as successfully authenticated, if this
   * method doesn't throws an exception.
   *
   * @method check
   * @async
   *
   * @return {Boolean}
   *
   * @example
   * ```js
   * try {
   *   await auth.check()
   * } catch (error) {
   *   // invalid jwt token
   * }
   * ```
   */
  async check() {
    if (this.user) {
      return true
    }

    const token = this.getAuthHeader()

    /**
     * Verify jwt token and wrap exception inside custom
     * exception classes
     */
    try {
      this.oauth2Payload = await this._verifyToken(token)
    } catch ({ name, message }) {
      if (name === 'TokenExpiredError') {
        throw CE.ExpiredJwtToken.invoke()
      }
      throw CE.InvalidJwtToken.invoke(message)
    }

    this.user = await this._serializerInstance.findById(this.oauth2Payload.sub)

    /**
     * Throw exception when user is not found
     */
    if (!this.user) {
      throw CE.InvalidJwtToken.invoke()
    }

    return true
  }

  /**
   * Same as {{#crossLink "JwtScheme/check:method"}}{{/crossLink}},
   * but doesn't throw any exceptions. This method is useful for
   * routes, where login is optional.
   *
   * @method loginIfCan
   * @async
   *
   * @return {Boolean}
   *
   * @example
   * ```js
 *   await auth.loginIfCan()
   * ```
   */
  async loginIfCan() {
    if (this.user) {
      return true
    }

    const token = this.getAuthHeader()

    /**
     * Do not attempt to check, when token itself is missing
     */
    if (!token) {
      return false
    }

    try {
      return await this.check()
    } catch (error) {
      return false
      // swallow exception
    }
  }

  /**
   * List all refresh tokens for a given user.
   *
   * @method listTokensForUser
   * @async
   *
   * @param  {Object} user
   *
   * @return {Array}
   */
  async listTokensForUser(user) {
    if (!user) {
      return []
    }

    const tokens = await this._serializerInstance.listTokens(user, 'jwt_refresh_token')
    return tokens.toJSON().map((token) => {
      token.token = this.Encryption.encrypt(token.token)
      return token
    })
  }

  /**
   * Login a user as a client. This method will set the
   * JWT token as a header on the request.
   *
   * @param  {Function}    headerFn     - Method to set the header
   * @param  {Function}    sessionFn    - Method to set the session
   * @param  {Object}      user         - User to login
   * @param  {Object}      [oauth2Options] - Passed directly to https://www.npmjs.com/package/jsonwebtoken
   *
   * @method clientLogin
   * @async
   *
   * @return {void}
   */
  async clientLogin(headerFn, sessionFn, user) {
    const { token } = await this.generate(user)
    headerFn('authorization', `Bearer ${token}`)
  }
}

module.exports = OAuth2Scheme
