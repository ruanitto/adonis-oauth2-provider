# adonis-oauth2-provider

# BETA

*Implemented:*
password grant
refresh_token grant

# Configurations
In auth.js add:
```javascript
  oauth2: {
    keysPath: Env.get('APP_OAUTHKEY_PATH', 'authkeys'),
    serializer: 'lucidOAuth2', // Can be lucidOAuth2 OR databaseOAuth2
    model: 'App/Models/User',
    scheme: 'oauth2',
    uid: 'email',
    password: 'password',
    refreshTokenLifetime: '14d', // Refresh Token Duration
    allowExtendedTokenAttributes: false,
    requireClientAuthentication: true,
    alwaysIssueNewRefreshToken: true, // Revoke old refresh token
    options: {
      algorithm: 'RS256',
      secret: fs.existsSync(Env.get('APP_OAUTHKEY_PATH', 'authkeys') + '/oauth-private.key') ? fs.readFileSync(Env.get('APP_OAUTHKEY_PATH', 'authkeys') + '/oauth-private.key') : Logger.error('OAuth Keys not found! Please, run `adonis oauth:key` to generate.'),
      public: fs.existsSync(Env.get('APP_OAUTHKEY_PATH', 'authkeys') + '/oauth-public.key') ? fs.readFileSync(Env.get('APP_OAUTHKEY_PATH', 'authkeys') + '/oauth-public.key') : Logger.error('OAuth Keys not found! Please, run `adonis oauth:key` to generate.'),
      expiresIn: Env.get('TOKEN_EXPIRE', '15d'),
      notBefore: 0
    },
    routes_config: {
      register_routes: false, // Define if provider register oauth/token route
      use_prefix: false, // Define if oauthProvider add prefix before oauth/token route
      prefix: null
    }
  }
```

'@ruanitto/adonis-oauth2-provider/providers/OAuth2Provider' - Auth Provider

# Model
*Scope*
```javascript
static scopeFindForOAuth2(builder, username) {
    ...function for search
}
```

*validation*
```javascript
validateForOAuth2(password) {
    ...function for validation
}
```

*Custom route*
Use auth.token() inside route, ex:
```javascript
Route.post('token', ({ auth }) => {
  return auth.token()
})
```

*TODO*
authorization_code grant
client_credentials grant

Views:
Oauth Authentication
Login

Routes
auto instalation
instructions


