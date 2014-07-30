var _ = require('underscore');
var crypto = require('crypto');
var request = require('request');
var querystring = require('querystring');
var validateToken = require('validate-token');
var logger;


function AndYetMiddleware() {
    var self = this;

    this.middleware = function (app, opts) {
        var self = this;

        self.app = app;
        self.clientId = opts.id;
        self.clientSecret = opts.secret;
        self.platformPublicKey = opts.platformPublicKey;
        logger = opts.logger || console;

        if (!self.clientId) {
            logger.error('Missing client ID');
        }
        if (!self.clientSecret) {
            logger.error('Missing client secret');
        }
        if (!self.platformPublicKey) {
            logger.error('Missing platform public key');
        }
        if (!opts.successRedirect) {
            logger.warn('Missing successRedirect in settings, using "/"');
        }
        if (!opts.failedRedirect) {
            logger.warn('Missing failedRedirect in settings, using "/signup"');
        }
        if (!opts.api) {
            logger.warn('Missing api in settings, using "shippy"');
        }

        self.andyetAPIs = _.extend({
            'login': 'https://login.andyet.com',
            'apps': 'https://apps.andyet.com',
            'shippy': 'https://api.cowboy.io',
            'talky': 'https://api.talky.io'
        }, opts.andyetAPIs || {});

        self.api = opts.api || 'shippy';
        self.successRedirect = opts.successRedirect || '/';
        self.failedRedirect = opts.failedRedirect || '/signup';
        self.loggedOutRedirect = opts.loggedOutRedirect || '/';
        self.onRefreshToken = opts.onRefreshToken || function (user, token, cb) { cb(); };

        // The login route. If we already have a token in the session we'll
        // just continue through.
        this.app.get('/auth', function (req, res) {
            if (req.cookies.accessToken) {
                return res.redirect(self.successRedirect);
            }

            res.clearCookie('accessToken');
            req.session.oauthState = crypto.createHash('sha1').update(crypto.randomBytes(4098)).digest('hex');
            // if you pass a next as query string, store it in session
            // so we can know where to come back to.
            if (req.query && req.query.next) {
                req.session.nextUrl = req.query.next;
            }
            req.session.save(function () {
                var url = self.andyetAPIs.login + '/authorize?' + querystring.stringify({
                    response_type: 'code',
                    client_id: self.clientId,
                    state: req.session.oauthState,
                    scope: 'openid profile'
                });
                res.redirect(url);
            });
        });

        this.app.get('/auth/andyet/callback', function (req, response) {
            var result = querystring.parse(req.url.split('?')[1]);

            if (result.error) {
                logger.error('Failed to parse querystring: ' + result.error);
                return self.failed(response);
            }

            if (result.state != req.session.oauthState) {
                logger.error('OAuth state values do not match: %s != %s', result.state, req.session.oauthState);
                return self.failed(response);
            }

            request.post({
                url: self.andyetAPIs.login + '/token',
                strictSSL: true,
                auth: {
                    user: self.clientId,
                    pass: self.clientSecret
                },
                form: {
                    code: result.code,
                    grant_type: 'authorization_code'
                }
            }, function (err, res, body) {
                if (res && res.statusCode === 200) {
                    var token = JSON.parse(body);
                    req.token = token;
                    var nextUrl = req.session.nextUrl || self.successRedirect || '/';
                    delete req.session.nextUrl;

                    if (token.error) {
                        logger.error('Error requesting access token: %s: %s', token.error, JSON.stringify(token));
                        return self.failed(response);
                    }

                    req.session.save(function () {
                        response.cookie('accessToken', token.access_token, {
                            maxAge: parseInt(token.expires_in, 10) * 1000,
                            secure: req.secure || req.host != 'localhost'
                        });
                        return self.userRequired(req, response, function () {
                            self.onRefreshToken(req.session.user, req.token.refresh_token, function () {
                                response.redirect(nextUrl);
                            });
                        });
                    });
                } else {
                    logger.error('Error requesting access token: %s', err, body);
                    return self.failed(response);
                }
            });
        });

        this.app.get('/logout', function (req, res) {
            req.session.destroy();
            res.clearCookie('accessToken');
            res.redirect(self.loggedOutRedirect);
        });

        return function (req, res, next) {
            next();
        };
    };

    this.failed = function (res) {
        res.clearCookie('accessToken');
        res.redirect(self.failedRedirect);
    };

    this.userRequired = function (req, res, next) {
        // Ensure that a user object is available after validating
        // or retrieving a token.
        if (req.session.user) {
            next();
        } else {
            request.get({
                url: self.andyetAPIs[self.api] + '/me',
                strictSSL: true,
                headers: {
                    authorization: 'Bearer ' + req.token.access_token
                },
                json: true
            }, function (err, res2, body) {
                if (res2 && res2.statusCode === 200) {
                    req.session.user = body;
                    next();
                } else {
                    logger.error('Error requesting user information: %s', err);
                    return self.failed(res);
                }
            });
        }
    };

    this.secure = function () {
        // Check that an access token is available, either in the current
        // session or cached in a cookie. We'll validate cached tokens to
        // ensure that they were issued for our app and aren't expired.
        return function (req, res, next) {
            var cookieToken = req.cookies.accessToken;

            if (!cookieToken) {
                req.session.nextUrl = req.url;
                return res.redirect('/auth');
            } 

            validateToken(cookieToken, {
                public_key: self.platformPublicKey,
                token_type: 'access_token'
            }, function (err, token) {
                if (err) {
                    logger.error('Error validating cached token: %s', err);
                    return self.failed(res);
                }

                req.token = {
                    access_token: cookieToken
                };

                return self.userRequired(req, res, next);
            });
        };
    };
}

module.exports = new AndYetMiddleware();
