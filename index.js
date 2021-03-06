var _ = require('underscore');
var crypto = require('crypto');
var request = require('request');
var querystring = require('querystring');
var logger;


function AndYetMiddleware() {
    var self = this;

    this.middleware = function (app, opts) {
        var self = this;

        self.app = app;
        self.clientId = opts.id;
        self.clientSecret = opts.secret;
        logger = opts.logger || console;

        if (!self.clientId) {
            logger.error('Missing client ID');
        }
        if (!self.clientSecret) {
            logger.error('Missing client secret');
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
            'apps': 'https://apps.andyet.com',
            'shippy': 'https://api.shippy.io',
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
                var url = self.andyetAPIs.apps + '/oauth/authorize?' + querystring.stringify({
                    response_type: 'code',
                    client_id: self.clientId,
                    state: req.session.oauthState
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
                url: self.andyetAPIs.apps + '/oauth/access_token',
                strictSSL: true,
                form: {
                    code: result.code,
                    grant_type: 'authorization_code',
                    client_id: self.clientId,
                    client_secret: self.clientSecret
                }
            }, function (err, res, body) {
                if (res && res.statusCode === 200) {
                    var token = JSON.parse(body);
                    req.token = token;
                    var nextUrl = req.session.nextUrl || self.successRedirect || '/';
                    delete req.session.nextUrl;
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
                    logger.error('Error requesting access token: %s', err);
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
            } else {
                request.post({
                    url: self.andyetAPIs.apps + '/oauth/validate',
                    strictSSL: true,
                    form: {
                        access_token: cookieToken,
                        client_id: self.clientId,
                        client_secret: self.clientSecret
                    }
                }, function (err, res2, body) {
                    if (res2 && res2.statusCode === 200) {
                        req.token = JSON.parse(body);
                        if (req.token.access_token === cookieToken) {
                            res.cookie('accessToken', req.token.access_token, {
                                maxAge: parseInt(req.token.expires_in, 10) * 1000,
                                secure: req.secure || req.host != 'localhost'
                            });
                            return self.userRequired(req, res, next);
                        }
                    }
                    logger.error('Error validating cached token: %s', err);
                    return self.failed(res);
                });
            }
        };
    };
}

module.exports = new AndYetMiddleware();
