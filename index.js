var _ = require('underscore'),
    colors = require('colors'),
    crypto = require('crypto'),
    request = require('request'),
    querystring = require('querystring');


function AndYetMiddleware() {
    var self = this;

    this.showHelp = function (message) {
        var output = [
            "\n",
            message.red,
            "_____________________________________________________________",
            "",
            "var express = require('express'),",
            "    auth = require('andyet-express-auth'),",
            "    app = express();",
            "",
            "",
            "app.use(express.cookieParser());",
            "app.use(express.session({ secret: 'keyboard cat' }));",
            "app.use(auth.middleware({",
            "    app: app",
            "    clientId: 'YOUR CLIENT ID',",
            "    clientSecret: 'YOUR CLIENT SECRET',",
            "    defaultRedirect: '/app'",
            "});",
            "",
            "",
            "// a route that requires being logged in with your &yet account",
            "app.get('/my-secured-route', auth.secure(), function (req, res) {",
            "    // req.user is everything we know about the andyet user",
            "    // req.token is now the auth token",
            "    res.send(req.user)",
            "});",
            "_____________________________________________________________",
            "",
            ""
        ].join('\n');
        console.log(output);
    };

    this.middleware = function (config) {
        var self = this;
        if (!config.app || !config.clientId || !config.clientSecret || !config.defaultRedirect) {
            this.showHelp('You have to pass the app, clientId and clientSecret and a default redirect. For example:');
        }

        // store our configs as properties
        _.extend(this, {
            loggedOutRedirect: '/'
        }, config);

        // set our account and API urls
        this.accountsUrl = config.accountsUrl || (config.local ? 'http://localhost:3001' : 'https://apps.andyet.com');
        this.apiUrl = config.apiUrl || (config.local ? 'http://localhost:3000' : 'https://api.shippy.io');
        this.onRefreshToken = config.onRefreshToken || function (user, token, cb) { cb(); };

        // The login route. If we already have a token in the session we'll
        // just continue through.
        this.app.get('/auth', function (req, res) {
            if (req.cookies.accessToken) {
                return res.redirect(self.defaultRedirect);
            }

            res.clearCookie('accessToken');
            req.session.oauthState = crypto.createHash('sha1').update(crypto.randomBytes(4098)).digest('hex');
            // if you pass a next as query string, store it in session
            // so we can know where to come back to.
            if (req.query && req.query.next) {
                req.session.nextUrl = req.query.next;
            }
            req.session.save(function () {
                var url = self.accountsUrl + '/oauth/authorize?' + querystring.stringify({
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
                return response.redirect('/auth/andyet/failed');
            }

            if (result.state != req.session.oauthState) {
                return response.redirect('/auth/andyet/failed');
            }

            request.post({
                url: self.accountsUrl + '/oauth/access_token',
                strictSSL: true,
                form: {
                    code: result.code,
                    grant_type: 'authorization_code',
                    client_id: self.clientId,
                    client_secret: self.clientSecret
                }
            }, function (err, res, body) {
                if (res && res.statusCode === 200) {
                    token = JSON.parse(body);
                    req.token = token;
                    var nextUrl = req.session.nextUrl || self.defaultRedirect || '/';
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
                    response.redirect('/auth/andyet/failed');
                }
            });
        });

        this.app.get('/auth/andyet/failed', function (req, res) {
            res.clearCookie('accessToken');
            res.redirect('/auth');
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

    this.userRequired = function (req, res, next) {
        // Ensure that a user object is available after validating
        // or retrieving a token.
        if (req.session.user) {
            next();
        } else {
            request.get({
                url: self.apiUrl + '/me',
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
                    res.redirect('/auth/andyet/failed');
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
                    url: self.accountsUrl + '/oauth/validate',
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
                    res.redirect('/auth/andyet/failed');
                });
            }
        };
    };
}

module.exports = new AndYetMiddleware();
