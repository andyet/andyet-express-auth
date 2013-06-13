var express = require('express'),
    andyet = require('./andyet-express-auth'),
    app = express();

// config our middleware
app.use(express.cookieParser());
app.use(express.session({ secret: 'keyboard cat' }));
app.use(andyet.middleware({
    app: app,
    clientId: 'You can get a client ID and secret from https://apps.andyet.com',
    clientSecret: 'Yup, you should get a client secret too.',
    defaultRedirect: '/secured'
}));

app.get('/', function (req, res) {
    res.send('<a href="/auth">login</a>');
});

app.get('/login', function (req, res) {
    res.send('<h1>Please login</h1><a href="/auth">login</a>');
});

app.get('/secured', andyet.secured, function (req, res) {
    res.send(req.session.user);
});

app.get('/other-secured', andyet.secured, function (req, res) {
    res.send(req.session.user);
});

app.listen(3003);
