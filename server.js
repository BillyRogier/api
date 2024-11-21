const http = require('http');
const app = require('./app');
app.set('port',process.env.PORT || 3000);
const server = http.createServer(app);
server.listen(process.env.PORT || 3000);
server.on('listening', () => {
    const address = server.address();
    //const bind = typeof address === 'string' ? 'pipe ' + address : 'port ' + port;
    console.log('Listening on 3000');
});