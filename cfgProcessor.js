const http = require('http');
const hostname = '206.124.129.60';
const port = 5000;
var fs = require("fs");
var exec = require('child_process').exec;
var Validator = require('jsonschema').Validator;
var v = new Validator();
var schema = {
    "id": "/tunnelCfg",
    "type": "object",
    "properties": {
      "sourceAddress": {"type": "string"},
      "destinationAddress1": {"type": "string"},
      "destinationAddress2": {"type": "string"},
      "preSharedKey": {"type": "string"},
      "srcSubnet": {"type": "string"},
      "destinationSubnet": {"type": "string"}
    },
    "required": [
        "sourceAddress",
        "destinationAddress1",
        "preSharedKey",
        "srcSubnet",
        "destinationSubnet"
    ]
};

const server = http.createServer((req, res) => {
    if (req.method == 'POST') {
        
        let body = '';
        req.on('data', chunk => {
            body += chunk.toString(); // convert Buffer to string
        });
        req.on('end', () => {
            try {
 
                reqObj = JSON.parse(body);
                v.addSchema(schema, '/tunnelCfg');
                var results = v.validate(reqObj, schema);
                if (results.errors.length == 0) {
                    
                    //Move to separate function - secFileCreate
                    var createStream = fs.createWriteStream("/etc/ipsec.secrets");
                    console.log(reqObj.preSharedKey);
                    createStream.write(reqObj.sourceAddress + ' ' + reqObj.destinationAddress1 + ' : PSK "' + reqObj.preSharedKey + '"\r');
                    if (reqObj.destinationAddress2 != null) { 
                        createStream.write(reqObj.sourceAddress + ' ' + reqObj.destinationAddress2 + ' : PSK "' + reqObj.preSharedKey + '"\r');
                    };
                    createStream.end();
                    // End of separate function

                    //Move to separate function - tunnelFileCreate
                    var createStream2 = fs.createWriteStream("/etc/ipsec.d/cons.conf");
                    createStream2.write('\n\nconn premtoazure');
                    createStream2.write('\n left=' + reqObj.sourceAddress);      
                    createStream2.write('\n leftsubnet=' + reqObj.srcSubnet);
                    createStream2.write('\n right=' + reqObj.destinationAddress1);
                    createStream2.write('\n rightsubnet=' + reqObj.destinationSubnet);
                    createStream2.write('\n');
                                       
                    if (reqObj.destinationAddress2 != null) { 
                        createStream2.write('\n\nconn premtoazure2');
                        createStream2.write('\n left=' + reqObj.sourceAddress);     
                        createStream2.write('\n leftsubnet=' + reqObj.srcSubnet);
                        createStream2.write('\n right=' + reqObj.destinationAddress2);
                        createStream2.write('\n rightsubnet=' + reqObj.destinationSubnet);
                    };
                    createStream2.end();
                    // End of separate function 
                    
                    function puts(error, stdout, stderr) { sys.puts(stdout) }
                    exec("sudo ipsec restart", function(err, stdout, stderr) {
                       console.log(stdout);
                    });

                    res.writeHead(200, {'Content-Type': 'text/html'});
                    res.write('Success: Configuration Updated');
                    res.end();
                } else {
                    res.writeHead(400, {'Content-Type': 'text/html'});
                    res.write('Malformed JSON');
                    console.log(results.errors);
                    res.end();
                 }
 
            } catch(err) {
                console.log(err);
                res.writeHead(400, {'Content-Type': 'text/html'});
                res.write('Malformed JSON');
                res.end();
 
            };
        });
    }
    else {
        res.writeHead(200, {'Content-Type': 'text/html'});
        res.write('Invalid HTTP Method');
        console.log(req.method);
        res.end();
};
});
server.listen(port, hostname, () => {
    console.log(`Server running at http://${hostname}:${port}/`);
});