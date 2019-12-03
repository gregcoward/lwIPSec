const http = require('http');
const https = require('https');
var hostname = 'localhost';
var port = '8443';
var myArgs = process.argv.slice(2);
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
const sleep = (waitTimeInMs) => new Promise(resolve => setTimeout(resolve, waitTimeInMs));

//Expect (hostname and/or port) - defaults to 127.0.0.1 8443 
if (myArgs.length == 0) {
    hostname = '127.0.0.1';
} else if (myArgs.length == 1) {
    hostname = myArgs[0];
} else { 
    hostname = myArgs[0];
    port = myArgs[1];
};

const server = http.createServer((req, res) => {
    
    // Validate required http method (POST) was used
    if (req.method == 'POST') {
        let body = '';
        // Capture post body
        req.on('data', chunk => {
            body += chunk.toString(); // Convert Buffer to string
        });
        req.on('end', () => {
            // Validate that input data is valid JSON including required key/value pairs
            try { 
                reqObj = JSON.parse(body);
                v.addSchema(schema, '/tunnelCfg');
                var results = v.validate(reqObj, schema);
                
                // If JSON is valid begin file conf file creations and restart IPSec daemon
                if (results.errors.length == 0) {
                    
                    // Create ipsec.secrets file 
                    var createStream = fs.createWriteStream("/etc/ipsec.secrets");
                    createStream.write(reqObj.sourceAddress + ' ' + reqObj.destinationAddress1 + ' : PSK "' + reqObj.preSharedKey + '"\r');
                    if (reqObj.destinationAddress2 != null) { 
                        createStream.write(reqObj.sourceAddress + ' ' + reqObj.destinationAddress2 + ' : PSK "' + reqObj.preSharedKey + '"\r');
                    };
                    createStream.end();
                    // End of file creation

                    // Create cons.conf file  - is referenced by /etc/ipsec.conf
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
                    // End of file creation
                    
                    // Restart IPSec daemon
                    function puts(error, stdout, stderr) { sys.puts(stdout) }
                    exec("ipsec restart", function(err, stdout, stderr) {});
                    
                    // Output ipsec status to console
                    sleep(5000).then(() => {
                        // This will execute 5 seconds from now
                        exec("ipsec status", function(err, stdout, stderr) {
                            let ts = Date.now();
                            let date_ob = new Date(ts);
                            let date = date_ob.getDate();
                            let month = date_ob.getMonth() + 1;
                            let year = date_ob.getFullYear();
                            console.log('Configuration Update Date - Timestamp: ' + month + "/" + date + "/" + year + ' - ' + ts + '\n');
                            console.log(stdout);
                        });
                    });

                    // Reply to caller with success
                    res.writeHead(200, {'Content-Type': 'text/html'});
                    res.write('The IPSec deployment Updated');
                    res.end();
                } else {

                    // The JSON package was malformed - notify caller
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
        // POST method not used - Return 405 to caller
        res.writeHead(405, {'Content-Type': 'text/html'});
        res.write('Invalid HTTP Method');
        res.end();
};
});
server.listen(port, hostname, () => {
    console.log(`Server running at http://${hostname}:${port}/`);
});
