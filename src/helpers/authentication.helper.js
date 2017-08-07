//Authenticate Router
//Username and Password Login

//imports
var mysql      = require('mysql');
var connection = mysql.createConnection({
  host     : 'hashdb.c5mqjhqvtirx.us-west-2.rds.amazonaws.com',
  port     : '3306',
  user     : 'wildappsadmin',
  password : '180770150270',
  database : 'wildappshashes'
});

var jwt = require('jsonwebtoken');
var tokenService = require('bleuapp-token-service').createTokenHandler('service.token', '50051');

var authenticator = {};

authenticator.authenticate = function(call, callback){
  //call.request._id && call.request.password - check password matches through encryption service
  if(call.request._id && call.request.password){
    //id and password exists
    //fetch hash
    connection.connect(function(err) {
      if (err) {
        console.log(err);
        callback({message:'0001 - Failed to connect to the database'},null);
      }else{
        var query = "SELECT hash FROM hashes WHERE _id = '" + call.request._id + "'";
        connection.query(query, function(error, results){
          if(err){
            callback({message:'0002 - Failed to run query against the database'},null);
          }else{
            if(typeof results != 'undefined'){
              if(results.length != 0){
                //id exists
                //make call to encryption service to check if they match
                var grpc = require("grpc");
                var encryptionDescriptor = grpc.load(__dirname + '/proto/encryption.proto').encryption;
                var encryptionClient = new encryptionDescriptor.EncryptionService('service.encryption:1295', grpc.credentials.createInsecure());
                encryptionClient.checkPassword(results[0],function(err, response){
                  if(err){
                    callback(err,null);
                  }else{
                    callback(null,{authenticated:response.match});
                  }
                });
                callback(null,{authenticated:true});
              }else{
                //no results
                callback({message:'0012 - No user exists with that id'},null);
              }
            }else{
              callback({message:'0012 - No user exists with that id'},null);
            }
          }

          connection.end();
        });
      }

    });
  }
}


module.exports = authenticator;
