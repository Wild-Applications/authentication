//Authenticate Router
//Username and Password Login

//imports
var mysql      = require('mysql');
var pool = mysql.createPool({
  connectionLimit   :  10,
  host              : 'hashdb.c5mqjhqvtirx.us-west-2.rds.amazonaws.com',
  port              : '3306',
  user              : 'wildappsadmin',
  password          : '180770150270',
  database          : 'wildappshashes'
});

var jwt = require('jsonwebtoken');

var authenticator = {};

authenticator.authenticate = function(call, callback){
  //call.request._id && call.request.password - check password matches through encryption service
  if(call.request._id && call.request.password){
    //id and password exists
    //fetch hash
    pool.getConnection(function(err, connection) {
      if (err) {
        console.log("Problem connecting to the database");
        callback({message:'0001 - Failed to connect to the database'},null);
      }else{
        console.log("connected to the database");
        var query = "SELECT hash FROM hashes WHERE _id = '" + call.request._id + "'";
        connection.query(query, function(error, results){
          connection.release();
          if(err){
            console.log("Error running query for hash");
            callback({message:'0002 - Failed to run query against the database'},null);
          }else{
            if(typeof results != 'undefined'){
              if(results.length != 0){
                console.log("got hash");
                var body = {};
                body.password = call.request.password;
                body.hash = results[0].hash;
                //id exists
                //make call to encryption service to check if they match
                var grpc = require("grpc");
                var encryptionDescriptor = grpc.load(__dirname + '/../proto/encryption.proto').encryption;
                var encryptionClient = new encryptionDescriptor.EncryptionService('service.encryption:1295', grpc.credentials.createInsecure());
                encryptionClient.checkPassword(body,function(err, response){
                  if(err){
                    console.log("problem checking the password");
                    callback(err,null);
                  }else{
                    console.log("password was checked");
                    console.log(response.match);
                    callback(null,{authenticated:response.match});
                  }
                });
              }else{
                //no results
                callback({message:'0012 - No user exists with that id'},null);
              }
            }else{
              callback({message:'0012 - No user exists with that id'},null);
            }
          }
        });
      }

    });
  }
}

authenticator.store = function(call,callback){
  if(call.request._id && call.request.password){
    pool.getConnection(function(err, connection){
      if (err) {
        callback({message:'0001 - Failed to connect to the database'},null);
        return;
      }else{
        connection.beginTransaction(function(err){
          if(err){
            callback({message:'0001 - Failed to connect to the database'}, null);
            return;
          }
          //hash the password
          var grpc = require("grpc");
          var encryptionDescriptor = grpc.load(__dirname + '/../proto/encryption.proto').encryption;
          var encryptionClient = new encryptionDescriptor.EncryptionService('service.encryption:1295', grpc.credentials.createInsecure());

          encryptionClient.encryptPassword({password:call.request.password},function(err, response){
            if(err){
              callback(err,null);
            }else{
              var query = "INSERT INTO hashes (_id, hash) VALUES (" + call.request._id + ", '" + response.encrypted + "');";
              connection.query(query, function(err, results){
                if(err){
                  connection.rollback(function(){
                    callback({message:"testing"},null);
                    return;
                  });
                }else{
                  //password stored successfully
                  callback(null, {stored:true});
                }
              });
            }
          });
        });
        connection.release();
      }
    });
  }else{
    callback({message:"0007 - Not all parameters were supplied"},null);
    return;
  }
}

module.exports = authenticator;
