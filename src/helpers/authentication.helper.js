//Authenticate Router
//Username and Password Login

//imports
var mysql      = require('mysql');
var pool = mysql.createPool({
  connectionLimit   :  10,
  //host              : 'hashdb.c5mqjhqvtirx.us-west-2.rds.amazonaws.com',
  host              : 'hash.c5mqjhqvtirx.us-west-2.rds.amazonaws.com',
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
        return callback({message:JSON.stringify({code:'0001', message:'Failed to connect to database'})}, null);
      }else{
        var query = "SELECT hash FROM hashes WHERE _id = '" + call.request._id + "'";
        connection.query(query, function(error, results){
          connection.release();
          if(err){
            return callback({message:JSON.stringify({code:'0002', message:'Failed to run query against the database'})}, null);
          }else{
            if(typeof results != 'undefined'){
              if(results.length != 0){
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
                    callback(err,null);
                  }else{
                    console.log(response.match);
                    callback(null,{authenticated:response.match});
                  }
                });
              }else{
                //no results
                return callback({message:JSON.stringify({code:'0012', message:'Username and password did not match'})}, null);
              }
            }else{
              return callback({message:JSON.stringify({code:'0012', message:'Username and password did not match'})}, null);
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
        return callback({message:JSON.stringify({code:'0001', message:'Failed to connect to the database'})}, null);
      }else{
        connection.beginTransaction(function(err){
          if(err){
            return callback({message:JSON.stringify({code:'0001', message:'Failed to connect to the database'})}, null);
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
                    return callback(err, null);
                    return;
                  });
                }else{
                  connection.commit(function(err){
                    if(err){
                      callback(err, null);
                    }else{
                      callback(null, {stored: true});
                    }
                  })
                }
              });
            }
          });
        });
        connection.release();
      }
    });
  }else{
    return callback({message:JSON.stringify({code:'0007', message:'Not all parameters were supplied'})}, null);
  }
}

authenticator.update = function(call, callback){
  if(call.request._id && call.request.password){
    pool.getConnection(function(err, connection){
      if (err) {
        return callback({message:JSON.stringify({code:'0001', message:'Failed to connect to the database'})}, null);
      }else{
        connection.beginTransaction(function(err){
          if(err){
            return callback({message:JSON.stringify({code:'0001', message:'Failed to connect to the database'})}, null);
          }
          //hash the password
          var grpc = require("grpc");
          var encryptionDescriptor = grpc.load(__dirname + '/../proto/encryption.proto').encryption;
          var encryptionClient = new encryptionDescriptor.EncryptionService('service.encryption:1295', grpc.credentials.createInsecure());

          encryptionClient.encryptPassword({password:call.request.password},function(err, response){
            if(err){
              callback(err,null);
            }else{
              var query = "UPDATE hashes SET hash = "+ response.encrypted +" WHERE _id = " + call.request._id + ";";
              connection.query(query, function(err, results){
                if(err){
                  connection.rollback(function(){
                    return callback(err, null);
                    return;
                  });
                }else{
                  connection.commit(function(err){
                    if(err){
                      callback(err, null);
                    }else{
                      callback(null, {stored: true});
                    }
                  })
                }
              });
            }
          });
        });
        connection.release();
      }
    });
  }else{
    return callback({message:JSON.stringify({code:'0007', message:'Not all parameters were supplied'})}, null);
  }
}

module.exports = authenticator;
