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

var grpc = require("grpc");
var encryptionDescriptor = grpc.load(__dirname + '/../proto/encryption.proto').encryption;
var encryptionClient = new encryptionDescriptor.EncryptionService('service.encryption:1295', grpc.credentials.createInsecure());


var errors = require('../errors/errors.json');

var jwt = require('jsonwebtoken');

var authenticator = {};

authenticator.authenticate = function(call, callback){
  //call.request._id && call.request.password - check password matches through encryption service
  if(call.request._id && call.request.password){
    //id and password exists
    //fetch hash
    pool.getConnection(function(err, connection) {
      if (err) {
        return callback({message:JSON.stringify({code:'02000001', error:errors['0001']})}, null);
      }else{
        var query = "SELECT hash FROM hashes WHERE _id = '" + call.request._id + "'";
        connection.query(query, function(error, results){
          connection.release();
          if(err){
            return callback({message:JSON.stringify({code:'02000002', error:errors['0002']})}, null);
          }else{
            if(typeof results != 'undefined'){
              if(results.length != 0){
                var body = {};
                body.password = call.request.password;
                body.hash = results[0].hash;
                //id exists
                //make call to encryption service to check if they match
                encryptionClient.checkPassword(body,function(err, response){
                  if(err){
                    callback(err,null);
                  }else{
                    callback(null,{authenticated:response.match});
                  }
                });
              }else{
                //no results
                return callback({message:JSON.stringify({code:'02000003', error:errors['0003']})}, null);
              }
            }else{
              return callback({message:JSON.stringify({code:'02010003', error:errors['0003']})}, null);
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
        return callback({message:JSON.stringify({code:'02010001', error:errors['0001']})}, null);
      }else{
        connection.beginTransaction(function(err){
          if(err){
            return callback({message:JSON.stringify({code:'02020001', error:errors['0001']})}, null);
          }
          //hash the password
          encryptionClient.encryptPassword({password:call.request.password},function(err, response){
            if(err){
              callback(err,null);
            }else{
              var query = "INSERT INTO hashes (_id, hash) VALUES (" + call.request._id + ", '" + response.encrypted + "');";
              connection.query(query, function(err, results){
                if(err){
                  connection.rollback(function(){
                    return callback(JSON.stringify({code:'02000004', error:errors['0004']}), null);
                  });
                }else{
                  connection.commit(function(err){
                    if(err){
                      return callback(JSON.stringify({code:'02010004', error:errors['0004']}), null);
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
    return callback({message:JSON.stringify({code:'02000005', error:errors['0005']})}, null);
  }
}

authenticator.update = function(call, callback){
  if(call.request._id && call.request.password){
    pool.getConnection(function(err, connection){
      if (err) {
        return callback({message:JSON.stringify({code:'02020001', error:errors['0001']})}, null);
      }else{
        connection.beginTransaction(function(err){
          if(err){
            return callback({message:JSON.stringify({code:'02030001', error:errors['0001']})}, null);
          }
          //hash the password
          encryptionClient.encryptPassword({password:call.request.password},function(err, response){
            if(err){
              callback(err,null);
            }else{
              var query = "UPDATE hashes SET hash = "+ response.encrypted +" WHERE _id = " + call.request._id + ";";
              connection.query(query, function(err, results){
                if(err){
                  connection.rollback(function(){
                    return callback({message:JSON.stringify({code:'02000006', error:errors['0006']})}, null);
                  });
                }else{
                  connection.commit(function(err){
                    if(err){
                      return callback({message:JSON.stringify({code:'02010006', error:errors['0006']})}, null);
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
    return callback({message:JSON.stringify({code:'02010005', error:errors['0005']})}, null);
  }
}

authenticator.requestReset = function(call,callback){
  if(call.request._id){
    pool.getConnection(function(err, connection){
      if (err) {
        return callback({message:JSON.stringify({code:'02040001', error:errors['0001']})}, null);
      }else{

        require('crypto').randomBytes(48, function(err, buffer) {
          var token = buffer.toString('hex');
          var requestTime = new Date().toISOString().slice(0, 19).replace('T', ' ');
          //store hashed token so password reset requests arent tampered with
          encryptionClient.encryptPassword({password:token},function(err, response){
            if(err){
              callback(err,null);
            }else{
              connection.beginTransaction(function(err){
                if(err){
                  return callback({message:JSON.stringify({code:'02050001', error:errors['0001']})}, null);
                }
                //hash the password

                var query = "INSERT INTO resets (guid, _id, time) VALUES ('" + response.encrypted + "', '" + call.request._id + "', '"+requestTime+"');";
                connection.query(query, function(err, results){
                  if(err){
                    connection.rollback(function(){
                      return callback({message:JSON.stringify({code:'02000006', error:errors['0006']})}, null);
                    });
                  }else{
                    connection.commit(function(err){
                      if(err){
                        return callback({message:JSON.stringify({code:'02010006', error:errors['0006']})}, null);
                      }else{
                        callback(null, {resetSent: true});
                      }
                    })
                  }
                });
              });
            }
          });
        });
        connection.release();
      }
    });
  }else{
    return callback({message:JSON.stringify({code:'02020005', error:errors['0005']})}, null);
  }
}

module.exports = authenticator;
