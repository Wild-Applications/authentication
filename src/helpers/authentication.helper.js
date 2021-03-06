//Authenticate Router
//Username and Password Login

//imports
var crypto = require('crypto');
var base64url = require('base64url');

var timeHelper = require('./time.helper.js');


var mysql      = require('mysql');
var pool = mysql.createPool({
  connectionLimit   :  10,
  //host              : 'hashdb.c5mqjhqvtirx.us-west-2.rds.amazonaws.com',
  host              : '127.0.0.1',
  port              : '3306',
  user              : process.env.DB_USER,
  password          : process.env.DB_PASS,
  database          : 'authdb'
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
        return callback(errors['0001'], null);
      }else{
        var query = "SELECT hash FROM hashes WHERE _id = '" + call.request._id + "'";
        connection.query(query, function(error, results){
          connection.release();
          if(err){
            return callback(errors['0002'], null);
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
                return callback(errors['0003'], null);
              }
            }else{
              return callback(errors['0003'], null);
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
        return callback(errors['0001'], null);
      }else{
        connection.beginTransaction(function(err){
          if(err){
            return callback(errors['0001'], null);
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
                    return callback(errors['0004'], null);
                  });
                }else{
                  connection.commit(function(err){
                    if(err){
                      return callback(errors['0004'], null);
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
    return callback(errors['0005'], null);
  }
}

authenticator.requestReset = function(call,callback){
  if(call.request._id){
    pool.getConnection(function(err, connection){
      if (err) {
        return callback(errors['0001'], null);
      }else{
        var token = randomStringAsBase64Url(48).substring(0,48);
        var requestTime = new Date().toISOString().slice(0, 19).replace('T', ' ');

        var hash = crypto.createHash('sha1').update(token).digest('hex');


        connection.beginTransaction(function(err){
          if(err){
            return callback(errors['0001'], null);
          }
          var query = "INSERT INTO resets (guid, _id, time) VALUES ('" + hash + "', '" + call.request._id + "', '"+requestTime+"');";
          connection.query(query, function(err, results){
            if(err){
              connection.rollback(function(){
                return callback(errors['0006'], null);
              });
            }else{
              connection.commit(function(err){
                if(err){
                  return callback(errors['0006'], null);
                }else{
                  callback(null, {guid: token});
                }
              })
            }
          });
        });
        connection.release();
      }
    });
  }else{
    return callback(errors['0005'], null);
  }
}

authenticator.resetPassword = function(call, callback){
  if(call.request.guid && call.request.guid.length > 0 && call.request.password.length > 0){
    pool.getConnection(function(err, connection){
        if(err){
          return callback(errors['0001'], null);
        }
        //guid is stored as a hash
        //hash the passed guid so we can retrieve the user id from the database
        var hash = crypto.createHash('sha1').update(call.request.guid).digest('hex');
        console.log("hash ", hash);
        connection.beginTransaction(function(err){
          if(err){
            connection.release();
            return callback(errors['0001'], null);
          }
          var query = "SELECT * FROM resets WHERE guid = '"+hash+"';";
          console.log("query ", query);
          connection.query(query, function(err, results){
            if(err){
              connection.release();
              return callback(errors['0002'], null);
            }
            if(typeof results != 'undefined' && results.length != 0){
              //now check the request hasnt expired
              var isValid = timeHelper.isWithinHours(results[0].time, 4);
              if(isValid){
                //is within the valid time period, so honour the request and reset the password
                encryptionClient.encryptPassword({password:call.request.password},function(err, response){
                  if(err){
                    callback(err,null);
                  }else{
                    var query = "UPDATE hashes SET hash = '"+ response.encrypted +"' WHERE _id = " + results[0]._id + ";";
                    connection.query(query, function(err, results){
                      if(err){
                        console.log(err);
                        connection.rollback(function(){
                          return callback(errors['0006'], null);
                        });
                      }else{
                        connection.commit(function(err){
                          if(err){
                            return callback(errors['0006'], null);
                          }else{
                            callback(null, {reset: true});
                            var deleteQuery = "DELETE FROM resets WHERE guid = '"+hash+"';"
                            connection.query(deleteQuery, function(err, result){
                              if(!err){
                                connection.commit(function(err){

                                });
                              }
                            });
                          }
                        })
                      }
                    });
                  }
                });
              }else{
                var deleteQuery = "DELETE FROM resets WHERE guid = '"+hash+"';"
                connection.query(deleteQuery, function(err, result){
                  if(!err){
                    connection.commit(function(err){
                      return callback(errors['0008'], null);
                    });
                  }else{
                    return callback(errors['0008'], null);
                  }
                });
              }
            }else{
              connection.release();
              return callback(errors['0007'], null);
            }
          });
        });
    });
  }else{
    return callback(errors['0005'], null);
  }
}

authenticator.changePassword = (call, callback) => {
  jwt.verify(call.metadata.get('authorization')[0], process.env.JWT_SECRET, function(err, token){
    if(err){
      return callback({message:err},null);
    }
    if(call.request.original && call.request.new){
      if(call.request.original !== call.request.new){
        pool.getConnection(function(err, connection) {
          if (err) {
            return callback(errors['0001'], null);
          }else{
            var query = "SELECT hash FROM hashes WHERE _id = '" + token.sub + "'";
            connection.query(query, function(error, results){
              if(err){
                return callback(errors['0002'], null);
              }else{
                if(typeof results != 'undefined'){
                  if(results.length != 0){
                    var body = {};
                    body.password = call.request.original;
                    body.hash = results[0].hash;
                    //id exists
                    //make call to encryption service to check if they match
                    encryptionClient.checkPassword(body,function(err, response){
                      if(err){
                        callback(err,null);
                      }else{
                        if(response.match){
                          //original password matched so we can change to new one now.
                          connection.beginTransaction(function(err){
                            if(err){
                              return callback(errors['0001'], null);
                            }
                            //hash the password
                            encryptionClient.encryptPassword({password:call.request.new},function(err, response){
                              if(err){
                                callback(err,null);
                              }else{
                                var query = "UPDATE hashes SET hash = '"+ response.encrypted +"' WHERE _id = " + token.sub + ";"
                                connection.query(query, function(err, results){
                                  if(err){
                                    connection.rollback(function(){
                                      return callback(errors['0004'], null);
                                    });
                                  }else{
                                    connection.commit(function(err){
                                      if(err){
                                        return callback(errors['0004'], null);
                                      }else{
                                        callback(null, {});
                                      }
                                    })
                                  }
                                });
                              }
                            });
                          });
                        }else{
                          //original password wasnt correct so deny request
                          return callback(errors['0009'],null);
                        }
                      }
                    });
                  }else{
                    //no results
                    return callback(errors['0003'], null);
                  }
                }else{
                  return callback(errors['0003'], null);
                }
              }
            });
          }
        });
      }else{
          //new password cant be same as old
          return callback(errors['0010'],null);
      }
    }else{
      return callback(errors['0005'], null);
    }
  });
};


function randomStringAsBase64Url(size) {
  return base64url(crypto.randomBytes(size));
}

module.exports = authenticator;
