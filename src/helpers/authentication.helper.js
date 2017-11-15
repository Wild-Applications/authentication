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

/*authenticator.update = function(call, callback){
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
}*/

authenticator.requestReset = function(call,callback){
  if(call.request._id){
    pool.getConnection(function(err, connection){
      if (err) {
        return callback({message:JSON.stringify({code:'02040001', error:errors['0001']})}, null);
      }else{
        var token = randomStringAsBase64Url(48).substring(0,48);
        var requestTime = new Date().toISOString().slice(0, 19).replace('T', ' ');

        var hash = crypto.createHash('sha1').update(token).digest('hex');


        connection.beginTransaction(function(err){
          if(err){
            return callback({message:JSON.stringify({code:'02050001', error:errors['0001']})}, null);
          }
          var query = "INSERT INTO resets (guid, _id, time) VALUES ('" + hash + "', '" + call.request._id + "', '"+requestTime+"');";
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
    return callback({message:JSON.stringify({code:'02020005', error:errors['0005']})}, null);
  }
}

authenticator.resetPassword = function(call, callback){
  if(call.guid && call.guid.length > 0 && call.request.password > 0){
    pool.getConnection(function(err, connection){
        if(err){
          return callback({message: JSON.stringify({code:'02050001', error: errors['0001']})}, null);
        }
        //guid is stored as a hash
        //hash the passed guid so we can retrieve the user id from the database
        var hash = crypto.createHash('sha1').update(call.request.guid).digest('hex');

        connection.beginTransaction(function(err){
          if(err){
            connection.release();
            return callback({message:JSON.stringify({code:'02060001', error:errors['0001']})}, null);
          }
          var query = "SELECT * FROM resets WHERE guid = '"+hash+"';";
          connection.query(query, function(err, results){
            if(err){
              connection.release();
              return callback({message:JSON.stringify({code:'02001002', error:errors['0006']})}, null);
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
                    var query = "UPDATE hashes SET hash = "+ response.encrypted +" WHERE _id = " + results[0]._id + ";";
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
                            callback(null, {reset: true});
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
                      return callback({message:JSON.stringify({code:'02000008', error:errors['0008']})}, null);
                    });
                  }else{
                    return callback({message:JSON.stringify({code:'02010008', error:errors['0008']})}, null);
                  }
                });
              }
            }else{
              connection.release();
              return callback({message:JSON.stringify({code:'02000007', error:errors['0007']})}, null);
            }
          });
        });
    });
  }
}

/*authenticator.resetPassword = function(call, callback){
  if(call.request.guid && call.request.password){
    pool.getConnection(function(err, connection){
      if (err) {
        return callback({message:JSON.stringify({code:'02050001', error:errors['0001']})}, null);
      }else{
        //hash the guid
        var hash = crypto.createHash('sha1').update(call.request.guid).digest('hex');

        connection.beginTransaction(function(err){
          if(err){
            return callback({message:JSON.stringify({code:'02060001', error:errors['0001']})}, null);
          }
          var query = "SELECT * FROM resets WHERE guid = '" + hash + "';";
          connection.query(query, function(err, results){
              if(err){
                return callback({message:JSON.stringify({code:'02001002', error:errors['0006']})}, null);
              }
              if(typeof results != 'undefined'){
                if(results.length != 0){
                  encryptionClient.encryptPassword({password:call.request.password},function(err, response){
                    if(err){
                      callback(err,null);
                    }else{
                      var query = "UPDATE hashes SET hash = "+ response.encrypted +" WHERE _id = " + results[0]._id + ";";
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
                              callback(null, {reset: true});
                            }
                          })
                        }
                      });
                    }
                  });
                }else{
                  return callback({message:JSON.stringify({code:'02010007', error:errors['0007']})}, null);
                }
              }else{
                return callback({message:JSON.stringify({code:'02000007', error:errors['0007']})}, null);
              }
          });
        });


        connection.release();
      }
    });
  }else{
    return callback({message:JSON.stringify({code:'02030005', error:errors['0005']})}, null);
  }
};
*/

function randomStringAsBase64Url(size) {
  return base64url(crypto.randomBytes(size));
}

module.exports = authenticator;
