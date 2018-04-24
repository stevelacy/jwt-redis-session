

var _ = require("lodash"),
  jwt = require("jsonwebtoken"),
  uuid = require("uuid");

var extendSession = function(session, data){
  _.reduce(data, function(memo, val, key){
    if(typeof val !== "function" && key !== "id")
      memo[key] = val;
    return memo;
  }, session);
};

var serializeSession = function(session){
  return _.reduce(session, function(memo, val, key){
    if(typeof val !== "function" && key !== "id")
      memo[key] = val;
    return memo;
  }, {});
};

// these are bound to the session
module.exports = function(options){

  var SessionUtils = function(){};

  _.extend(SessionUtils.prototype, {

    // create a new session and return the jwt
    create: function(claims, opts, callback){
      if(typeof claims === "function" && !callback){
        callback = claims;
        claims = {};
      }
      if(typeof opts === "function" && !callback){
        callback = claims;
        claims = {};
        opts = {};
      }
      opts = _.extend(options, opts);
      var self = this,
        sid = uuid.v4();
      var token = jwt.sign(_.extend({ jti: sid }, claims || {}), opts.secret, { algorithm: opts.algorithm });
      opts.client.setex(opts.keyspace + self.user.id + ':' + sid, opts.maxAge, JSON.stringify(serializeSession(self)), function(error){
        self.id = sid;
        callback(error, token);
      });
    },

    // update the TTL on a session
    touch: function(callback){
      var self = this;
      if(!this.id){
        return process.nextTick(function(){
          callback(new Error("Invalid session ID"));
        });
      }
      options.client.expire(options.keyspace + self.user.id + ':' + this.id, options.maxAge, callback);
    },

    // update a session's data, update the ttl
    update: function(callback){
      var self = this;
      if(!this.id){
        return process.nextTick(function(){
          callback(new Error("Invalid session ID"));
        });
      }
      options.client.setex(options.keyspace + self.user.id + ':' + this.id, options.maxAge, JSON.stringify(serializeSession(this)), callback);
    },

    // reload a session data from redis
    reload: function(callback){
      var self = this;
      if(!this.id){
        return process.nextTick(function(){
          callback(new Error("Invalid session ID"));
        });
      }

      options.client.get(options.keyspace + self.user.id + ':' + self.id, function(error, resp){
        if(error)
          return callback(error);
        try{
          resp = JSON.parse(resp);
        }catch(e){
          return callback(e);
        }
        extendSession(self, resp);
        callback();
      });
    },

    // destroy a session
    destroy: function(callback){
      var self = this;
      if(!this.id){
        return process.nextTick(function(){
          callback(new Error("Invalid session ID"));
        });
      }
      options.client.del(options.keyspace + self.user.id + ':' + this.id, callback);
    },

    toJSON: function(){
      return serializeSession(this);
    }

  });

  return SessionUtils;
};
