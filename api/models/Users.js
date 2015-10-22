/**
 * Users.js
 *
 * @description :: User Model, defines information related to the Users to be stored
 * @docs        :: http://sailsjs.org/#!documentation/models
 */

// We don't want to store password with out encryption
var bcrypt = require('bcrypt');

module.exports = {

    attributes: {

        user_id: {
            type: 'integer',
            primaryKey: true,
            unique: true,
            autoIncrement: true
        },

        email: {
            type: 'email',
            required: true,
            unique: true // Yes unique one
        },

        encryptedPassword: {type: 'string'},

        isLogged: {type: 'boolean'},
        status: {type: 'boolean'},
        deleted: {type: 'boolean'},

        first_name: {type: 'string'},
        middle_name: {type: 'string'},
        last_name: {type: 'string'},
        birthday: {type: 'date'},
        phone: {type: 'string'},
       
    // We don't wan't to send back encrypted password either
        toJSON: function () {
            var obj = this.toObject();
            delete obj.encryptedPassword;
            return obj;
        }
    },

    // Here we encrypt password before creating a User
    beforeCreate: function (values, next) {
        bcrypt.genSalt(10, function (err, salt) {
            if (err) return next(err);
            bcrypt.hash(values.password, salt, function (err, hash) {
                if (err) return next(err);
                values.encryptedPassword = hash;
                next();
            })
        })
    },

    comparePassword: function (password, user, cb) {
        bcrypt.compare(password, user.encryptedPassword, function (err, match) {
            if (err) cb(err);
            if (match) {
                cb(null, true);
            } else {
                cb(err);
            }
        })
    }
};
