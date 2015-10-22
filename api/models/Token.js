/**
 * Token.js
 *
 * @description :: Token Model for storing issued Tokens into the Database and other Session related information
 * @docs        :: http://sailsjs.org/#!documentation/models
 */

module.exports = {

    attributes: {

        id: {
            type: 'integer',
            primaryKey: true,
            unique: true,
            autoIncrement: true
        },

        user_id: {
            type: 'integer',
            required: true
        },

        token: {type: 'string'},
        isValid: {type: 'boolean'},
        os: {type: 'string'},
        agent: {type: 'string'},
        device: {type: 'string'},
        latitude: {type: 'string'},
        longitude: {type: 'string'},
        ip: {type: 'string'}

    }
};

