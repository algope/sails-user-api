/**
 * UsersController
 *
 * @description :: Server-side logic for managing users
 * @help        :: See http://links.sailsjs.org/docs/controllers
 *
 */

var useragent = require('useragent');
var requestIp = require('request-ip');
var nodemailer = require('nodemailer');
var mg = require('nodemailer-mailgun-transport');
var fs = require('fs');
var ejs = require('ejs');
var bcrypt = require('bcrypt');
var flash = require('express-flash');

module.exports = {

    /**
     * @api {post} /users/create/ Create user
     * @apiVersion 0.1.0
     * @apiName CreateUser
     * @apiGroup User
     *
     * @apiParam {Email} email  Mandatory Email of the user.
     * @apiParam {String} password  Mandatory Password of the User.
     * @apiParam {String} confirmPassword  Mandatory Password confirmation of the User.
     * @apiParam {Boolean} isLogged  Mandatory Online Status of the User.
     * @apiParam {String} [first_name]  Optional First Name of the User.
     * @apiParam {String} [middle_name]  Optional Middle Name of the User.
     * @apiParam {String} [last_name]  Optional Last Name of the User.
     * @apiParam {String} [birthday]  Optional Birthday of the User.
     * @apiParam {String} [phone]  Optional Phone of the User.
     *
     *
     * @apiSuccess {Json} Profile + Token.
     *
     * @apiSuccessExample {json} Success-Response:
     *     HTTP/1.1 200 OK
     *     {
     *      "user": {
     *          "email": "test@test.com",
     *          "createdAt": "2015-08-18T18:05:50.344Z",
     *          "updatedAt": "2015-08-18T18:05:50.344Z",
     *          "user_id": 5
     *      },
     *      "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6NSwiaWF0IjoxNDM5OTIxMTUwLCJleHAiOjE0Mzk5MzE5NTB9.405vilVbToWvvb7drBzibiFht3Sufd8mmHwMfG-qvYE"
     *     }
     *
     */
    create: function (req, res) {
        var agent = useragent.lookup(req.headers['user-agent']);
        if (req.body.password !== req.body.confirmPassword) {
            return res.json(401, {err: 'Password doesn\'t match'});
        }
        Users.create(req.body).exec(function (err, user) {
            if (err) {
                return res.json(err.status, {err: err});
            }
            // If user created successfuly we return user and token as a response
            if (user) {
                var generatedToken = jwToken.issue({id: user.user_id});
                Token.create({
                    token: generatedToken,
                    user_id: user.user_id,
                    isValid: true,
                    os: agent.os.toString(),
                    agent: agent.toAgent(),
                    device: agent.device.toString(),
                    ip: requestIp.getClientIp(req)

                }, function (err, success) {
                    if (err) {
                        sails.log.error("Error updating Token DB entry " + err);
                    }
                    if (success) {

                        sails.log.verbose("Token for User ID: " + user.user_id + " Generated");
                        sails.log.verbose("Issued token for user: " + user.user_id);

                        res.json(200, {user: user, token: generatedToken});
                    }
                });
            }
        });
    },

    /**
     * @api {get} /users/login/ Login The User
     * @apiName Login
     * @apiGroup User
     * @apiVersion 0.1.0
     *
     * @apiParam {Email} email Users Email.
     * @apiParam {String} password Users Password
     *
     * @apiSuccess {String} User Data + Token.
     * @apiSuccessExample Success-Response:
     *     {
     *   "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE0Mzk5MjE0OTAsImV4cCI6MTQzOTkzMjI5MH0.IjUNLzucv-JWfIM7pa0oWJLvIWUllJ59Sh9ozblFhsA"
     *     }
     */
    login: function (req, res) {
        var agent = useragent.lookup(req.headers['user-agent']);
        var ip = requestIp.getClientIp(req);
        var email = req.param('email');
        var password = req.param('password');

        if (!email || !password) {
            return res.json(401, {err: 'email and password required'});
        }

        Users.findOne({email: email}, function (err, user) {

            if (!user) {
                return res.json(401, {err: 'invalid email or password'});
            }
            Users.comparePassword(password, user, function (err, valid) {
                if (err) {
                    return res.json(403, {err: 'forbidden'});
                }

                if (!valid) {
                    return res.json(401, {err: 'invalid email or password'});
                } else {

                    Token.findOne({user_id: user.user_id, isValid: true}, function (err, tokenFound) {
                        if (err) {
                            sails.log.error("Error getting Token from DB: " + err);
                        }

                        if (tokenFound) {
                            sails.log.verbose("Found Token with ID: " + tokenFound.id);
                            Token.update({token: tokenFound.token}, {isValid: false}, function (err, updated) {
                                if (err) {
                                    sails.log.error("Error updating Token DB entry " + err);
                                }
                                if (updated) {
                                    sails.log.verbose("Token id: " + tokenFound.id + " Invalidated");
                                    var generatedToken = jwToken.issue({id: user.user_id});
                                    Token.create({
                                        token: generatedToken,
                                        user_id: user.user_id,
                                        isValid: true,
                                        os: agent.os.toString(),
                                        agent: agent.toAgent(),
                                        device: agent.device.toString(),
                                        ip: ip

                                    }, function (err, success) {
                                        if (err) {
                                            sails.log.error("Error updating Token DB entry " + err);
                                        }
                                        if (success) {

                                            sails.log.verbose("Token for User ID: " + user.user_id + " Generated");
                                            sails.log.verbose("Issued token for user: " + user.user_id);

                                            res.json(200, {
                                                session: success
                                            });
                                        }
                                    });
                                }
                            });

                        } else {
                            var generatedToken = jwToken.issue({id: user.user_id});
                            Token.create({
                                token: generatedToken,
                                user_id: user.user_id,
                                isValid: true,
                                os: agent.os.toString(),
                                agent: agent.toAgent(),
                                device: agent.device.toString(),
                                ip: requestIp.getClientIp(req)

                            }, function (err, success) {
                                if (err) {
                                    sails.log.error("Error updating Token DB entry " + err);
                                }
                                if (success) {

                                    sails.log.verbose("Token for User ID " + user.user_id + " Generated");
                                    sails.log.verbose("Issued token for user: " + user.user_id);

                                    res.json(200, {
                                        session: success
                                    });
                                }
                            });

                        }
                    });
                }
            });
        })
    },


    /**
     * @api {get} /users/logout/ Logout
     * @apiName Logout
     * @apiGroup User
     * @apiVersion 0.1.0
     *
     * @apiHeader {String} token Users unique token for this session
     * @apiHeaderExample {json} Header-Example:
     *  {
     *      "Authorization": Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE0NDAwMDIwMTYsImV4cCI6MTQ0MDAxMjgxNn0.93DssayIgPiZfsI-jJioWVta4CFNVfVHCTM6R5zFKE8
     *  }
     *
     * @apiSuccess {String} Bye message.
     */
    logout: function (req, res) {
        var token = req.headers.authorization;
        var user_id_token = jwToken.getUserId(token);
        Token.findOne({user_id: user_id_token, token: jwToken.getToken(token)}, function (err, tokenFound) {
            if (err) {
                sails.log.verbose("Error invalidating Token, Token not found, clean DB to prevent this again");
                res.json(200, {msg: "Bye!"});
            }

            if (tokenFound) {

                Token.update({token: tokenFound.token}, {isValid: false}, function (err, updated) {
                    if (err) {
                        sails.log.error("Error updating Token DB entry");
                    }

                    if (updated) {
                        sails.log.verbose("Token from User ID " + user_id_token + " Invalidated");
                        res.json(200, {msg: "Bye!"});
                    }

                })
            }
        });

    },

    deleteUser: function (req, res) {
        var token = req.headers.authorization;
        var user_id_token = jwToken.getUserId(token);
        //TODO HardCoded!
        Users.destroy({user_id: user_id_token}, function (err, userDeleted) {
            if (err) {
                sails.log.error("Error deleting a user");
                res.json(500, {msg: "Error"});
            }
            if (!err) {
                res.json(200, {msg: "User deleted"});
            }


        })
    },

    /**
     * @api {post} /users/checkEmail/ Check if email is already registered
     * @apiVersion 0.1.0
     * @apiName CreateUser
     * @apiGroup User
     *
     * @apiParam {Email} email  Mandatory Email of the user.
     *
     * @apiSuccess {Json} code + message.
     *
     * @apiSuccessExample {json} Success-Response:
     *     HTTP/1.1 200 OK
     *     {
     *      "code": 0,
     *      "msg" : "Email not registered"
     *     }
     *
     */
    checkEmail: function (req, res) {
        var email = req.param('email');

        Users.findOne({email: email}, function (err, user) {
            if (err) {
                return res.json(err.status, {err: err});
            }

            if (!user) {
                return res.json(200, {code: 0, msg: 'Email not registered'});
            }
            if (user) {
                return res.json(200, {code: 1, msg: 'Email already exists'})
            }

        })
    },

    resetPassword: function (req, res) {
        var email = req.param('email');
        var auth = {
            auth: {
                api_key: 'yourKey',
                domain: 'yourDomain'
            }
        };

        Users.findOne({email: email}, function (err, user) {
            if (err) {
                return res.json(err.status, {err: err});
            }

            if (user) {
                var nodemailerMailgun = nodemailer.createTransport(mg(auth));
                var template = process.cwd() + '/views/emailTemplates/passwordRecovery/html.ejs';

                var token = jwToken.issue({id: user.user_id});


                var host = req.headers.host;

                var emailLink = "http://" + host + "/users/changePassword/?token=" + token;
                fs.readFile(template, 'utf8', function (err, file) {
                    if (err) return callback(err);

                    var html = ejs.render(file, {emailLink: emailLink});

                    nodemailerMailgun.sendMail({
                        from: 'test@test.com',
                        to: user.email, // An array if you have multiple recipients.
                        subject: 'Seems that you forgot something',
                        'h:Reply-To': 'test@test.com',
                        //You can use "html:" to send HTML email content. It's magic!
                        html: html

                    }, function (err, info) {
                        if (err) {
                            console.log('Error: ' + err);
                        }
                        else {
                            //console.log('Response: ' + info);
                        }
                    });


                });
            }
            res.send(200, {msg: "Email sent"});

        })

    },

    changePassword: function (req, res) {

        var token = req.param('token');
        var thisToken = "Bearer " + token;

        var user_id_token = jwToken.getUserId(thisToken);

        Users.findOne({user_id: user_id_token}, function (err, user) {
            if (err) {
                return res.json(err.status, {err: err});
            }

            if (user) {
                res.view('resetPassword', {token: token});
            }
        })


    },

    modifyPassword: function (req, res) {
        var token = req.body.token;
        var thisToken = "Bearer " + token;
        var user_id_token = jwToken.getUserId(thisToken);
        if (req.body.password !== req.body.confirmPassword) {
            return res.json(401, {err: 'Password doesn\'t match, What a shame!'});
        }
        var password = req.body.password;

        jwToken.verify(token, function (err, token) {
            if (err) return res.json(401, {err: 'Invalid Token!'});

            if (token) {
                bcrypt.genSalt(10, function (err, salt) {
                    if (err) return next(err);
                    bcrypt.hash(password, salt, function (err, hash) {
                        if (err) sails.log.error("ERROR ecripting password");
                        Users.update({user_id: user_id_token}, {encryptedPassword: hash}, function (err, updated) {
                            if (err) sails.log.error("ERROR UPDATING PASSWORD");
                            res.view('resetPasswordOK');
                        });

                    })
                });

            }

        });
    }

};
