var request = require('supertest');
var token;
var util = require('util');
describe('UsersController', function () {

    describe('#create()', function () {
        it('should create a user', function (done) {
            request(sails.hooks.http.app)
                .post('/users/create/')
                .send({email: 'test@test.com', password: 'a555555', confirmPassword: 'a555555'})
                .expect(200, done);
        });
    });

    describe('#login()', function () {
        it('should login', function (done) {
            request(sails.hooks.http.app)
                .get('/users/login/?email=test@test.com&password=a555555')
                .send({"email": "test@test.com", "password": "a555555"})
                .expect(200)
                .end(function (err, res) {
                    if (res) {
                        token = res.body.session.token;
                    }
                    done();
                })
        })
    });

    describe('#delete()', function () {
        it('should destroy a user', function (done) {
            var t = "Bearer " + token;
            request(sails.hooks.http.app)
                .get('/users/deleteUser')
                .set('Authorization', t)
                .expect(200, done);
        })
    })
});
