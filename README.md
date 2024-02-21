# go-fundament

As the name suggests the project can be used as a fundament for you application.

It contains:
* API rate limiter
* Chi router
* Useful middlewares:
    1) IsJSONMiddleware that checks the content of request body for json;
    2) AccessTokenMiddleware that is used for handlers that expect auth token;
* Sign in/Sign up API
* Password update API
* Password reset API
* JWT auth
and many more interesting stuff that can help to create your application faster

Technologies used:
* Go lang
* Mongo DB
* Redis
* Swagger
* Nginx
* Docker
* Docker compose

## Local development
Let's get started! Clone the project and install utils that
are necessary during the process of development by executing
the following command:
```bash
make install
```

Install `make` if you don't have it. For example, a solution
for debian based Linux distros will be:
```bash
sudo apt-get install build-essential
```
OK, you're ready to go! To see the available aliases from `make`
simply execute:
```bash
make
```

### Generating Go types from openapi spec
```
make gen
```
The generated Go types will be located in
`/app/common/rest/types.go`

### Running project in minimalistic way
```bash
make run_app_simple
```
Check the containers that will be run in `Makefile`

### Running full version of the project
```bash
make run_app_full
```
Check the containers that will be run in `Makefile`

### Connecting to MongoDB locally:
We recommend to use MongoDB Compass as a convenient GUI for mongoDB server.
To connect to a docker container with MongoDB you can use follow URI:
```text
mongodb://root:test@mongo1:27017/test?authSource=admin
```

### Connecting to Redis locally
To connect to Redis server you can use redis-cli:
```bash
redis-cli -h 0.0.0.0 -p 6379
```

### Running linters locally
Linters are one of the most important component in the
development process. To make sure locally that the code
passes checks of linters execute the command:
```bash
make linters_loc
```
It can be very handy to run this command  before merging
your code.

### Tests
Basically we stick to the following testing strategy:
1. Make things simple
2. Use classical school for testing

We have `db` docker container for running tests. So when you're
creating test that involves db interaction just use
the local `db` container. To do it just execute:
```bash
make run_test_env
```
And you will have local db for test purposes. Also, run
`make run_test_env` before running tests locally.

Note that in this case you should set up all the environment variables in your IDE. If you don't want to do this
then use the following alias:
```bash
make run_tests_in_docker
```
This make alias will run all the environment for testing and tests themselves in docker.


Enjoy coding! c:

# Contributors
[GonnaFlyMethod](https://github.com/GonnaFlyMethod),[F0rzend](https://github.com/F0rzend)
