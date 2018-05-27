/*
**  Nebulize -- Nebulize Security-Sensitive Information
**  Copyright (c) 2018 Ralf S. Engelschall <rse@engelschall.com>
**
**  Permission is hereby granted, free of charge, to any person obtaining
**  a copy of this software and associated documentation files (the
**  "Software"), to deal in the Software without restriction, including
**  without limitation the rights to use, copy, modify, merge, publish,
**  distribute, sublicense, and/or sell copies of the Software, and to
**  permit persons to whom the Software is furnished to do so, subject to
**  the following conditions:
**
**  The above copyright notice and this permission notice shall be included
**  in all copies or substantial portions of the Software.
**
**  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
**  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
**  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
**  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
**  CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
**  TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
**  SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

/* global module: true */
module.exports = function (grunt) {
    grunt.loadNpmTasks("grunt-contrib-clean")
    grunt.loadNpmTasks("grunt-browserify")
    grunt.loadNpmTasks("grunt-mocha-test")
    grunt.loadNpmTasks("grunt-eslint")
    grunt.initConfig({
        eslint: {
            options: {
                configFile: "eslint.yaml"
            },
            "nebulize": [ "src/**/*.js", "tst/**/*.js" ]
        },
        browserify: {
            "nebulize-browser": {
                files: {
                    "lib/nebulize.browser.js": [ "src/**/*.js" ]
                },
                options: {
                    transform: [
                        [ "babelify", {
                            presets: [
                                [ "env", {
                                    "targets": {
                                        "browser": [ "last 8 versions", "> 1%", "ie 9" ]
                                    }
                                } ]
                            ]
                        } ],
                        [ "uglifyify", { sourceMap: false, global: true } ],
                    ],
                    plugin: [
                        [ "browserify-derequire" ],
                        [ "browserify-header" ]
                    ],
                    browserifyOptions: {
                        standalone: "Nebulize",
                        debug: false
                    }
                }
            },
            "nebulize-node": {
                files: {
                    "lib/nebulize.node.js": [ "src/**/*.js" ]
                },
                options: {
                    transform: [
                        [ "babelify", {
                            presets: [
                                [ "env", {
                                    "targets": {
                                        "node": [ "8.0.0" ]
                                    }
                                } ]
                            ]
                        } ]
                    ],
                    plugin: [
                        [ "browserify-derequire" ],
                        [ "browserify-header" ]
                    ],
                    external: [
                        "ducky",
                        "traverse",
                        "minimatch",
                        "pure-uuid"
                    ],
                    browserifyOptions: {
                        standalone: "Nebulize",
                        debug: false
                    }
                }
            }
        },
        mochaTest: {
            "nebulize": {
                src: [ "tst/*.js" ]
            },
            options: {
                reporter: "spec"
            }
        },
        clean: {
            clean: [],
            distclean: [ "node_modules" ]
        }
    })
    grunt.registerTask("default", [ "eslint", "browserify", "mochaTest" ])
}

