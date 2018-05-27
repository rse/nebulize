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

/*  external requirements  */
const ducky     = require("ducky")
const traverse  = require("traverse")
const minimatch = require("minimatch")
const UUID      = require("pure-uuid")

/* eslint no-console: off */

/*  the API class  */
class Nebulize {
    constructor () {
        this.filters = []
        this.anonmap = {}
    }
    filter (pathMatch, dataMatch, dataReplace) {
        /*  sanity check filter configuration  */
        let errors = []
        if (!ducky.validate(pathMatch, "(string|function)", errors))
            throw new Error(`invalid path match argument: ${errors.join("; ")}`)
        errors = []
        if (!ducky.validate(dataMatch, "(RegExp|string|number|boolean|function)", errors))
            throw new Error(`invalid data match argument: ${errors.join("; ")}`)
        errors = []
        if (!ducky.validate(dataReplace, "(string|number|boolean|function)", errors))
            throw new Error(`invalid data replace argument: ${errors.join("; ")}`)

        /*  sanity-check regular expressions  */
        if (   typeof dataMatch === "object"
            && dataMatch instanceof RegExp
            && typeof dataMatch.flags === "string"
            && dataMatch.flags.indexOf("g") === -1)
            dataMatch = new RegExp(dataMatch.source, `${dataMatch.flags}g`)

        /*  remember filter  */
        this.filters.push({ pathMatch, dataMatch, dataReplace })

        return this
    }
    nebulize (data) {
        if (this.filters.length > 0) {
            /*  match path  */
            const matchPath = (pathMatch, path) => {
                let matched = false
                if (typeof pathMatch === "string")
                    matched = minimatch(path, pathMatch, { dot: true, nocomment: true })
                else if (typeof pathMatch === "function")
                    matched = pathMatch(path)
                return matched
            }

            /*  match data  */
            const matchData = (dataMatch, value) => {
                let matched = false
                let matchings = []
                if (typeof dataMatch === "object" && dataMatch instanceof RegExp) {
                    if (typeof value === "string") {
                        let match
                        while ((match = dataMatch.exec(value)) !== null) {
                            matched = true
                            matchings.push({ index: match.index, match: match })
                        }
                    }
                }
                else if (typeof dataMatch === "string") {
                    if (typeof value === "string") {
                        let pos = 0
                        let idx
                        while ((idx = value.indexOf(dataMatch, pos)) !== -1) {
                            matched = true
                            matchings.push({ index: idx, match: [ dataMatch ] })
                            pos = idx + dataMatch.length
                        }
                    }
                }
                else if (typeof dataMatch === "number" || typeof dataMatch === "boolean")
                    matched = (value === dataMatch)
                else if (typeof dataMatch === "function")
                    matched = dataMatch(value)
                return { matched, matchings }
            }

            /*  change data  */
            let anonmap = this.anonmap
            const changeData = (dataReplace, value, matchings) => {
                let valueNew
                if (typeof dataReplace === "string") {
                    valueNew = ""
                    let pos = 0
                    matchings.forEach((matching) => {
                        valueNew += value.substring(pos, matching.index)
                        let chunk = dataReplace

                        /*  first, expand match-references  */
                        chunk = chunk.replace(/\$(\d+)/g, (_, num) => {
                            num = parseInt(num)
                            if (num <= (matching.match.length - 1))
                                return matching.match[num]
                            else
                                return ""
                        })

                        /*  second, expand value changes  */
                        chunk = chunk.replace(/<([APB]):(.*?):>/g, (_, type, value) => {
                            if (type === "A") {
                                if (anonmap[value] === undefined)
                                    anonmap[value] = (new UUID(4, value)).format()
                                value = anonmap[value]
                            }
                            else if (type === "P")
                                value = (new UUID(5, "ns:URL", value)).format()
                            else if (type === "B")
                                value = "#".repeat(value.length)
                            return value
                        })

                        valueNew += chunk
                        pos = matching.index + matching.match[0].length
                    })
                    valueNew += value.substring(pos)
                }
                else if (typeof dataReplace === "number" || typeof dataReplace === "boolean")
                    valueNew = dataReplace
                else if (typeof dataReplace === "function")
                    valueNew = dataReplace(value, matchings)
                return valueNew
            }

            /*  recursively traverse data and conditionally change it  */
            let filters = this.filters
            data = traverse(data).map(function (value) {
                filters.forEach((filter) => {
                    if (matchPath(filter.pathMatch, this.path.join("."))) {
                        let { matched, matchings } = matchData(filter.dataMatch, value)
                        if (matched) {
                            let valueNew = changeData(filter.dataReplace, value, matchings)
                            if (valueNew !== value)
                                this.update(valueNew)
                        }
                    }
                })
            })
        }
        return data
    }
}

/*  export the API class  */
module.exports = Nebulize

