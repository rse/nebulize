/*
**  Nebulize -- Nebulize Security-Sensitive Information
**  Copyright (c) 2018-2021 Dr. Ralf S. Engelschall <rse@engelschall.com>
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

const Nebulize = require("..")

describe("Nebulize API", () => {
    it("API availability", () => {
        const ds = new Nebulize()
        expect(ds).to.be.a("object")
        expect(ds).to.respondTo("nebulize")
    })
    it("base functionality", () => {
        const ds = new Nebulize()
        ds.filter("", "foo", "bar")
        ds.filter("foo", "foo", "bar")
        ds.filter("bar.baz", "baz", "quux")
        ds.filter("quux", 7, 42)
        expect(ds.nebulize("foo")).to.be.equal("bar")
        expect(ds.nebulize({ foo: "foo", bar: { baz: "baz" }, quux: 7 }))
            .to.be.deep.equal({ foo: "bar", bar: { baz: "quux" }, quux: 42 })
    })
    it("regexp functionality", () => {
        const ds = new Nebulize()
        ds.filter("", /b.r/, "baz")
        ds.filter("", "pw1", "<P:$0:>")
        ds.filter("", /(pw2)/, "<B:$1:>")
        expect(ds.nebulize("foobarbArquux")).to.be.equal("foobazbazquux")
        expect(ds.nebulize("foopw1bar")).to.be.equal("foobbb06556-0c53-5503-8493-9872c02a48fabar")
        expect(ds.nebulize("foopw2barpw2quux")).to.be.equal("foo###bar###quux")
    })
})

