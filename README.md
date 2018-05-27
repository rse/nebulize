
Nebulize
========

Nebulize Security-Sensitive Information

<p/>
<img src="https://nodei.co/npm/nebulize.png?downloads=true&stars=true" alt=""/>

<p/>
<img src="https://david-dm.org/rse/nebulize.png" alt=""/>

About
-----

Nebulize is a small JavaScript library, providing the capability to
nebulize security-sensitive information in data by anonymization
(replacing with random-based UUID version 4), pseudonymization
(replacing with hash-based UUID version 5), blacking (replacing with `#`
characters) or substitution (replacing with custom characters). This
nebulization approach is especially intended to support applications in
their filtering of log messages from sensitive information in order to
be compliant to the EU [General Data Protection Regulation (GDPR)](https://en.wikipedia.org/wiki/General_Data_Protection_Regulation).

Installation
------------

```shell
$ npm install nebulize
```

Usage
-----

```js
const Nebulize = require("nebulize")
const expect   = require("chai").expect

let ds = new Nebulize()
ds.filter("**", "foo", "bar")
expect(ds.nebulize("foo")).to.be.equal("bar")
```

Application Programming Interface (API)
---------------------------------------

- `new Nebulize(): Nebulize`:<br/>
  Create a new Nebulize context.

- `Nebulize#filter(pathMatch: string|function,
  dataMatch: RegExp|string|number|boolean|function,
  dataReplace: string|number|boolean|function): Nebulize`:<br/>
  Add a filter to the context.

- `Nebulize#nebulize(data: any): any`:<br/>
  Nebulize arbitrary data based on filters in context.
  The `data` is recursively traversed and all filters
  applied to all leaf data.

License
-------

Copyright (c) 2018 Ralf S. Engelschall (http://engelschall.com/)

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

