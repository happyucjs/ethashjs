# SYNOPSIS 
[![NPM Package](https://img.shields.io/npm/v/icjs-mpt.svg?style=flat-square)](https://www.npmjs.org/package/icjs-mpt)
[![Build Status](https://img.shields.io/travis/icjs/icjs-mpt.svg?branch=master&style=flat-square)](https://travis-ci.org/icjs/icjs-mpt)
[![Coverage Status](https://img.shields.io/coveralls/icjs/icjs-mpt.svg?style=flat-square)](https://coveralls.io/r/icjs/icjs-mpt)
[![Gitter](https://img.shields.io/gitter/room/irchain/icjs-lib.svg?style=flat-square)](https://gitter.im/irchain/icjs-lib) or #icjs on freenode

[![js-standard-style](https://cdn.rawgit.com/feross/standard/master/badge.svg)](https://github.com/feross/standard)  

This is an implementation of the modified merkle patricia tree as specified in the [Ethereum's yellow paper](http://gavwood.com/Paper.pdf).

> The modified Merkle Patricia tree (trie) provides a persistent data structure to map between arbitrary-length binary data (byte arrays). It is defined in terms of a mutable data structure to map between 256-bit binary fragments and arbitrary-length binary data. The core of the trie, and its sole requirement in terms of the protocol specification is to provide a single 32-byte value that identifies a given set of key-value pairs.   
  \- Ethereum's yellow paper  

The only backing store supported is LevelDB through the ```levelup``` module.

# INSTALL
 `npm install icjs-mpt`

# USAGE

## Initialization and Basic Usage

```javascript
var Trie = require('icjs-mpt'),
levelup = require('levelup'),
db = levelup('./testdb'),
trie = new Trie(db); 

trie.put('test', 'one', function () {
  trie.get('test', function (err, value) {
    if(value) console.log(value.toString())
  });
});
```

## Merkle Proofs

```javascript
Trie.prove(trie, 'test', function (err, prove) {
  if (err) return cb(err)
  Trie.verifyProof(trie.root, 'test', prove, function (err, value) {
    if (err) return cb(err)
    console.log(value.toString())
    cb()
  })
})
```

## Read stream on Geth DB

```javascript
var levelup = require('levelup')
var Trie = require('./secure')

var stateRoot = "0xd7f8974fb5ac78d9ac099b9ad5018bedc2ce0a72dad1827a1709da30580f0544" // Block #222

var db = levelup('YOUR_PATH_TO_THE_GETH_CHAIN_DB')
var trie = new Trie(db, stateRoot)

trie.createReadStream()
  .on('data', function (data) {
    console.log(data)
  })
  .on('end', function() { 
    console.log('End.')
  })
```

# API
[./docs/](./docs/index.md)

# TESTING
`npm test`

# REFERENCES

- ["Exploring IrChain's state trie with Node.js"](https://wanderer.github.io/irchain/nodejs/code/2014/05/21/using-irchains-tries-with-node/) blog post
- ["Merkling in Ethereum"](https://blog.irchain.org/2015/11/15/merkling-in-irchain/) blog post
- [Ethereum Trie Specification](https://github.com/irchain/wiki/wiki/Patricia-Tree) Wiki
- ["Understanding the irchain trie"](https://easythereentropy.wordpress.com/2014/06/04/understanding-the-irchain-trie/) blog post
- ["Trie and Patricia Trie Overview"](https://www.youtube.com/watch?v=jXAHLqQthKw&t=26s) Video Talk on Youtube

# LICENSE
MPL-2.0
