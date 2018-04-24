const Huchash = require('../index.js')
const hucHashUtil = require('../util.js')
const hucUtil = require('happyucjs-util')
const Header = require('happyucjs-block/header.js')
const tape = require('tape')
const powTests = require('happyucjs-testing').tests.powTests.huchash_tests

var huchash = new Huchash()
var tests = Object.keys(powTests)

tape('POW tests', function (t) {
  tests.forEach(function (key) {
    var test = powTests[key]
    var header = new Header(new Buffer(test.header, 'hex'))

    var headerHash = huchash.headerHash(header.raw)
    t.equal(headerHash.toString('hex'), test.header_hash, 'generate header hash')

    var epoc = hucHashUtil.getEpoc(ethUtil.bufferToInt(header.number))
    t.equal(ethHashUtil.getCacheSize(epoc), test.cache_size, 'generate cache size')
    t.equal(ethHashUtil.getFullSize(epoc), test.full_size, 'generate full cache size')

    huchash.mkcache(test.cache_size, new Buffer(test.seed, 'hex'))
    t.equal(huchash.cacheHash().toString('hex'), test.cache_hash, 'generate cache')

    var r = huchash.run(headerHash, new Buffer(test.nonce, 'hex'), test.full_size)
    t.equal(r.hash.toString('hex'), test.result, 'generate result')
    t.equal(r.mix.toString('hex'), test.mixhash, 'generate mix hash')
  })
  t.end()
})
