const ircUtil = require('icjs-util')
const ichashUtil = require('./util.js')
const xor = require('buffer-xor')
const BN = ircUtil.BN
const async = require('async')

var Ichash = module.exports = function (cacheDB) {
  this.dbOpts = {
    valueEncoding: 'json'
  }
  this.cacheDB = cacheDB
  this.cache = false
}

Ichash.prototype.mkcache = function (cacheSize, seed) {
  // console.log('generating cache')
  // console.log('size: ' + cacheSize)
  // console.log('seed: ' + seed.toString('hex'))
  const n = Math.floor(cacheSize / ichashUtil.params.HASH_BYTES)
  var o = [ircUtil.sha3(seed, 512)]

  var i
  for (i = 1; i < n; i++) {
    o.push(ircUtil.sha3(o[o.length - 1], 512))
  }

  for (var _ = 0; _ < ichashUtil.params.CACHE_ROUNDS; _++) {
    for (i = 0; i < n; i++) {
      var v = o[i].readUInt32LE(0) % n
      o[i] = ircUtil.sha3(xor(o[(i - 1 + n) % n], o[v]), 512)
    }
  }

  this.cache = o
  return this.cache
}

Ichash.prototype.calcDatasetItem = function (i) {
  const n = this.cache.length
  const r = Math.floor(ichashUtil.params.HASH_BYTES / ichashUtil.params.WORD_BYTES)
  var mix = Buffer.from(this.cache[i % n])
  mix.writeInt32LE(mix.readUInt32LE(0) ^ i, 0)
  mix = ircUtil.sha3(mix, 512)
  for (var j = 0; j < ichashUtil.params.DATASET_PARENTS; j++) {
    var cacheIndex = ichashUtil.fnv(i ^ j, mix.readUInt32LE(j % r * 4))
    mix = ichashUtil.fnvBuffer(mix, this.cache[cacheIndex % n])
  }
  return ircUtil.sha3(mix, 512)
}

Ichash.prototype.run = function (val, nonce, fullSize) {
  fullSize = fullSize || this.fullSize
  const n = Math.floor(fullSize / ichashUtil.params.HASH_BYTES)
  const w = Math.floor(ichashUtil.params.MIX_BYTES / ichashUtil.params.WORD_BYTES)
  const s = ircUtil.sha3(Buffer.concat([val, ichashUtil.bufReverse(nonce)]), 512)
  const mixhashes = Math.floor(ichashUtil.params.MIX_BYTES / ichashUtil.params.HASH_BYTES)
  var mix = Buffer.concat(Array(mixhashes).fill(s))

  var i
  for (i = 0; i < ichashUtil.params.ACCESSES; i++) {
    var p = ichashUtil.fnv(i ^ s.readUInt32LE(0), mix.readUInt32LE(i % w * 4)) % Math.floor(n / mixhashes) * mixhashes
    var newdata = []
    for (var j = 0; j < mixhashes; j++) {
      newdata.push(this.calcDatasetItem(p + j))
    }

    newdata = Buffer.concat(newdata)
    mix = ichashUtil.fnvBuffer(mix, newdata)
  }

  var cmix = Buffer.alloc(mix.length / 4)
  for (i = 0; i < mix.length / 4; i = i + 4) {
    var a = ichashUtil.fnv(mix.readUInt32LE(i * 4), mix.readUInt32LE((i + 1) * 4))
    var b = ichashUtil.fnv(a, mix.readUInt32LE((i + 2) * 4))
    var c = ichashUtil.fnv(b, mix.readUInt32LE((i + 3) * 4))
    cmix.writeUInt32LE(c, i)
  }

  return {
    mix: cmix,
    hash: ircUtil.sha3(Buffer.concat([s, cmix]))
  }
}

Ichash.prototype.cacheHash = function () {
  return ircUtil.sha3(Buffer.concat(this.cache))
}

Ichash.prototype.headerHash = function (header) {
  return ircUtil.rlphash(header.slice(0, -2))
}

/**
 * Loads the seed and the cache given a block nnumber
 * @method loadEpoc
 * @param number Number
 * @param cb function
 */
Ichash.prototype.loadEpoc = function (number, cb) {
  var self = this
  const epoc = ichashUtil.getEpoc(number)

  if (this.epoc === epoc) {
    return cb()
  }

  this.epoc = epoc

  // gives the seed the first epoc found
  function findLastSeed (epoc, cb2) {
    if (epoc === 0) {
      return cb2(ircUtil.zeros(32), 0)
    }

    self.cacheDB.get(epoc, self.dbOpts, function (err, data) {
      if (!err) {
        cb2(data.seed, epoc)
      } else {
        findLastSeed(epoc - 1, cb2)
      }
    })
  }

  /* eslint-disable handle-callback-err */
  self.cacheDB.get(epoc, self.dbOpts, function (err, data) {
    if (!data) {
      self.cacheSize = ichashUtil.getCacheSize(epoc)
      self.fullSize = ichashUtil.getFullSize(epoc)

      findLastSeed(epoc, function (seed, foundEpoc) {
        self.seed = ichashUtil.getSeed(seed, foundEpoc, epoc)
        var cache = self.mkcache(self.cacheSize, self.seed)
        // store the generated cache
        self.cacheDB.put(epoc, {
          cacheSize: self.cacheSize,
          fullSize: self.fullSize,
          seed: self.seed,
          cache: cache
        }, self.dbOpts, cb)
      })
    } else {
      // Object.assign(self, data)
      self.cache = data.cache.map(function (a) {
        return Buffer.from(a)
      })
      self.cacheSize = data.cacheSize
      self.fullSize = data.fullSize
      self.seed = Buffer.alloc(data.seed)
      cb()
    }
  })
  /* eslint-enable handle-callback-err */
}

Ichash.prototype._verifyPOW = function (header, cb) {
  var self = this
  var headerHash = this.headerHash(header.raw)
  var number = ircUtil.bufferToInt(header.number)

  this.loadEpoc(number, function () {
    var a = self.run(headerHash, Buffer.from(header.nonce, 'hex'))
    var result = new BN(a.hash)
    cb(a.mix.toString('hex') === header.mixHash.toString('hex') && (ircUtil.TWO_POW256.div(new BN(header.difficulty)).cmp(result) === 1))
  })
}

Ichash.prototype.verifyPOW = function (block, cb) {
  var self = this
  var valid = true

  // don't validate genesis blocks
  if (block.header.isGenesis()) {
    cb(true)
    return
  }

  this._verifyPOW(block.header, function (valid2) {
    valid &= valid2

    if (!valid) {
      return cb(valid)
    }

    async.eachSeries(block.uncleHeaders, function (uheader, cb2) {
      self._verifyPOW(uheader, function (valid3) {
        valid &= valid3
        if (!valid) {
          cb2(Boolean(valid))
        } else {
          cb2()
        }
      })
    }, function () {
      cb(Boolean(valid))
    })
  })
}
