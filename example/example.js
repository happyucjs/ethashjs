const Ichash = require('../index.js')

var ichash = new Ichash()
// make the 1000 cache items with a seed of 0 * 32
ichash.mkcache(1000, Buffer.alloc(32).fill(0))

var result = ichash.run(Buffer.from('test'), Buffer.from([0]), 1000)
console.log(result.hash.toString('hex'))
