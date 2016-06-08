'use strict'

const crypto = require('crypto')
const secp256k1 = require('secp256k1')
const nkey = require('nkey')
const type = 'ec'

module.exports = nkey.wrap({
  type,
  genSync,
  fromJSON
})

function genSync () {
  let priv
  do {
    priv = crypto.randomBytes(32)
  } while (!secp256k1.privateKeyVerify(priv))

  return fromJSON({ priv })
}

function fromJSON (opts) {
  if (!(opts.priv || opts.pub)) {
    throw new Error('expected "priv" or "pub"')
  }

  const priv = typeof opts.priv === 'string' ? new Buffer(opts.priv, 'hex') : opts.priv
  const pub = typeof opts.pub === 'string' ? new Buffer(opts.pub, 'hex') : opts.pub || pubFromPriv(priv)
  const privEnc = typeof priv === 'string' && 'hex'
  const pubEnc = typeof pub === 'string' && 'hex'
  const pubKeyString = pub.toString('hex')
  const privKeyString = priv && secp256k1.privateKeyExport(priv)
  const fingerprint = crypto.createHash('sha256').update(pub).digest('hex')

  return nkey.wrap({
    type,
    signSync,
    verifySync,
    hasDeterministicSig: false,
    pubKeyString,
    fingerprint,
    pub,
    priv,
    toJSON
  })

  function signSync (msg) {
    if (!priv) throw new Error('this is a public key')

    let sig = secp256k1.sign(msg, priv)

    // Ensure low S value
    sig = secp256k1.signatureNormalize(sig.signature)

    // Convert to DER array
    return new Buffer(secp256k1.signatureExport(sig)).toString('hex')
  }

  function verifySync (msg, sig) {
    if (typeof sig === 'string') sig = new Buffer(sig, 'hex')

    sig = secp256k1.signatureImport(sig)
    return secp256k1.verify(msg, sig, pub)
  }

  function pubFromPriv (priv) {
    return secp256k1.publicKeyCreate(priv)
  }

  function toJSON (exportPrivate) {
    const obj = {
      type: 'ec',
      curve: 'secp256k1',
      pub: pubKeyString,
      fingerprint
    }

    if (exportPrivate) obj.priv = privKeyString

    return obj
  }
}
