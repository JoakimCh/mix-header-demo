/*
Do not encrypt anything with these raw functions thinking that you'll achieve security, for that you'll need to use a padding scheme. See: https://en.wikipedia.org/wiki/Padding_(cryptography)

Every argument to the raw functions needs to be a BigInt and that's also what's returned. Check the helper functions bigIntFromData and dataFromBigInt.

Helpful links:
https://www.di-mgt.com.au/rsa_alg.html
https://stackoverflow.com/questions/58146853/get-the-congruence-of-big-numbers-javascript-rsa-algorithm/66439973
https://crypto.stackexchange.com/a/15184/87436

In calculations:
m is known as the plaintext message (the original data)
c is known as the ciphertext (the encrypted data)
n is known as the modulus (usually the public key)
e is known as the public exponent (usually set to 65537 / 0x10001)
d is known as the secret exponent (usually the private key)
*/

// From: https://stackoverflow.com/questions/30694842/exponentiation-by-squaring
function powermod(base, exponent, modulus) {
  if (base < 0n || exponent < 0n || modulus < 1n) return -1n
  let result = 1n
  while (exponent > 0n) {
    if ((exponent % 2n) == 1n) result = (result * base) % modulus
    base = (base * base) % modulus
    exponent = exponent / 2n
  }
  return result
} 

function rsaAlgorithm(base, exponent, modulus) {
  return powermod(base, exponent, modulus)
  // return base**exponent % modulus // not a good idea, the power would be too large a number in real world usage (CPU hangs)
}

/** Encrypt a block where the public exponent together with the public key can decrypt it. */
export function raw_encryptPublicDataBlock(data, secretExponent, publicKey) {
  return rsaAlgorithm(data, secretExponent, publicKey)
}
/** Decrypt a block where it has been encrypted using a secret exponent together with a public key. */
export function raw_decryptPublicDataBlock(data, publicExponent, publicKey) {
  if (data >= publicKey) throw Error('Can\'t decrypt data larger than the publicKey (as BigInt\'s).')
  return rsaAlgorithm(data, publicExponent, publicKey)
}
/** Encrypt a block where only the secret exponent together with public key can decrypt it, e.g. when Bob wants Alice to send him something others must not be able to decode. */
export function raw_encryptSecretDataBlock(data, publicExponent, publicKey) {
  if (data >= publicKey) throw Error('Can\'t encrypt data larger than the publicKey (as BigInt\'s).')
  return rsaAlgorithm(data, publicExponent, publicKey)
}
/** Decrypt a block where only the secret exponent together with public key can decrypt it. */
export function raw_decryptSecretDataBlock(data, secretExponent, publicKey) {
  return rsaAlgorithm(data, secretExponent, publicKey)
}

// It will not copy underlying buffers, instead it will create a view into them.
function dataToUint8Array(data) {
  let uint8array
  if (data instanceof ArrayBuffer || Array.isArray(data)) {
    uint8array = new Uint8Array(data)
  } else if (ArrayBuffer.isView(data)) { // DataView or TypedArray
    uint8array = new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
  } else if (data instanceof Buffer) { // Node.js Buffer
    uint8array = new Uint8Array(data.buffer, data.byteOffset, data.length)
  } else {
    throw Error('Data is not an ArrayBuffer, TypedArray, DataView or a Node.js Buffer.')
  }
  return uint8array
}

export function bigIntFromData(data, reverseByteOrder) {
  const uint8array = dataToUint8Array(data)
  let i = 0n, big = 0n
  if (reverseByteOrder) {
    for (let i=0n; i<BigInt(uint8array.length); i++) {
      const byte = uint8array[uint8array.length-Number(i)-1]
      big |= BigInt(byte) << (8n * i)
    }
  } else {
    for (let i=BigInt(uint8array.length-1); i>=0; i--) {
      big |= BigInt(uint8array[i]) << (8n * i)
    }
  }
  return big
}

export function dataFromBigInt({bytesToGet, reverseByteOrder}, ...bigints) {
  if (!bytesToGet) throw Error('Please specify amount of bytes to get')
  let data = []
  for (const number of bigints) {
    if (typeof number != 'bigint') throw Error('Number must be a standard BigInt')
    if (reverseByteOrder) {
      for (let i=0n; i<BigInt(bytesToGet); i++) {
        data.push(Number((number >> i*8n) & 0xFFn))
      }
    } else {
      for (let i=BigInt(bytesToGet-1); i>=0; i--) {
        data.push(Number((number >> i*8n) & 0xFFn))
      }
    }
  }
  return new Uint8Array(data)
}
