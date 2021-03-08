/*
Interesting links:
https://moddingwiki.shikadi.net/wiki/Category:Westwood_Studios_File_Formats
https://forums.cncnet.org/topic/1382-cc1ra1tsra2-basic-guide-to-graphics-modding/
https://forums.cncnet.org/topic/4507-progress-a-detour-into-big-numbers-and-encrypted-headers/
https://forums.cncnet.org/topic/2088-encrypted-mix-file-reading/?do=findComment&comment=21357

From https://moddingwiki.shikadi.net/wiki/MIX_Format_(Westwood) :
Public key:  AihRvNoIbTn85FZRYNZRcT+i6KpU+maCsEqr3Q5q+LDB5tH7Tz2qQ38V
Private key: AigKVje8mROcR8QixnxUEF5b29Curkq01DNDWCdOG99XBqH79OaCiTCB
From https://lapo.it/asn1js/ :
Public key as BigInt:  681994811107118991598552881669230523074742337494683459234572860554038768387821901289207730765589
Private key as BigInt: 86247051199411053334281494167791973621671185637692924135415903833260161802955167952134132543617
*/

import {BetterDataView, bdvFileStreamer} from 'better-data-view'
// import {log} from 'jlc-logger'
import fs from 'fs'
import * as rsa from './rsa.js'
import {Blowfish} from './blowfish.js'

const
  publicRsaKey = 681994811107118991598552881669230523074742337494683459234572860554038768387821901289207730765589n,
  publicRsaExponent = 0x10001n, // (65537)
  idMap = new Map(),
  log = console.log

async function main() {
  log('Loading global mix database...')
  await parseMixDatabase('./globalMixDatabase.dat')
  log('Reading header...')
  const header = await parseMixHeader(process.argv[2])
  log('Content:')
  for (const record of header.records) {
    const {fileId, offset, size} = record
    log({fileId, offset, size}, idMap.get(fileId))
  }
}

main()

async function parseMixHeader(filePath) {
  let header
  const fileStreamer = new bdvFileStreamer(fs, filePath, 'r')
  const dv = new BetterDataView(fileStreamer)
  dv.setByteEndianness(true) // little-endian
  let data = await dv.u16()
  if (data == 0) { // the modern mix format
    data = (await dv.readObject(t_mix_headerFlags)).flags
    if (data.hasEncryption) { // we got an encrypted header then
      data = await dv.readObject(t_mix_headerEncryptedKey)
      // decrypt the RSA encrypted blocks holding the blowfish key
      const bigInt1 = rsa.raw_decryptPublicDataBlock(
        rsa.bigIntFromData(data.keyBlock1),
        publicRsaExponent, publicRsaKey
      )
      const bigInt2 = rsa.raw_decryptPublicDataBlock(
        rsa.bigIntFromData(data.keyBlock2),
        publicRsaExponent, publicRsaKey
      )
      // extract the blowfish key from the resulting data which is now stored as two BigInts
      const blowfishKey = Buffer.concat([
        rsa.dataFromBigInt({bytesToGet: 40, reverseByteOrder: true}, bigInt1).slice(0, -1), // first part of key
        rsa.dataFromBigInt({bytesToGet: 40, reverseByteOrder: true}, bigInt2).slice(0, 17) // second...
      ]) // the 56 byte blowfish key (which is the maximum key size)
      const dvForEncryptedData = new BetterDataView(new BlowfishDecipherStream(dv, blowfishKey))
      dvForEncryptedData.setByteEndianness(true)
      header = await dvForEncryptedData.readObject(t_mix_header)
    } else {
      header = await dv.readObject(t_mix_header)
    }
  } else { // the legacy mix format
    dv.seekStart()
    header = await dv.readObject(t_mix_header)
  }
  fileStreamer.close()
  return header
}

class BlowfishDecipherStream {
  constructor(dv, key) {
    this.dv = dv
    this.fish = new Blowfish(key)
    this.blockIndex = 7
  }
  async readBytes(offset, length) { // we ignore offset
    for (let i=0; i<length; i++) {
      if (++this.blockIndex == 8) { // we need to get a new block
        this.block = new Uint8Array(this.fish.raw_decrypt(await this.dv.readBytes(8))) // will throw if it didn't get 8 bytes btw
        this.blockIndex = 0
      }
      this.ioBuffer[i] = this.block[this.blockIndex]
    }
    return length
  }
}

async function parseMixDatabase(path) {
  const stream = new bdvFileStreamer(fs, path,'r')
  const dv = new BetterDataView(stream)
  const unknown = await dv.u32()
  let index = 0
  while (true) {
    try {
      const fileName = await dv.readString()
      const comment = await dv.readString()
      const id = genId(fileName)
      //log(index, id, fileName, comment)
      idMap.set(id, fileName+' '+comment)
      index ++
    } catch {break}
  }
}

function genId(fileName) {
  fileName = fileName.toUpperCase()
  let i = 0, id = 0, length = fileName.length
  while (i < length) {
    let a = 0
    for (let j=0; j<4; j++) {
      a >>>= 8
      if (i < length) a = (a + (fileName.codePointAt(i) << 24)) >>> 0
      i++
    }
    id = (((id << 1) >>> 0 | id >>> 31) + a) >>> 0
  }
  return id
}

const t_mix_headerRecord = {
  fileId: 'u32',
  offset: 'u32',
  size: 'u32'
}
const t_mix_header = {
  numFiles: 'u16',
  dataSize: 'u32',
  records: ['list', {length: 'this.numFiles'}, t_mix_headerRecord]
}
const t_mix_headerFlags = {
  flags: ['bitfield', {
    reserved: 8-2, // not used
    hasEncryption: 1,
    hasChecksum: 1,
    reserved2: 8,
  }]
}
const t_mix_headerEncryptedKey = { // the RSA encrypted Blowfish key
  keyBlock1: 'bytes:40',
  keyBlock2: 'bytes:40',
}


