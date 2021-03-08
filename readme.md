# MIX-file header decryption demo

I've thrown together a little demo demonstrating how to decrypt the header of MIX files with encrypted header records. This is intented for developers already familiar with the MIX format, hence I will not document the format here.

To run it make sure you have the latest [Node.js](https://nodejs.org/) version installed and type:
```bash
node mix.js theMixFile.mix
```
*Replace "theMixFile.mix" with the path to the mix file you want to open...*

## Tips on how to implement it in another language
If you want to do the RSA decryption yourself (which is very easy) then you'll need a library for working with [big integers](https://en.wikipedia.org/wiki/Arbitrary-precision_arithmetic). Or if you want a library to do the RSA decryption then you'll have to use a library which allows you to run the raw [RSA algorithm](https://www.di-mgt.com.au/rsa_alg.html) without a [padding scheme](https://en.wikipedia.org/wiki/Padding_(cryptography)) in the [ECB mode](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook_(ECB)).

Blowish on the other hand is much easier to implement since it's just doing some simple uint32 arithmetic. Here you'll also need to use it without a padding scheme and in ECB mode as well.

## The End

Well, that's all for now. For more details just look at my code and the comments I wrote in it. I tried to make it very easy to understand, hence I don't need to explain more in this readme.

Oh, btw. Credits to [Olaf van der Spek](https://github.com/OlafvdSpek/) for the global mix database (which I would love to know how he created btw).
