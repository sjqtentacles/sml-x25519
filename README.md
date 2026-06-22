# sml-x25519

Curve25519 Diffie-Hellman key exchange (RFC 7748) in pure Standard ML

## Installation

```
smlpkg add github.com/sjqtentacles/sml-x25519
smlpkg sync
```

## Usage

Keys and coordinates are little-endian 32-byte strings (one `char` per byte).

```sml
(* tiny hex helper, as in the test suite *)
fun hexDigit c =
  if c >= #"0" andalso c <= #"9" then Char.ord c - Char.ord #"0"
  else if c >= #"a" andalso c <= #"f" then Char.ord c - Char.ord #"a" + 10
  else raise Fail "bad hex digit"

fun fromHex s =
  CharVector.tabulate
    (String.size s div 2,
     fn i => Char.chr (hexDigit (String.sub (s, 2*i)) * 16
                       + hexDigit (String.sub (s, 2*i + 1))))

(* RFC 7748 section 6.1 vectors *)
val alicePriv = fromHex "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
val bobPriv   = fromHex "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"

(* Public keys: base point (u = 9) scalar multiplication. *)
val alicePub = X25519.base alicePriv
val bobPub   = X25519.base bobPriv

(* Shared secret — identical from both sides (Diffie-Hellman). *)
val s1 = X25519.dh alicePriv bobPub
val s2 = X25519.dh bobPriv   alicePub
(* s1 = s2 = 4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742 *)

(* Scalar clamping per RFC 7748 section 5 (applied automatically inside dh/base). *)
val clamped = X25519.clamp alicePriv
```

### API

| Value | Type | Description |
| --- | --- | --- |
| `keySize` | `int` | Byte length of scalars / coordinates (`32`). |
| `dh` | `string -> string -> string` | `dh scalar uCoord`: X25519 scalar multiplication. |
| `base` | `string -> string` | Public key: `dh scalar basePoint` (u = 9). |
| `clamp` | `string -> string` | RFC 7748 section 5 scalar clamping. |
| `toHex` | `string -> string` | Encode key/coordinate bytes as lowercase hex. |
| `fromHex` | `string -> string option` | Decode hex to bytes; `NONE` on bad input (`fromHex (toHex b) = SOME b`). |

Field arithmetic uses `IntInf.int` over GF(2^255 - 19) via the Montgomery
ladder, so it is portable across MLton and Poly/ML with no overflow concerns.

## Example

`make example` builds and runs [`examples/demo.sml`](examples/demo.sml), which
runs an X25519 key exchange on the fixed RFC 7748 section 6.1 vectors and prints
the public keys and shared secret in hex:

```
$ make example
X25519 key exchange (RFC 7748 section 6.1):
  Alice public  = 8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a
  Bob   public  = de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f
  shared (A*Bpub) = 4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742
  shared (B*Apub) = 4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742
  secrets agree   = true

Single scalar multiplication (RFC 7748 section 5.2):
  result = c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552
```

## Testing

```
make test       # MLton
make test-poly  # Poly/ML
make example    # build + run the demo
```

## License

MIT
