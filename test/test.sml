(* test.sml
 *
 * Tests for sml-x25519 against RFC 7748 vectors.
 *)
structure Tests =
struct

  (* ----- local hex <-> bytes helpers ----- *)

  fun hexDigit c =
    if c >= #"0" andalso c <= #"9" then Char.ord c - Char.ord #"0"
    else if c >= #"a" andalso c <= #"f" then Char.ord c - Char.ord #"a" + 10
    else if c >= #"A" andalso c <= #"F" then Char.ord c - Char.ord #"A" + 10
    else raise Fail ("bad hex digit: " ^ String.str c)

  fun fromHex s =
    let
      val n = String.size s
      val () = if n mod 2 <> 0 then raise Fail "odd hex length" else ()
      fun byte i =
        let val hi = hexDigit (String.sub (s, 2 * i))
            val lo = hexDigit (String.sub (s, 2 * i + 1))
        in Char.chr (hi * 16 + lo) end
    in
      CharVector.tabulate (n div 2, byte)
    end

  val hexChars = "0123456789abcdef"
  fun toHex s =
    String.concat
      (List.map
         (fn c =>
            let val v = Char.ord c
            in String.str (String.sub (hexChars, v div 16)) ^
               String.str (String.sub (hexChars, v mod 16))
            end)
         (String.explode s))

  (* ----- RFC 7748 section 6.1 vectors ----- *)

  val alicePriv = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
  val alicePub  = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
  val bobPriv   = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
  val bobPub    = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
  val shared    = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"

  (* RFC 7748 section 5.2 single scalar-mult vector *)
  val smInScalar = "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"
  val smInU      = "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"
  val smOut      = "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"

  (* base point u = 9 (little-endian 32 bytes) *)
  val basePoint = fromHex "0900000000000000000000000000000000000000000000000000000000000000"

  fun run () =
    let
      open Harness
      val () = reset ()
    in
      (* 1. API contract *)
      section "API contract";
      checkInt "keySize is 32" (32, X25519.keySize);
      checkInt "dh output length is 32"
        (32, String.size (X25519.dh (fromHex alicePriv) basePoint));
      checkInt "base output length is 32"
        (32, String.size (X25519.base (fromHex alicePriv)));
      checkInt "clamp output length is 32"
        (32, String.size (X25519.clamp (fromHex alicePriv)));

      (* 2. spec vectors *)
      section "spec vectors";
      checkString "Alice public key (RFC 7748 6.1)"
        (alicePub, toHex (X25519.base (fromHex alicePriv)));
      checkString "Bob public key (RFC 7748 6.1)"
        (bobPub, toHex (X25519.base (fromHex bobPriv)));
      checkString "shared secret = Alice priv * Bob pub"
        (shared, toHex (X25519.dh (fromHex alicePriv) (fromHex bobPub)));
      checkString "shared secret = Bob priv * Alice pub"
        (shared, toHex (X25519.dh (fromHex bobPriv) (fromHex alicePub)));
      checkString "single scalar-mult vector (RFC 7748 5.2)"
        (smOut, toHex (X25519.dh (fromHex smInScalar) (fromHex smInU)));

      (* 3. roundtrip / commutativity *)
      section "roundtrip";
      checkString "DH commutativity (Alice.Bobpub = Bob.Alicepub)"
        (toHex (X25519.dh (fromHex alicePriv) (X25519.base (fromHex bobPriv))),
         toHex (X25519.dh (fromHex bobPriv) (X25519.base (fromHex alicePriv))));
      checkBool "base scalar equals dh scalar basepoint"
        (true,
         X25519.base (fromHex alicePriv) = X25519.dh (fromHex alicePriv) basePoint);

      (* 4. edge cases *)
      section "edge cases";
      let
        val zero = fromHex "0000000000000000000000000000000000000000000000000000000000000000"
        (* clamp(0): byte0 &= 0xF8 -> 0; byte31 &= 0x7F |= 0x40 -> 0x40 *)
        val clampedZero = X25519.clamp zero
      in
        checkInt "clamp clears low 3 bits of byte 0"
          (0, Char.ord (String.sub (clampedZero, 0)));
        checkInt "clamp sets bit 6 / clears bit 7 of byte 31"
          (0x40, Char.ord (String.sub (clampedZero, 31)))
      end;
      let
        val ones = CharVector.tabulate (32, fn _ => Char.chr 0xFF)
        val c = X25519.clamp ones
      in
        checkInt "clamp byte 0: 0xFF & 0xF8 = 0xF8"
          (0xF8, Char.ord (String.sub (c, 0)));
        checkInt "clamp byte 31: (0xFF & 0x7F) | 0x40 = 0x7F"
          (0x7F, Char.ord (String.sub (c, 31)))
      end;

      (* 5. error cases *)
      section "error cases";
      checkRaises "dh rejects short scalar"
        (fn () => X25519.dh (fromHex "00") basePoint);
      checkRaises "dh rejects short u-coordinate"
        (fn () => X25519.dh (fromHex alicePriv) (fromHex "00"));
      checkRaises "base rejects short scalar"
        (fn () => X25519.base (fromHex "0011"));
      checkRaises "clamp rejects wrong length"
        (fn () => X25519.clamp (fromHex "0011"));

      (* 6. properties *)
      section "properties";
      checkBool "clamp is idempotent"
        (true,
         X25519.clamp (X25519.clamp (fromHex alicePriv))
           = X25519.clamp (fromHex alicePriv));
      checkBool "dh ignores unclamped scalar bits (dh s u = dh (clamp s) u)"
        (true,
         X25519.dh (fromHex alicePriv) basePoint
           = X25519.dh (X25519.clamp (fromHex alicePriv)) basePoint);
      checkBool "distinct scalars give distinct public keys"
        (true,
         X25519.base (fromHex alicePriv) <> X25519.base (fromHex bobPriv));

      run ()
    end
end
