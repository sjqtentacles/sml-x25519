(* demo.sml - X25519 Diffie-Hellman key exchange on the fixed RFC 7748 section
   6.1 test vectors, printing public keys and the shared secret in hex.
   Deterministic: same bytes out on every run and compiler (no RNG, no clock). *)

fun fromHex h = case X25519.fromHex h of SOME b => b | NONE => raise Fail ("bad hex: " ^ h)

(* RFC 7748 section 6.1 private keys *)
val alicePriv = fromHex "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
val bobPriv   = fromHex "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"

(* Public keys: scalar * base point (u = 9). *)
val alicePub = X25519.base alicePriv
val bobPub   = X25519.base bobPriv

(* Shared secret, computed from each side. *)
val s1 = X25519.dh alicePriv bobPub
val s2 = X25519.dh bobPriv alicePub

val () = print "X25519 key exchange (RFC 7748 section 6.1):\n"
val () = print ("  Alice public  = " ^ X25519.toHex alicePub ^ "\n")
val () = print ("  Bob   public  = " ^ X25519.toHex bobPub ^ "\n")
val () = print ("  shared (A*Bpub) = " ^ X25519.toHex s1 ^ "\n")
val () = print ("  shared (B*Apub) = " ^ X25519.toHex s2 ^ "\n")
val () = print ("  secrets agree   = " ^ Bool.toString (s1 = s2) ^ "\n")

(* RFC 7748 section 5.2 single scalar-multiplication vector. *)
val smOut = X25519.dh
  (fromHex "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
  (fromHex "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
val () = print "\nSingle scalar multiplication (RFC 7748 section 5.2):\n"
val () = print ("  result = " ^ X25519.toHex smOut ^ "\n")
