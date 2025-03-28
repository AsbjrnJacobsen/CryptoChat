using System;
using System.Security.Cryptography;
using System.Text;

namespace CryptoChat;

public class ECDHHelper
{
    public static ECDiffieHellman CreateECDH(out byte[] publicKey)
    {
        var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        publicKey = ecdh.PublicKey.ExportSubjectPublicKeyInfo();
        return ecdh;
    }

    public static byte[] DeriveSharedKey(ECDiffieHellman ecdh, byte[] otherPublicKey)
    {
        using var otherEcdh = ECDiffieHellman.Create();
        otherEcdh.ImportSubjectPublicKeyInfo(otherPublicKey, out _);
        
        // Derive shared secret
        byte[] rawSharedKey = ecdh.DeriveKeyMaterial(otherEcdh.PublicKey);
        
        // Hash the shared secret to get fixed length AES key (256bits)
        using var sha256 = SHA256.Create();
        return sha256.ComputeHash(rawSharedKey);
        
        
        // If not hashing the shared secret, use the line below.
        //return ecdh.DeriveKeyMaterial(otherEcdh.PublicKey);
    }
}