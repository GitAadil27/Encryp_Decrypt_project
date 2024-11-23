using System;
using System.Security.Cryptography;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Newtonsoft.Json;

public class EncryptionDemo
{
    public static void Main()
    {
        var payload = new JwtPayload
        {
            {"iss", "issuer"},
            {"sub", "subject"},
            // Add other claims as required
        };

        // Create RSA keys for JWT signing
        using var rsa = RSA.Create();
        rsa.ImportRSAPrivateKey(Convert.FromBase64String(privateKey), out _); // privateKey in Base64
        var signingCredentials = new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256);

        // JWT encoding
        var header = new JwtHeader(signingCredentials);
        header.Add("typ", "JWT");
        var tokenHandler = new JwtSecurityTokenHandler();
        var securityToken = new JwtSecurityToken(header, payload);
        var encodedJwt = tokenHandler.WriteToken(securityToken);

        // Generate random alphanumeric bytes for AES symmetric key and IV
        var symmetricKey = GenerateRandomAlphanumericBytes(32);
        var iv = GenerateRandomAlphanumericBytes(16);

        // Encrypt the symmetric key using RSA
        rsa.ImportRSAPublicKey(Convert.FromBase64String(publicKey), out _); // publicKey in Base64
        var encryptedKey = rsa.Encrypt(symmetricKey, RSAEncryptionPadding.Pkcs1);

        // Encrypt JWT using AES in CBC mode
        using var aes = Aes.Create();
        aes.Key = symmetricKey;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
        var encodedJwtBytes = Encoding.UTF8.GetBytes(encodedJwt);
        var encryptedJwt = EncryptData(encryptor, encodedJwtBytes);

        // Base64 encode the encrypted values
        var symmetricKeyEncryptedValue = Convert.ToBase64String(encryptedKey);
        var requestSignatureEncryptedValue = Convert.ToBase64String(iv.Concat(encryptedJwt).ToArray());

        // Output results as JSON
        var output = new
        {
            RequestSignatureEncryptedValue = requestSignatureEncryptedValue,
            SymmetricKeyEncryptedValue = symmetricKeyEncryptedValue,
            Scope = "CITY",
            TransactionId = "19112024120715237425",
            OAuthTokenValue = "KSSgaV3cXASLGddKZqfaCsUZcc3T",
            IdTokenJwt = ""
        };

        Console.WriteLine(JsonConvert.SerializeObject(output, Formatting.Indented));
    }

    private static byte[] GenerateRandomAlphanumericBytes(int length)
    {
        const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        var random = new Random();
        var bytes = new byte[length];
        for (int i = 0; i < length; i++)
        {
            bytes[i] = (byte)chars[random.Next(chars.Length)];
        }
        return bytes;
    }

    private static byte[] EncryptData(ICryptoTransform encryptor, byte[] data)
    {
        using var ms = new System.IO.MemoryStream();
        using var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write);
        cs.Write(data, 0, data.Length);
        cs.FlushFinalBlock();
        return ms.ToArray();
    }
}
