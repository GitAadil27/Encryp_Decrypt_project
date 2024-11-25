using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;

public class Program
{
    public static void Main()
    {
        var payload = new
        {
            fetchbalancerequest = new
            {
                header = new
                {
                    ReqId = GenerateRandomAlphanumericString(16),
                    EnqDtTm = "2020-07-08 16:21:42",
                    ClientCode = "XYZ",
                    UserId = "472262141734",
                    Password = GenerateRandomAlphanumericString(32),
                    ReservedFieldH1 = "Reserved Header Data"
                },
                details = new
                {
                    ReservedFieldD1 = "Reserved Details Data"
                }
            }
        };

        string transactionId = "19112024120715237425";
        string oAuthTokenValue = "KSSgaV3cXASLGddKZqfaCsUZcc3T";
        string idTokenJwt = ""; // Placeholder for actual JWT token
        string payloadJson = JsonConvert.SerializeObject(payload);
        string headerJson = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
        string Scope = "CITY";

        using (RSA rsa = LoadPrivateKey("privatekey.pem"))
        {
            byte[] signature = SignData(ComputeSha256Hash(payloadJson), rsa);
            string jwt = CreateJwtToken(headerJson, payloadJson, signature);

            string iv = GenerateRandomAlphanumericString(16);
            string symmetricKey = GenerateRandomAlphanumericString(32);
            string publicKeyString = @"-----BEGIN PUBLIC KEY-----
            MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnC4JGhL18119wlf7vKm5
            fUwn3mUUmrrhKJErz5rgy4JRTisAJX2vFMYNajYrFs9+g4Gw+ZVuoYNh+EyNA6V5
            4nLtMWhCNet+2EziJiZn3GaP5LK6D+EFutNsi4MASORckk4Tue7M4dwde+aTBcip
            ddxJSObD7zcMP869KtI6pGzsCWJ0r6fR9/1N6x8QIL6qbioeTrAqPzhGLc880Ndz
            SroxtoA20iy27G1IjyaNJ19apAM7HRFHk9Fb6qLMs9SOVoJ/q4MvEzug8oQcc3EG
            +64Vh9Eke3vvVqMc4crxNPlj0Bmt8nFm+/ilrFs2LICOGh7B4pnAQw/GGkqhcUWE
            RQIDAQAB
            -----END PUBLIC KEY-----";
            RSA pubKey = LoadPublicKey(publicKeyString);

            // Encrypt the JWT directly without Base64 encoding it first
            string encryptedJwt = Encrypt(jwt, symmetricKey, iv);
            string symmetricKeyEncrypted = EncryptKeyWithRSA(symmetricKey, pubKey);

            var output = new
            {
                RequestSignatureEncryptedValue = encryptedJwt,
                SymmetricKeyEncryptedValue = symmetricKeyEncrypted,
                Scope,
                TransactionId = transactionId,
                OAuthTokenValue = oAuthTokenValue,
                Id_token_jwt = idTokenJwt
            };

            string outputJson = JsonConvert.SerializeObject(output, Formatting.Indented);
            Console.WriteLine(outputJson);
        }
    }
    
    private static string EncryptKeyWithRSA(string keyToEncrypt, RSA publicKey)
    {
    byte[] keyBytes = Encoding.UTF8.GetBytes(keyToEncrypt);
    byte[] encryptedKey = publicKey.Encrypt(keyBytes, RSAEncryptionPadding.Pkcs1);
    return Convert.ToBase64String(encryptedKey);
    }
    private static RSA LoadPublicKey(String publicKeyString)
    {
      var rsa = RSA.Create();
      rsa.ImportFromPem(publicKeyString);
      return rsa;
    }

    private static RSA LoadPrivateKey(string filePath)
    {
        using (var reader = System.IO.File.OpenText(filePath))
        {
            var privateKey = new StringBuilder();
            string line;
            while ((line = reader.ReadLine()) != null)
            {
                privateKey.AppendLine(line);
            }

            var rsa = RSA.Create();
            rsa.ImportFromPem(privateKey.ToString());
            return rsa;
        }
    }

    private static byte[] ComputeSha256Hash(string rawData)
    {
        using (SHA256 sha256Hash = SHA256.Create())
        {
            return sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(rawData));
        }
    }

    private static byte[] SignData(byte[] hash, RSA rsa)
    {
        return rsa.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    public static string CreateJwtToken(string header, string payload, byte[] signature)
    {
        return $"{Base64UrlEncode(Encoding.UTF8.GetBytes(header))}.{Base64UrlEncode(Encoding.UTF8.GetBytes(payload))}.{Base64UrlEncode(signature)}";
    }

    public static string Base64UrlEncode(byte[] input)
    {
        string output = Convert.ToBase64String(input);
        output = output.Split('=')[0]; // Remove any trailing '='s
        output = output.Replace('+', '-'); // Replace '+' with '-'
        output = output.Replace('/', '_'); // Replace '/' with '_'
        return output;
    }

    public static string GenerateRandomAlphanumericString(int size)
    {
        const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        byte[] data = new byte[size];
        using (RNGCryptoServiceProvider crypto = new RNGCryptoServiceProvider())
        {
            crypto.GetBytes(data);
        }
        StringBuilder result = new StringBuilder(size);
        foreach (byte b in data)
        {
            result.Append(chars[b % chars.Length]);
        }
        return result.ToString();
    }

    private static string Encrypt(string plaintext, string keyString, string ivString)
{
    byte[] key = Encoding.UTF8.GetBytes(keyString);
    byte[] iv = Encoding.UTF8.GetBytes(ivString);
    byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);

    // Add PKCS7 padding manually
    int blockSize = 16; // AES block size is 16 bytes
    int padSize = blockSize - (plaintextBytes.Length % blockSize);
    if (padSize == 0) padSize = blockSize;

    byte[] paddedPlaintext = new byte[plaintextBytes.Length + padSize];
    Array.Copy(plaintextBytes, paddedPlaintext, plaintextBytes.Length);
    for (int i = plaintextBytes.Length; i < paddedPlaintext.Length; i++)
    {
        paddedPlaintext[i] = (byte)padSize;
    }

    using (Aes aesAlg = Aes.Create())
    {
        aesAlg.Key = key;
        aesAlg.IV = iv;
        aesAlg.Mode = CipherMode.CBC;
        aesAlg.Padding = PaddingMode.None;

        ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

        // Create result array to hold IV and encrypted data
        using (MemoryStream msEncrypt = new MemoryStream())
        {
            msEncrypt.Write(iv, 0, iv.Length); // Write IV first

            using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
            {
                csEncrypt.Write(paddedPlaintext, 0, paddedPlaintext.Length);
                csEncrypt.FlushFinalBlock();
            }

            byte[] fullResult = msEncrypt.ToArray();
            return Convert.ToBase64String(fullResult);
        }
    }
}

}
