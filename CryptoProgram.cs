using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;

public class CryptoProgram
{
    public static void Main()
    {
        Console.WriteLine("=== Starting Encryption ===");
        // First perform encryption
        var (requestSignatureEncryptedValue, symmetricKeyEncryptedValue, originalJwt) = PerformEncryption();

        Console.WriteLine("\nEncrypted Values:");
        Console.WriteLine($"RequestSignatureEncryptedValue: {requestSignatureEncryptedValue}");
        Console.WriteLine($"SymmetricKeyEncryptedValue: {symmetricKeyEncryptedValue}");
        Console.WriteLine($"Original JWT: {originalJwt}");
        // Then perform decryption
        string testRequestSignatureEncryptedValue = "EZ+uFo7aKqFKFmHFzSAPHJPp7ZBTccSOK2Rfoe8WKWNokQiUve2ZPK2tgon/ccSMgZlOgRny1T1aHq04MVw4Oxxm1T3Vv1WSOrkDSu2Swyfwl+4XD1a26JHruDBZmrJ8MB4eGEcYDh9RUIOn6D/SvjzbAkjrjYBW1eGNflFQpezEGnQYa+jt0Ihjx7aQlQHZb4xat3t+o7zkvoPBIr4T6P2PEFgaO6YKInUs1DFM/Flxrdat0AcTS+YBIwtnbX30ZUN2GSvJnlRux8tz3iwk52imjpU5XYBPJQF8oBsU92k7Pmu/vLpheUF+zzCWjew6B0Vad3Lmb57TRzY0tbhUTllSfjJROW2ouFre5i+G9WPSmaH5rCXgWfZGKTJiHdsvK1nik+It4lOWsngX03rHsOEQ6wDTBFFlI/icG99IABGaGoHoYdbg260vYqFceSVLWgH7/52jeHtIOFi5gS4kMilr8QPTzpo2sjGzeaSF+7f5IMFxPPZGumhdvsljdEnmVDQwOZY1M0Bt93RhStgrHbW3UjiFVZn9iEhF0ZTfgeXurmcrciuj8aDLqArfNlzU9kr7XZ43weDg9lVCGCffmux3zsy/RjFo9PPTXtoNDAp7aC96kBScX0Q4AMufbmxN3kRj01ahbPvTQw8jhVoVvcC+Rsuqh4qncFMxFFioPRr/uhGVhNa1A8NWrygJM/7EJCYpq3Vl3HqHm1J+dVOH6F3KqukoGv7pYcVGd+V6o/5LIOiXyYoDVPCvALbbJ2cpunHIEBta/0AoMfVAJyDmR9uFZ4Vl46ZjoB3sD8NilHrA9ju6gbIFfTiviD+Lu2EAx+IKn+VVEJzVgFB4Xi8vS7VdpGsF019sUMTcNzN7esFkr1O7UHv43fUsY+KopM1QkCOlJWj4flGkyELW4cmckNTWNz2j3VD6VF8I8RitvbL+8SeEZWe+Yd3GrXjGoe1GJC272OYrhFjAtLwqgCUHj13me2V8uGoaHFiPfhWBYV+22MIKzd9wQuWj+bIdBbCiGIxP1gx9/Ceg/1WhY2Mk2tiat/jbh8uERWHg4dg4YXKTcTP3mxcXdQ5sydpJLkMs3G/PU9+iurE1jSdc8krB5asyodSsIm7+/al5BNfPD8NCMTjrSUkjgYDvtxNo+MtSCEAZxxwy57prxZvNmOJJM9sy6Ro9Kvuk8yf5MnGxYHa+Ebl0ZGA7+WCYYIFQyGC7CU/EFSS0X+MKXih3jL1FpYHUNNnecGzKw0OBQY49+DF97scegSpxRWTXgMbHXDbO";
string testSymmetricKeyEncryptedValue = "CjRWhLWRBscL+XyjdJFTJGWhuhnScLBsyQVjZqiwJnimqq9zXEa4enJyPW5p3jYqIpcGftro72/uNjiBjYv4X+JiUiJIvo+WtDbHaGNUM1aF5QHE+ifx3avDqxFTVfgujw91T44rToxnM/LaBJPafANY59EOo5UGfR51RYHO67P1S83lyA5T5qEx5TQCKcv1P00nv3eR3K8apLEh0alW6CtHC9Jq8Lp0YPHv+4wWJvWfU9XYabH1rV87IxAf+a+2reaIvsuPbLEwkcVIeqUPm3LjbunmBEFKYAQTSf1crF1s1OhppdjOyLrm6UH+gmH0IfOlnZchVdCRZU3av51aaw==";

        string decryptedJwt = PerformDecryption(requestSignatureEncryptedValue, symmetricKeyEncryptedValue);

        Console.WriteLine("\nDecrypted JWT: " + decryptedJwt);
        string[] jwtencoded = decryptedJwt.Split(".");
        string header_encoded = jwtencoded[0];
        string payload_encoded = jwtencoded[1];
        string signature_encoded = jwtencoded[2];
        Console.WriteLine("Header Encrypted " + header_encoded);
        Console.WriteLine("Payload Encrypted " + payload_encoded);
        string header_decoded = Base64UrlDecode(header_encoded);
        string payload_decoded = Base64UrlDecode(payload_encoded);
        Console.WriteLine("Header Decoded " + header_decoded);
        Console.WriteLine("Payload Decoded " + payload_decoded);
        Console.WriteLine("\nVerifying results:");
        Console.WriteLine($"Encryption and Decryption match: {originalJwt == decryptedJwt}");
    }

    private static (string requestSignature, string symmetricKey, string originalJwt) PerformEncryption()
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

        string payloadJson = JsonConvert.SerializeObject(payload);
        string headerJson = @"{
            ""alg"": ""RS256"",
            ""typ"": ""JWT""
        }";

        using (RSA rsa = LoadPrivateKey("privatekey.pem"))
        {
            byte[] signature = SignData(ComputeSha256Hash(payloadJson), rsa);
            string jwt = CreateJwtToken(headerJson, payloadJson, signature);

            // Remove this line:
            // string jwtBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(jwt));

            string iv = GenerateRandomAlphanumericString(16);
            string symmetricKey = GenerateRandomAlphanumericString(32);

            RSA pubKey = LoadPublicKey(File.ReadAllText("publickey.pem"));

            // Encrypt the JWT directly without Base64 encoding it first
            string encryptedJwt = Encrypt(jwt, symmetricKey, iv);
            string symmetricKeyEncrypted = EncryptKeyWithRSA(symmetricKey, pubKey);

            return (encryptedJwt, symmetricKeyEncrypted, jwt);
        }
    }

    private static string PerformDecryption(string encryptedValue, string encryptedSymmetricKey)
    {
        RSA priv_key = LoadPrivateKey("privatekey.pem");
        byte[] decryptedSymmetricKey = Decrypt_RSA(encryptedSymmetricKey, priv_key);

        byte[] responseBytes = Convert.FromBase64String(encryptedValue);
        byte[] iv = new byte[16];
        byte[] encryptedData = new byte[responseBytes.Length - 16];

        Array.Copy(responseBytes, 0, iv, 0, 16);
        Array.Copy(responseBytes, 16, encryptedData, 0, encryptedData.Length);

        return Decrypt_AES(encryptedData, decryptedSymmetricKey, iv);
    }

    public static string Base64UrlDecode(string input)
    {
        string output = input;
        output = output.Replace('-', '+').Replace('_', '/');
        switch (output.Length % 4) // Pad with '=' characters
        {
            case 0: break; // No padding needed
            case 2: output += "=="; break; // Two pad characters
            case 3: output += "="; break; // One pad character
            default: throw new Exception("Illegal base64url string!");
        }
        var converted = Convert.FromBase64String(output); // Standard base64 decoder
        return Encoding.UTF8.GetString(converted);
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
    private static RSA LoadPrivateKey(string filePath)
    {
        using (var reader = File.OpenText(filePath))
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
    public static string Decrypt_AES(byte[] cipherTextBytes, byte[] key, byte[] iv)
    {
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = key;
            aesAlg.IV = iv;
            aesAlg.Mode = CipherMode.CBC;
            aesAlg.Padding = PaddingMode.None; // Disable automatic padding

            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            using (MemoryStream msDecrypt = new MemoryStream(cipherTextBytes))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (MemoryStream ms = new MemoryStream())
                    {
                        csDecrypt.CopyTo(ms);
                        byte[] decryptedBytes = ms.ToArray();
                        // Manually remove PKCS7 padding
                        return Encoding.UTF8.GetString(RemovePkcs7Padding(decryptedBytes));
                    }
                }
            }
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
    public static byte[] Decrypt_RSA(string encryptedText, RSA privateKey)
    {
        byte[] encryptedBytes = Convert.FromBase64String(encryptedText);
        byte[] decryptedBytes = privateKey.Decrypt(encryptedBytes, RSAEncryptionPadding.Pkcs1);
        return decryptedBytes;
    }
    private static string Encrypt(string plaintext, string keyString, string ivString)
    {
        byte[] key = Encoding.UTF8.GetBytes(keyString);
        byte[] iv = Encoding.UTF8.GetBytes(ivString);
        byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);

        int blockSize = 16;
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

            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    csEncrypt.Write(paddedPlaintext, 0, paddedPlaintext.Length);
                    csEncrypt.FlushFinalBlock();
                }

                byte[] encryptedBytes = msEncrypt.ToArray();
                byte[] result = new byte[iv.Length + encryptedBytes.Length];
                Array.Copy(iv, 0, result, 0, iv.Length);
                Array.Copy(encryptedBytes, 0, result, iv.Length, encryptedBytes.Length);

                return Convert.ToBase64String(result);
            }
        }
    }
    private static byte[] RemovePkcs7Padding(byte[] data)
    {
        int paddingLength = data[data.Length - 1];
        if (paddingLength < 1 || paddingLength > 16)
        {
            throw new ArgumentException("Incorrect padding");
        }

        // Validate padding
        for (int i = data.Length - paddingLength; i < data.Length; i++)
        {
            if (data[i] != paddingLength)
            {
                throw new ArgumentException("Incorrect padding");
            }
        }

        byte[] result = new byte[data.Length - paddingLength];
        Array.Copy(data, 0, result, 0, data.Length - paddingLength);
        return result;
    }

}
