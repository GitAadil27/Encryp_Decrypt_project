using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;

public class Decryption
{
    public static void Main()
    {
      string ResponseSignatureEncryptedValue = "xpgCXfVwow2TxkldiBqKBd7iCoqsADqzVBi4XAxZXH+bU4Prt8eELCsgDPNIW6r8bilM+T9EcXpZKKJFNWOqcVyy3thcWx1EZPO50h4vYkCimBdXzv9b1lOdU3kPyJeutxvRImmyy1YmgXLZMRITY88uVrPFnzFkoJOWn7gSwS8/zxSa+MSobgFWKqM43e/x3AYBEJENut5Er8FqW1pTgFMxYuCNReMBx1KMuKZ48OUx+tu8hl5L4Ecvhhkw8pNxY3rnpAhyEqA910DXyzZUs0zua155SPNDlSpWZ2fohHi/M8khcvHHRBdudCZajLHtsH7Qjmnf+pww18EKN+GuCFih/lnpA3x1h+PruJ/smNLJ57pvxVG95Za5+hjXi+ZTgiOv62cQ6HApA1FvOobgK5MA+8FxMEZ55Ae6TAYBEzM/kxg4A8yjOf/dawfuj0v8qe4O68RFNOkaGWkwxfMRAFgtTxcY1CV8vqDzquxQhpSyr1VzfHz5s6N0P9f+6RDbjnvk1/+dhVs7ETxcuCajDSa6r3UsPlsFOPEPkX17qDvc+4duYEfXRVSQIjiH+1xW388/XoU0rkuG6mohVMTAWqYIJPHok27M5ebpX7vxlW0lT+qg9TX+c+taaUfWgbmAJhi0aDUpogyYDVpIkySs/eBDKzOksUPEcyycOi36ltY4f23NXyBHGbIKoEefQnBwU1fOxTqJaUIjKs+DiMloAs1LR96esj3HxbbGj86LJhfKQAuiALBH+agwRTHvDley5kDRoL5PE5l2jETcdIW0UEN7wnh6gScPw5P5XELjwjV6xnYR05xqynyurcnXULIyFuJUvhK9vKTK37E37ExEgGV8GamQEqqxOiNeUqSj3q2yfLx3uGckUemuI+R4PpSQjO37ZoJg9TmKzYYeX+6PUBoE3nPxAYXxHghmdrIHAWRQKSkuNNxJR00cqN0GKPI/fDAiX8x7TRcN0Oq5ctYX/AanEumUzpORIWMCjKXlxo/pYPTx/ck0r+YyDfDKw730MqO0i+IK3dOss1Sy16LAXBLBKOa4KflwY4hc8/Tjdpvo9Y8EtOdJe0bBhYzx18j7xmUU5A0mVdLDOyiu1L+yzeLvDSJYw1nCNf5YVqRr6cA8dIIVfBX0dLPWgxH4hr8gAw//WovD/Cu6/Gmrcltp+2Vfw75Do7QrYolCelJHDLOgtL/wYvBB+X8EuiUVmuLn";
      string GWSymmetricKeyEncryptedValue = "amuWvCaoh2beQh6bdDzhP8KLTzReZw0IOZiP0Oa6CEEASYc5bX+3GL0swQmSUehocia8XKsfaaJ40hOX+ZuWjbGYJMuYnKI7stKA1eij2Lrz+ZgUMKtTpyrk8Xsl1OUO0hBRxbkHCXca4ImYBgqfl+Qhzb8XYVIRwzu785iD3yC7zgflmaKOHtNXPqlHK8qC6Pn84IMGxUiZNj+Txe2UKXOweLCwu0qIHq/B6GpjBfuKLnu3GZ5EGGTGfHCKdDYPEM6lrlUQGRFG1Bru3eJVqJV3cZYydS/RLMPW5dFM3puocWLsbz10IqSQmakCpiUwRJPGWwKIiBQsdhdWz7pMfw==";
        //string GWSymmetricKeyEncryptedValue = "WB6K6lsCYdu+olgoBrrwgkcjNn2he/azI2eXhLNYASZ4wOhfa+VCfCasyNju0KCTDjbK0BE0snrIzbNubd5lRAaAKBZXWgMd/3mq+VygYEzxKiujqL31fxAR7DVzENqNFqk+pCUkDnK5qFGRncGR6DpyqABAfSAGP8uUXwkujRkDGGvE0zzIihnbC/amlzhAwjmbb7ThxSNQGho8r5NDWt4wCxjLtyp/MZ1Yumq7A2355KTgdDnmv3omW/WNCv9RxSTYZ8onhWXMywMbhQMEVlvy59XZBfXSZ/OcbSuH/wBHJ90o9WZJ/gbXi8E+7yR1VQEKUUMLN7qq2p8LYvGzVQ==";
        RSA priv_key = LoadPrivateKey("privatekey.pem");

        byte[] decryptedSymmetricKey = Decrypt_RSA(GWSymmetricKeyEncryptedValue, priv_key);

        byte[] responseBytes = Convert.FromBase64String(ResponseSignatureEncryptedValue);
        byte[] iv = new byte[16];
        byte[] encryptedData = new byte[responseBytes.Length - 16];

        Array.Copy(responseBytes, 0, iv, 0, 16);
        Array.Copy(responseBytes, 16, encryptedData, 0, encryptedData.Length);

        string decryptedData = Decrypt_AES(encryptedData, decryptedSymmetricKey, iv);
        string[] jwtencoded = decryptedData.Split(".");
        string header_encoded = jwtencoded[0];
        string payload_encoded = jwtencoded[1];
        string signature_encoded = jwtencoded[2];
        Console.WriteLine("Header Encrypted " + header_encoded);
        Console.WriteLine("Payload Encrypted " + payload_encoded);
        string header_decoded = Base64UrlDecode(header_encoded);
        string payload_decoded = Base64UrlDecode(payload_encoded);
        Console.WriteLine("Header Decoded " + header_decoded);
        Console.WriteLine("Payload Decoded " + payload_decoded);
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

    public static byte[] Decrypt_RSA(string encryptedText, RSA privateKey)
    {
        byte[] encryptedBytes = Convert.FromBase64String(encryptedText);
        byte[] decryptedBytes = privateKey.Decrypt(encryptedBytes, RSAEncryptionPadding.Pkcs1);
        return decryptedBytes;
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
}
