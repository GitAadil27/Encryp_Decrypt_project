using System;
using System.IO;
using System.Security.Cryptography;

class Encryption
{
    static void Main(string[] args)
    {
        string filePath = "path_to_your_key_file.pem"; // Change this to your actual file path
        string message = "Your message here";

        try
        {
            RSA rsa = LoadPrivateKey(filePath);
            byte[] hash = ComputeSha256Hash(message);
            byte[] signature = SignData(hash, rsa);

            Console.WriteLine("Signature (Base64): " + Convert.ToBase64String(signature));
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error: " + ex.Message);
        }
    }

    public static RSA LoadPrivateKey(string fileName)
    {
        var privateKeyText = File.ReadAllText(fileName);
        var privateKeyBlocks = privateKeyText.Split("-", StringSplitOptions.RemoveEmptyEntries);
        var privateKeyBytes = Convert.FromBase64String(privateKeyBlocks[1].Trim());

        using (var ms = new MemoryStream(privateKeyBytes))
        {
            using (var rsa = RSA.Create())
            {
                rsa.ImportPkcs8PrivateKey(privateKeyBytes, out _);
                return rsa;
            }
        }
    }

    public static byte[] ComputeSha256Hash(string data)
    {
        using (var sha256 = SHA256.Create())
        {
            return sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(data));
        }
    }

    public static byte[] SignData(byte[] hash, RSA rsa)
    {
        return rsa.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }
}
