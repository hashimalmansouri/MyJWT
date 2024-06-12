using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System.Security.Cryptography;
using System.Text;

namespace MyJwtAPI.Security;
public interface IEncryption
{
    string Encrypt(string data);
    string Decrypt(string data);
    bool Validate(string value, string salt, string hash);
    string CreateSlat();
    string IDEncrypt(int value);
    int IDDecrypt(string value);
}
public class Encryption : IEncryption
{
    private string DulaKey = Environment.GetEnvironmentVariable("MyJWT_Enc_Key", EnvironmentVariableTarget.Machine);
    public string Encrypt(string plainText)
    {
        var key = DulaKey;
        byte[] iv = new byte[16];
        byte[] array;

        using (Aes aes = Aes.Create())
        {
            aes.Key = Encoding.UTF8.GetBytes(key);
            aes.IV = iv;

            ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

            using (MemoryStream memoryStream = new())
            {
                using (CryptoStream cryptoStream = new(memoryStream, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter streamWriter = new(cryptoStream))
                    {
                        streamWriter.Write(plainText);
                    }

                    array = memoryStream.ToArray();
                }
            }
        }

        return Convert.ToBase64String(array);
    }

    public string Decrypt(string cipherText)
    {
        var key = DulaKey;
        byte[] iv = new byte[16];
        byte[] buffer = Convert.FromBase64String(cipherText);

        using (Aes aes = Aes.Create())
        {
            aes.Key = Encoding.UTF8.GetBytes(key);
            aes.IV = iv;
            ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

            using (MemoryStream memoryStream = new(buffer))
            {
                using (CryptoStream cryptoStream = new(memoryStream, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader streamReader = new(cryptoStream))
                    {
                        return streamReader.ReadToEnd();
                    }
                }
            }
        }
    }
    public string CreateHash(string value, string salt)
    {
        var valueBytes = KeyDerivation.Pbkdf2(
                            password: value,
                            salt: Encoding.UTF8.GetBytes(salt),
                            prf: KeyDerivationPrf.HMACSHA512,
                            iterationCount: 10000,
                            numBytesRequested: 256 / 8);

        return Convert.ToBase64String(valueBytes);
    }

    public bool Validate(string value, string salt, string hash)
        => CreateHash(value, salt) == hash;
    public string CreateSlat()
    {
        byte[] randomBytes = new byte[128 / 8];
        using (var generator = RandomNumberGenerator.Create())
        {
            generator.GetBytes(randomBytes);
            return Convert.ToBase64String(randomBytes);
        }
    }
    public string IDEncrypt(int value)
    {
        return Convert.ToBase64String(BitConverter.GetBytes(value)).Replace("==", "");
    }
    public int IDDecrypt(string value)
    {
        int res = 0;
        try
        {
            res = BitConverter.ToInt32(Convert.FromBase64String(value + "=="), 0);
        }
        catch (Exception)
        {
            res = 0;
        }
        return res;
    }
}
