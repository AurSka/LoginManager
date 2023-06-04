using System;
using System.IO;
using System.Security.Cryptography;

namespace LoginManager.Classes
{
    public static class FileEncryptor
    {
        public static bool EncryptFile(string sourceFilename, string destinationFilename, AesCryptoServiceProvider provider)
        {
            try
            {
                if (File.Exists(destinationFilename))
                    File.Delete(destinationFilename);
                using (var sourceStream = File.OpenRead(sourceFilename))
                using (var destinationStream = File.Create(destinationFilename))
                {
                    var IV = provider.IV;
                    using (var cryptoTransform = provider.CreateEncryptor(provider.Key, IV))
                    using (var cryptoStream = new CryptoStream(destinationStream, cryptoTransform, CryptoStreamMode.Write))
                    {
                        destinationStream.Write(provider.IV, 0, provider.IV.Length);
                        sourceStream.CopyTo(cryptoStream);
                        Console.WriteLine(System.Convert.ToBase64String(provider.Key));
                    }
                }
                return true;
            }
            catch (Exception E)
            {
                Console.Write(E.Message);
                return false;
            }
        }

        public static bool DecryptFile(string sourceFilename, string destinationFilename, AesCryptoServiceProvider provider)
        {
            try
            {
                if (File.Exists(destinationFilename))
                    File.Delete(destinationFilename);
                using (var sourceStream = File.OpenRead(sourceFilename))
                using (var destinationStream = File.Create(destinationFilename))
                {
                    var IV = provider.IV;
                    sourceStream.Read(IV, 0, IV.Length);
                    using (var cryptoTransform = provider.CreateDecryptor(provider.Key, IV))
                    using (var cryptoStream = new CryptoStream(sourceStream, cryptoTransform, CryptoStreamMode.Read))
                    {
                        cryptoStream.CopyTo(destinationStream);
                    }
                }
                return true;
            }
            catch (Exception E)
            {
                Console.Write(E.Message);
                return false;
            }
        }
    }
}
