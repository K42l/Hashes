using System.Text;
using System.Security.Cryptography;

namespace Crypt.Project.Hahses
{
    public class Sha256Hash
    {
        private static string GetHash(byte[] data)
        {
            StringBuilder sBuilder = new StringBuilder();
            foreach (byte b in data)
            {
                sBuilder.Append(b.ToString("x2"));
            }
            return sBuilder.ToString();
        }

        private static bool VerifyHash(byte[] data, string hash)
        {
            return 0 == StringComparer.OrdinalIgnoreCase.Compare(GetHash(data), hash);
        }

        public string CreateHashFromString(string data)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                return GetHash(sha256.ComputeHash(Encoding.UTF8.GetBytes(data)));
            }
        }
        public string CreateHashFromFileStream(FileStream data)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                return GetHash(sha256.ComputeHash(data));
            }
        }

        public bool ValidadteHashString(string data, string hash)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                return VerifyHash(sha256.ComputeHash(Encoding.UTF8.GetBytes(data)), hash);
            }
        }

        public bool ValidateHashFileStream(FileStream data, string hash)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                return VerifyHash(sha256.ComputeHash(data), hash);
            }
        }

    }
}
