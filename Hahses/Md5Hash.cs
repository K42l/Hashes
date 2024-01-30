using System.Security.Cryptography;
using System.Text;

namespace Crypt.Project.Hahses
{
    public class Md5Hash 
    {
        private static string GetMd5Hash(byte[] data)
        {
            StringBuilder sBuilder = new StringBuilder();
            foreach (byte b in data)
            {
                sBuilder.Append(b.ToString("x2"));
            }
            return sBuilder.ToString();
        }

        private static bool VerifyMd5Hash(byte[] data, string hash)
        {
            return 0 == StringComparer.OrdinalIgnoreCase.Compare(GetMd5Hash(data), hash);
        }

        public string CreateHashFromString(string data)
        {
            using (MD5 md5 = MD5.Create())
            {
                return GetMd5Hash(md5.ComputeHash(Encoding.UTF8.GetBytes(data)));
            }
        }
        public string CreateHashFromFileStream(FileStream data)
        {
            using (MD5 md5 = MD5.Create())
            {
                return GetMd5Hash(md5.ComputeHash(data));
            }
        }

        public bool ValidadteHashString(string data, string hash)
        {
            using (MD5 md5 = MD5.Create())
            {
                return VerifyMd5Hash(md5.ComputeHash(Encoding.UTF8.GetBytes(data)), hash);
            }
        }

        public bool ValidateHashFileStream(FileStream data, string hash)
        {
            using (MD5 md5 = MD5.Create())
            {
                return VerifyMd5Hash(md5.ComputeHash(data), hash);
            }
        }
    }
}