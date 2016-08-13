using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace GPSOAuthSharp
{
    // ReSharper disable once InconsistentNaming
    public class GPSOAuthClient
    {
        private const string B64Key = "AAAAgMom/1a/v0lblO2Ubrt60J2gcuXSljGFQXgcyZWveWLEwo6prwgi3" + 
            "iJIZdodyhKZQrNWp5nKJ3srRXcUW+F1BD3baEVGcmEgqaLZUNBjm057pK" + 
            "RI16kB0YppeGx5qIQ5QjKzsR8ETQbKLNWgRY0QRNVz34kMJR3P/LgHax/" + 
            "6rmf5AAAAAwEAAQ==";
        private const string Version = "0.0.5";
        private const string AuthUrl = "https://android.clients.google.com/auth";
        private const string UserAgent = "GPSOAuthSharp/" + Version;

        private readonly RsaKeyParameters _androidKey = GoogleKeyUtils.KeyFromB64(B64Key);
        private readonly string _email;
        private readonly string _password;

        public GPSOAuthClient(string email, string password)
        {
            _email = email;
            _password = password;
        }
        
        private async Task<Dictionary<string, string>> PerformAuthRequest(Dictionary<string, string> data)
        {
            using (var client = new HttpClient())
            {
                client.DefaultRequestHeaders.UserAgent.TryParseAdd(UserAgent);
                var postResponse = await client.PostAsync(AuthUrl, new FormUrlEncodedContent(data.ToArray()));
                var result = await postResponse.Content.ReadAsStringAsync();
                return GoogleKeyUtils.ParseAuthResponse(result);
            }
        }
        
        public async Task<Dictionary<string, string>> PerformMasterLogin(string service = "ac2dm",
            string deviceCountry = "us", string operatorCountry = "us", string lang = "en", int sdkVersion = 21)
        {
            var signature = GoogleKeyUtils.CreateSignature(_email, _password, _androidKey);
            var dict = new Dictionary<string, string> {
                { "accountType", "HOSTED_OR_GOOGLE" },
                { "Email", _email },
                { "has_permission", 1.ToString() },
                { "add_account", 1.ToString() },
                { "EncryptedPasswd",  signature},
                { "service", service },
                { "source", "android" },
                { "device_country", deviceCountry },
                { "operatorCountry", operatorCountry },
                { "lang", lang },
                { "sdk_version", sdkVersion.ToString() }
            };
            return await PerformAuthRequest(dict);
        }
        
        public async Task<Dictionary<string, string>> PerformOAuth(string masterToken, string service, string app, string clientSig,
            string deviceCountry = "us", string operatorCountry = "us", string lang = "en", int sdkVersion = 21)
        {
            var dict = new Dictionary<string, string> {
                { "accountType", "HOSTED_OR_GOOGLE" },
                { "Email", _email },
                { "has_permission", 1.ToString() },
                { "EncryptedPasswd",  masterToken},
                { "service", service },
                { "source", "android" },
                { "app", app },
                { "client_sig", clientSig },
                { "device_country", deviceCountry },
                { "operatorCountry", operatorCountry },
                { "lang", lang },
                { "sdk_version", sdkVersion.ToString() }
            };
            return await PerformAuthRequest(dict);
        }
    }

    internal static class GoogleKeyUtils
    {
        public static RsaKeyParameters KeyFromB64(string b64Key)
        {
            var decodedKey = Convert.FromBase64String(b64Key);

            var modLength = BitConverter.ToInt32(decodedKey.Take(4).Reverse().ToArray(), 0);
            var modBytes = decodedKey.Skip(4).Take(modLength).ToArray();

            var expLength = BitConverter.ToInt32(decodedKey.Skip(modLength + 4).Take(4).Reverse().ToArray(), 0);
            var expBytes = decodedKey.Skip(modLength + 8).Take(expLength).ToArray();

            return new RsaKeyParameters(false, new BigInteger(1, modBytes), new BigInteger(1, expBytes));
        }
        
        public static Dictionary<string, string> ParseAuthResponse(string text)
        {
            return text.Split(new[] {"\n", "\r\n"}, StringSplitOptions.RemoveEmptyEntries)
                .Select(line => line.Split('='))
                .ToDictionary(parts => parts[0], parts => parts[1]);
        }

        public static string CreateSignature(string email, string password, RsaKeyParameters key)
        {
            var prefix = new byte[] { 0x00 };
            var keyBytes = KeyToStruct(key);
            var bytesToEncrypt = Encoding.UTF8.GetBytes(email + "\x00" + password);

            var messageDigest = new Sha1Digest();
            messageDigest.BlockUpdate(keyBytes, 0, keyBytes.Length);
            var hash = new byte[messageDigest.GetDigestSize()];
            messageDigest.DoFinal(hash, 0);

            var cipher = CipherUtilities.GetCipher("RSA/NONE/OAEPPadding");
            cipher.Init(true, key);
            var encrypted = cipher.DoFinal(bytesToEncrypt);
            return UrlSafeBase64(CombineBytes(prefix, hash.Take(4).ToArray(), encrypted));
        }

        private static byte[] KeyToStruct(RsaKeyParameters key)
        {
            byte[] modLength = { 0x00, 0x00, 0x00, 0x80 };
            var mod = key.Modulus.ToByteArrayUnsigned();
            byte[] expLength = { 0x00, 0x00, 0x00, 0x03 };
            var exponent = key.Exponent.ToByteArrayUnsigned();
            return CombineBytes(modLength, mod, expLength, exponent);
        }

        private static byte[] CombineBytes(params byte[][] arrays)
        {
            var rv = new byte[arrays.Sum(a => a.Length)];
            var offset = 0;
            foreach (var array in arrays)
            {
                Buffer.BlockCopy(array, 0, rv, offset, array.Length);
                offset += array.Length;
            }
            return rv;
        }

        private static string UrlSafeBase64(byte[] byteArray)
        {
            return Convert.ToBase64String(byteArray).Replace('+', '-').Replace('/', '_');
        }

    }

}