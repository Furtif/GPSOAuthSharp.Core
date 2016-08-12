using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Math;

namespace DankMemes.GPSOAuthSharp
{
    public class GPSOAuthClient
    {

        // gpsoauth:__init__.py
        // URL: https://github.com/simon-weber/gpsoauth/blob/master/gpsoauth/__init__.py
        static string b64Key = "AAAAgMom/1a/v0lblO2Ubrt60J2gcuXSljGFQXgcyZWveWLEwo6prwgi3" +
               "iJIZdodyhKZQrNWp5nKJ3srRXcUW+F1BD3baEVGcmEgqaLZUNBjm057pK" +
               "RI16kB0YppeGx5qIQ5QjKzsR8ETQbKLNWgRY0QRNVz34kMJR3P/LgHax/" +
               "6rmf5AAAAAwEAAQ==";

        RsaKeyParameters androidKey = GoogleKeyUtils.KeyFromB64(b64Key);

        static string version = "0.0.5";
        static string authUrl = "https://android.clients.google.com/auth";
        static string userAgent = "GPSOAuthSharp/" + version;

        private string email;
        private string password;

        public GPSOAuthClient(string email, string password)
        {
            this.email = email;
            this.password = password;
        }

        // _perform_auth_request
        private async Task<Dictionary<string, string>> PerformAuthRequest(Dictionary<string, string> data)
        {
            using (HttpClient client = new HttpClient())
            {
                client.DefaultRequestHeaders.UserAgent.TryParseAdd(userAgent);
                var postResponse = await client.PostAsync(authUrl, new FormUrlEncodedContent(data.ToArray()));
                var result = await postResponse.Content.ReadAsStringAsync();
                return GoogleKeyUtils.ParseAuthResponse(result);
            }
        }

        // perform_master_login
        public async Task<Dictionary<string, string>> PerformMasterLogin(string service = "ac2dm",
            string deviceCountry = "us", string operatorCountry = "us", string lang = "en", int sdkVersion = 21)
        {
            string signature = GoogleKeyUtils.CreateSignature(email, password, androidKey);
            var dict = new Dictionary<string, string> {
                { "accountType", "HOSTED_OR_GOOGLE" },
                { "Email", email },
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

        // perform_oauth
        public async Task<Dictionary<string, string>> PerformOAuth(string masterToken, string service, string app, string clientSig,
            string deviceCountry = "us", string operatorCountry = "us", string lang = "en", int sdkVersion = 21)
        {
            var dict = new Dictionary<string, string> {
                { "accountType", "HOSTED_OR_GOOGLE" },
                { "Email", email },
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

    // gpsoauth:google.py
    // URL: https://github.com/simon-weber/gpsoauth/blob/master/gpsoauth/google.py
    static class GoogleKeyUtils
    {
        // key_from_b64
        // BitConverter has different endianness, hence the Reverse()
        // RSAKeyParams
        public static RsaKeyParameters KeyFromB64(string b64Key)
        {
            var decodedKey = Convert.FromBase64String(b64Key);

            var modLength = BitConverter.ToInt32(decodedKey.Take(4).Reverse().ToArray(), 0);
            var modBytes = decodedKey.Skip(4).Take(modLength).ToArray();

            var expLength = BitConverter.ToInt32(decodedKey.Skip(modLength + 4).Take(4).Reverse().ToArray(), 0);
            var expBytes = decodedKey.Skip(modLength + 8).Take(expLength).ToArray();
            
            return new RsaKeyParameters(false, new BigInteger(1, modBytes), new BigInteger(expBytes));
        }

        // parse_auth_response
        public static Dictionary<string, string> ParseAuthResponse(string text)
        {
            Dictionary<string, string> responseData = new Dictionary<string, string>();
            foreach (string line in text.Split(new string[] { "\n", "\r\n" }, StringSplitOptions.RemoveEmptyEntries))
            {
                string[] parts = line.Split('=');
                responseData.Add(parts[0], parts[1]);
            }
            return responseData;
        }

        // signature
        public static string CreateSignature(string email, string password, RsaKeyParameters key)
        {
            /* RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(key);
            SHA1 sha1 = SHA1.Create();
            byte[] prefix = { 0x00 };
            byte[] hash = sha1.ComputeHash(GoogleKeyUtils.KeyToStruct(key)).Take(4).ToArray();
            byte[] encrypted = rsa.Encrypt(Encoding.UTF8.GetBytes(email + "\x00" + password), true);
            return DataTypeUtils.UrlSafeBase64(DataTypeUtils.CombineBytes(prefix, hash, encrypted)); */
            
            var prefix = new byte[] { 0x00 };
            var keyBytes = KeyToStruct(key);
            var bytesToEncrypt = Encoding.UTF8.GetBytes(email + "\x00" + password);

            // SHA1 (Works correctly)
            var messageDigest = new Sha1Digest();
            messageDigest.BlockUpdate(keyBytes, 0, keyBytes.Length);
            var messageResult = new byte[messageDigest.GetDigestSize()];
            messageDigest.DoFinal(messageResult, 0);

            messageResult = messageResult.Take(4).ToArray();

            // Encrypted bytes
            // TODO: Fix this, generates invalid "encrypted" value
            var encryptEngine = new Pkcs1Encoding(new RsaEngine());
            encryptEngine.Init(true, key);
            var encrypted = encryptEngine.ProcessBlock(bytesToEncrypt, 0, bytesToEncrypt.Length);

            return UrlSafeBase64(CombineBytes(prefix, messageResult.Take(4).ToArray(), encrypted));
//            ISigner sig = SignerUtilities.GetSigner("SHA1withRSA");
//            sig.Init(false, key);
//            var bytesToEncrypt = Encoding.UTF8.GetBytes(email + "\x00" + password);
//            sig.BlockUpdate(bytesToEncrypt, 0, bytesToEncrypt.Length);
//
//            byte[] signature = sig.GenerateSignature();
//
//            return UrlSafeBase64(signature);
        }

        public static byte[] KeyToStruct(RsaKeyParameters key)
        {
            byte[] modLength = { 0x00, 0x00, 0x00, 0x80 };
            byte[] mod = key.Modulus.ToByteArray().Skip(1).ToArray();
            byte[] expLength = { 0x00, 0x00, 0x00, 0x03 };
            byte[] exponent = key.Exponent.ToByteArray();
            return CombineBytes(modLength, mod, expLength, exponent);
        }

        private static byte[] CombineBytes(params byte[][] arrays)
        {
            byte[] rv = new byte[arrays.Sum(a => a.Length)];
            int offset = 0;
            foreach (byte[] array in arrays)
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