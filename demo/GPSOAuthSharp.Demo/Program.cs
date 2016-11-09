using System;

namespace GPSOAuthSharp.Demo
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var email = Environment.GetEnvironmentVariable("GOOGLE_USERNAME") ?? "";
            var password = Environment.GetEnvironmentVariable("GOOGLE_PASSWORD") ?? "";

            var googleClient = new GPSOAuthClient(email, password);
            var masterLoginResponse = googleClient.PerformMasterLogin().Result;

            if (masterLoginResponse.ContainsKey("Error"))
            {
                throw new Exception($"Google returned an error message: '{masterLoginResponse["Error"]}'");
            }

            if (!masterLoginResponse.ContainsKey("Token"))
            {
                throw new Exception("Token was missing from master login response.");
            }

            var oauthResponse = googleClient.PerformOAuth(masterLoginResponse["Token"], "audience:server:client_id:848232511240-7so421jotr2609rmqakceuu1luuq0ptb.apps.googleusercontent.com","com.nianticlabs.pokemongo", "321187995bc7cdc2b5fc91b11a96e2baa8602c62").Result;
            if (!oauthResponse.ContainsKey("Auth"))
            {
                throw new Exception("Auth token was missing from oauth login response.");
            }

            Console.WriteLine("Authenticated through Google.");
            Console.ReadLine();
        }
    }
}
