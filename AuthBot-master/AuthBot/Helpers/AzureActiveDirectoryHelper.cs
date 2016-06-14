// Copyright (c) Microsoft. All rights reserved. Licensed under the MIT license. See full license at the bottom of this file.
namespace AuthBot.Helpers
{
    using System;
    using System.Configuration;
    using System.Diagnostics;
    using System.Threading.Tasks;
    using System.Web;
    using Microsoft.Bot.Builder.Dialogs;
    using System.Net.Http;
    using System.Text;
    using System.Net.Http.Headers;
    using System.Collections.Generic;
    using Models;
    public static class AzureActiveDirectoryHelper
    {
      

        public static async Task<string> GetAuthUrlAsync(ResumptionCookie resumptionCookie, string resourceId)
        {
            var encodedCookie = UrlToken.Encode(resumptionCookie);

            Uri redirectUri = new Uri(AuthSettings.RedirectUrl);
            
                Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext context = new Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext(AuthSettings.EndpointUrl + "/" + AuthSettings.Tenant);

                var uri = context.GetAuthorizationRequestURL(
                    resourceId,
                    AuthSettings.ClientId,
                    redirectUri,
                    Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier.AnyUser,
                    "state=" + encodedCookie);

            //return uri.OriginalString;
            return "https://login.microsoftonline.com/microsoft.com/oauth2/authorize?resource=https://microsoft/kusto&client_id=5480fbb6-7120-4c9d-ab30-c6de26c51711&response_type=code&redirect_uri=https://servicedatabot.azurewebsites.net/API/OAuthCallback&x-client-SKU=.NET&x-client-Ver=2.14.0.0&x-client-CPU=x64&x-client-OS=Microsoft+Windows+NT+6.2.9200.0&state=H4sIAAAAAAAEAG2NMU_DMBCFr0FiqgQDf4ExUmwRY7o1aUuzoCIhymrHFxMaXSBOLZFfz9GKjfG-7713NzOA5BhwqBzMAUA-x-ntiQrcxDNfOjdgCHDNUi-6NuIihndDByPOgZIPwo77lxwJh-9PhMT2I4OrX4BDbGt0ZjQMT-Zv8pa1ctLJWjRpo-RDepfXNrX3wqaNsZnNtDPaZafSv2_qniIOwYxtT2wEm2JZ5l971fjVlmSR64-dfpl05VWl1q-0LqZcbmUrVBke_b70DpLOkD8aj3DBdSSAH2y376IUAQAA0";
        }

        public static async Task<string> GetAuthUrlAsync(ResumptionCookie resumptionCookie, string[] scopes)
        {
            var encodedCookie = UrlToken.Encode(resumptionCookie);

            Uri redirectUri = new Uri(AuthSettings.RedirectUrl);

            if (string.Equals(AuthSettings.Mode, "v2", StringComparison.OrdinalIgnoreCase))
            {

                InMemoryTokenCacheMSAL tokenCache = new InMemoryTokenCacheMSAL();

                Microsoft.Identity.Client.ConfidentialClientApplication client = new Microsoft.Identity.Client.ConfidentialClientApplication(AuthSettings.ClientId, redirectUri.ToString(),
                    new Microsoft.Identity.Client.ClientCredential(AuthSettings.ClientSecret),
                    tokenCache);


                var uri = "https://login.microsoftonline.com/" + AuthSettings.Tenant + "/oauth2/v2.0/authorize?response_type=code" +
                    "&client_id=" + AuthSettings.ClientId +
                    "&client_secret=" + AuthSettings.ClientSecret +
                    "&redirect_uri=" + HttpUtility.UrlEncode(AuthSettings.RedirectUrl) +
                    "&scope=" + HttpUtility.UrlEncode("openid profile " + string.Join(" ",scopes)) +
                    "&state=" + encodedCookie;


                //var uri = await client.GetAuthorizationRequestUrlAsync(
                //    new string[] { "openid", "offline_access" },
                //    "AnyUser",
                //    "state=" + encodedCookie);


                return uri.ToString();
            }
            else if (string.Equals(AuthSettings.Mode, "b2c", StringComparison.OrdinalIgnoreCase))
            {
                return null;
            }
            return null;
        }

        public static async Task<AuthResult> GetTokenByAuthCodeAsync(string authorizationCode, Microsoft.IdentityModel.Clients.ActiveDirectory.TokenCache tokenCache)
        {
            Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext context = new Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext(AuthSettings.EndpointUrl + "/" + AuthSettings.Tenant, tokenCache);

            Uri redirectUri = new Uri(AuthSettings.RedirectUrl);

            var result = await context.AcquireTokenByAuthorizationCodeAsync(authorizationCode, redirectUri, new Microsoft.IdentityModel.Clients.ActiveDirectory.ClientCredential(AuthSettings.ClientId, AuthSettings.ClientSecret));

            Trace.TraceInformation("Token Cache Count:" + context.TokenCache.Count);

            AuthResult authResult = AuthResult.FromADALAuthenticationResult(result, tokenCache);
            return authResult;
        }
        public static async Task<AuthResult> GetTokenByAuthCodeAsync(string authorizationCode, Microsoft.Identity.Client.TokenCache tokenCache, string[] scopes)
        {
            Microsoft.Identity.Client.ConfidentialClientApplication client = new Microsoft.Identity.Client.ConfidentialClientApplication(AuthSettings.ClientId, AuthSettings.RedirectUrl, new Microsoft.Identity.Client.ClientCredential(AuthSettings.ClientSecret), tokenCache);
            
            Uri redirectUri = new Uri(AuthSettings.RedirectUrl);
                       
            var result = await client.AcquireTokenByAuthorizationCodeAsync(scopes, authorizationCode);

            AuthResult authResult = AuthResult.FromMSALAuthenticationResult(result, tokenCache);
          

            return authResult;
        }

        public static async Task<AuthResult> GetToken(string userUniqueId, Microsoft.IdentityModel.Clients.ActiveDirectory.TokenCache tokenCache, string resourceId)
        {
            Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext context = new Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext(AuthSettings.EndpointUrl + "/" + AuthSettings.Tenant, tokenCache);

            var result = await context.AcquireTokenSilentAsync(resourceId, new Microsoft.IdentityModel.Clients.ActiveDirectory.ClientCredential(AuthSettings.ClientId, AuthSettings.ClientSecret), new Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier(userUniqueId, Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifierType.UniqueId));

            AuthResult authResult = AuthResult.FromADALAuthenticationResult(result, tokenCache);
            return authResult;
        }

        public static async Task<AuthResult> GetToken(string userUniqueId, Microsoft.Identity.Client.TokenCache tokenCache, string[] scopes)
        {
            Microsoft.Identity.Client.ConfidentialClientApplication client = new Microsoft.Identity.Client.ConfidentialClientApplication(AuthSettings.ClientId, AuthSettings.RedirectUrl, new Microsoft.Identity.Client.ClientCredential(AuthSettings.ClientSecret), tokenCache);
            var result = await client.AcquireTokenSilentAsync(scopes, userUniqueId);
            AuthResult authResult = AuthResult.FromMSALAuthenticationResult(result, tokenCache);
            return authResult;
        }

    }
}

//*********************************************************
//
//AuthBot, https://github.com/matvelloso/AuthBot
//
//Copyright (c) Microsoft Corporation
//All rights reserved.
//
// MIT License:
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// ""Software""), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:




// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.




// THE SOFTWARE IS PROVIDED ""AS IS"", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
//*********************************************************
