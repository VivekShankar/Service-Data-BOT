﻿// Copyright (c) Microsoft. All rights reserved. Licensed under the MIT license. See full license at the bottom of this file.
namespace SampleAADV1Bot.Dialogs
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;
    using Microsoft.Bot.Builder.Dialogs;
    using Microsoft.Bot.Builder.FormFlow;
    using Microsoft.Bot.Builder.Luis;
    using Microsoft.Bot.Builder.Luis.Models;
    using Microsoft.Bot.Connector;
    using AuthBot;
    using AuthBot.Dialogs;
    using System.Configuration;
    [Serializable]
    public class ActionDialog : IDialog<string>
    {
      
        private static Lazy<string> mode = new Lazy<string>(() => ConfigurationManager.AppSettings["ActiveDirectory.Mode"]);
        private static Lazy<string> activeDirectoryEndpointUrl = new Lazy<string>(() => ConfigurationManager.AppSettings["ActiveDirectory.EndpointUrl"]);
        private static Lazy<string> activeDirectoryTenant = new Lazy<string>(() => ConfigurationManager.AppSettings["ActiveDirectory.Tenant"]);
        private static Lazy<string> activeDirectoryResourceId = new Lazy<string>(() => ConfigurationManager.AppSettings["ActiveDirectory.ResourceId"]);
        private static Lazy<string> redirectUrl = new Lazy<string>(() => ConfigurationManager.AppSettings["ActiveDirectory.RedirectUrl"]);
        private static Lazy<string> clientId = new Lazy<string>(() => ConfigurationManager.AppSettings["ActiveDirectory.ClientId"]);
        private static Lazy<string> clientSecret = new Lazy<string>(() => ConfigurationManager.AppSettings["ActiveDirectory.ClientSecret"]);
        private static Lazy<string[]> scopes = new Lazy<string[]>(() => ConfigurationManager.AppSettings["ActiveDirectory.Scopes"].Split(','));

        public async Task StartAsync(IDialogContext context)
        {
            context.Wait(MessageReceivedAsync);
        }
      
        public async Task TokenSample(IDialogContext context)
        {
            int index = 0;

            string[] mylist = new string[] { activeDirectoryResourceId.Value };


            //endpoint v1
            var accessToken = await context.GetAccessToken(mylist);

            if (string.IsNullOrEmpty(accessToken))
            {
                return;
            }

            await context.PostAsync($"Your access token is: {accessToken}");

            context.Wait(MessageReceivedAsync);
        }


        public async Task MessageReceivedAsync(IDialogContext context, IAwaitable<Message> item)

        {

            var message = await item;

            context.UserData.SetValue(ContextConstants.CurrentMessageFromKey, message.From);
            context.UserData.SetValue(ContextConstants.CurrentMessageToKey, message.To);

            if (message.Text.ToLower() == "logon")
            {
                //endpoint v1
                if (string.IsNullOrEmpty(await context.GetAccessToken(new string[] { activeDirectoryResourceId.Value })))
                {
                    await context.Forward(new AzureAuthDialog(activeDirectoryResourceId.Value), this.ResumeAfterAuth, message, CancellationToken.None);
                }
                else
                {
                    context.Wait(MessageReceivedAsync);
                }
            }
            else if (message.Text.ToLower() == "echo")
            {
                await context.PostAsync("echo");

                context.Wait(this.MessageReceivedAsync);
            }
            else if (message.Text.ToLower() == "token")
            {
                await TokenSample(context);               
            }
            else if (message.Text.ToLower() == "qos")
            {
                string[] mylist = new string[] { activeDirectoryResourceId.Value };
                string accessToken = await context.GetAccessToken(mylist);
                string data = QOS(accessToken);
                await context.PostAsync(data);
                context.Wait(this.MessageReceivedAsync);

            }
            else if (message.Text.ToLower().StartsWith("qos for"))
            {
                string[] mylist = new string[] { activeDirectoryResourceId.Value };
                string accessToken = await context.GetAccessToken(mylist);
                string data = QOSForLastWeek(accessToken);
                await context.PostAsync(data);
                context.Wait(this.MessageReceivedAsync);
            }
            else if (message.Text.ToLower().StartsWith("qos from"))
            {
                string[] messageArr = message.Text.Split(' ');
                string start = messageArr[2];
                string end = messageArr[4];

                string[] mylist = new string[] { activeDirectoryResourceId.Value };
                string accessToken = await context.GetAccessToken(mylist);
                string data = QOS(accessToken, "TPEngine", start, end) + " " + QOS(accessToken, "Admin", start, end);
                await context.PostAsync(data);
                context.Wait(this.MessageReceivedAsync);
            }
            else if (message.Text.ToLower() == "kusto")
            {
                string[] mylist = new string[] { activeDirectoryResourceId.Value };
                string accessToken = await context.GetAccessToken(mylist);
                string data = GetServiceHealth(accessToken);
                await context.PostAsync(data);
                context.Wait(this.MessageReceivedAsync);
            }
            else if (message.Text.ToLower() == "logout")
            {
                await context.Logout();
                context.Wait(this.MessageReceivedAsync);
            }
            else
            {
                string defaultText = "Sorry, I don't understand that command.";
                await context.PostAsync(defaultText);
                context.Wait(MessageReceivedAsync);
            }

        }

        public static string QOSForLastWeek(string token)
        {
            DateTime input = DateTime.UtcNow;
            int delta = DayOfWeek.Saturday - input.DayOfWeek;
            DateTime prevSaturday = input.AddDays(delta - 7);
            string prevSaturdayStr = prevSaturday.ToString("yyyy-MM-dd") + " 00:00";
            string prevPrevSaturdayStr = prevSaturday.AddDays(-7).ToString("yyyy-MM-dd");
            return QOS(token, "TPEngine", prevPrevSaturdayStr, prevSaturdayStr) + " " + QOS(token, "Admin", prevPrevSaturdayStr, prevSaturdayStr);
        }

        public static string QOS(string token)
        {
            DateTime input = DateTime.UtcNow;
            int delta = DayOfWeek.Saturday - input.DayOfWeek;
            DateTime prevSaturday = input.AddDays(delta - 7);
            string prevSaturdayStr = prevSaturday.ToString("yyyy-MM-dd") + " 00:00";

            string curTime = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm");
            return QOS(token, "TPEngine", prevSaturdayStr, curTime) + " " + QOS(token, "Admin", prevSaturdayStr, curTime);
        }


        public static string QOS(string token, string role, string start, string end)
        {
            var failureClient = Kusto.Data.Net.Client.KustoClientFactory.CreateCslQueryProvider(string.Format("https://cpim.kusto.windows.net;Initial Catalog=CPIM;Federated Security=true;UserToken={0}", token));
            string failureQuery =
                String.Format(
                    "IfxRequestEvent | where env_time >= datetime({0}) and env_time < datetime({1}) and resultType == \"Failure\" | count",
                    start, end);
            var failureReader = failureClient.ExecuteQuery(String.Format("IfxRequestEvent | where role == \"{0}\" and env_time >= datetime({1}) and env_time < datetime({2}) and resultType == \"Failure\" | count", role, start, end));
            failureReader.Read();
            long failureCount = (long)failureReader["Count"];

            var successClient = Kusto.Data.Net.Client.KustoClientFactory.CreateCslQueryProvider(string.Format("https://cpim.kusto.windows.net;Initial Catalog=CPIM;Federated Security=true;UserToken={0}", token));
            var successReader = successClient.ExecuteQuery(String.Format("IfxRequestEvent | where role == \"{0}\" and env_time >= datetime({1}) and env_time < datetime({2}) and resultType != \"Failure\" | count", role, start, end));
            successReader.Read();
            long successCount = (long)successReader["Count"];
            float serviceHealthPercentage = 100*(1 - (float)failureCount / (failureCount + successCount));
            string serviceHealthStr = String.Format("Role: {0} Service Health: {1}%", role, serviceHealthPercentage.ToString("0.00000"));
            System.Console.WriteLine(serviceHealthStr);
            return serviceHealthStr;
        }

        public static string GetServiceHealth(string token)
        {
            var failureClient = Kusto.Data.Net.Client.KustoClientFactory.CreateCslQueryProvider(string.Format("https://cpim.kusto.windows.net;Initial Catalog=CPIM;Federated Security=true;UserToken={0}", token));
            var failureReader = failureClient.ExecuteQuery("IfxRequestEvent | where resultType == \"Failure\" | count");
            failureReader.Read();
            long failureCount = (long)failureReader["Count"];

            var successClient = Kusto.Data.Net.Client.KustoClientFactory.CreateCslQueryProvider(string.Format("https://cpim.kusto.windows.net;Initial Catalog=CPIM;Federated Security=true;UserToken={0}", token));
            var successReader = successClient.ExecuteQuery("IfxRequestEvent | where resultType == \"Success\" | count");
            successReader.Read();
            long successCount = (long)successReader["Count"];
            float serviceHealthPercentage = 1 - 100 * (float)failureCount / (failureCount + successCount);
            string serviceHealthStr = String.Format("Service Health: {0}%", serviceHealthPercentage.ToString("0.00000"));
            System.Console.WriteLine(serviceHealthStr);
            return serviceHealthStr;
        }

        private async Task ResumeAfterAuth(IDialogContext context, IAwaitable<string> result)
        {
            var message = await result;

            await context.PostAsync(message);
            context.Wait(MessageReceivedAsync);
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
