namespace AlwaysEncryptedKeyVaultIssue
{
    using Microsoft.IdentityModel.Clients.ActiveDirectory;
    using Microsoft.SqlServer.Management.AlwaysEncrypted.AzureKeyVaultProvider;
    using System;
    using System.Collections.Generic;
    using System.Data.SqlClient;
    using System.Threading.Tasks;

    public class Program
    {
        private static ClientCredential clientCredential;

        static void Main(string[] args)
        {
            InitializeAzureKeyVaultProvider();
        }

        public static void InitializeAzureKeyVaultProvider()
        {
            var clientId = Guid.NewGuid().ToString();
            var clientSecret = "ITS_A_SECRET";

            clientCredential = new ClientCredential(clientId, clientSecret);

            var azureKeyVaultProvider = new SqlColumnEncryptionAzureKeyVaultProvider(GetToken);

            var providers = new Dictionary<string, SqlColumnEncryptionKeyStoreProvider>()
            {
                { SqlColumnEncryptionAzureKeyVaultProvider.ProviderName, azureKeyVaultProvider }
            };

            SqlConnection.RegisterColumnEncryptionKeyStoreProviders(providers);
        }

        public async static Task<string> GetToken(string authority, string resource, string scope)
        {
            var authContext = new AuthenticationContext(authority);
            AuthenticationResult result = await authContext.AcquireTokenAsync(resource, clientCredential);

            if (result == null)
                throw new InvalidOperationException("Failed to obtain the access token");

            return result.AccessToken;
        }
    }
}
