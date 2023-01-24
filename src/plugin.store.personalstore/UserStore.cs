﻿using PKISharp.WACS.DomainObjects;
using PKISharp.WACS.Plugins.Base.Capabilities;
using PKISharp.WACS.Plugins.Interfaces;
using PKISharp.WACS.Services;
using System;
using System.Runtime.Versioning;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

[assembly: SupportedOSPlatform("windows")]

namespace PKISharp.WACS.Plugins.StorePlugins
{
    [IPlugin.Plugin<
        UserStoreOptions, UserStoreOptionsFactory, 
        DefaultCapability, UserStoreJson>
        ("95ee94e7-c8e2-40e6-a26f-c9fc3afa9fa5",
        Name, "Windows Certificate Store (Current User)")]
    internal class UserStore : IStorePlugin, IDisposable
    {
        internal const string Name = "UserStore";
        private const string DefaultStoreName = nameof(StoreName.My);
        private readonly ILogService _log;
        private readonly ISettingsService _settings;
        private readonly CertificateStoreClient _storeClient;

        public UserStore(ILogService log, ISettingsService settings)
        {
            _log = log;
            _settings = settings;
            _storeClient = new CertificateStoreClient(DefaultStoreName, StoreLocation.CurrentUser, _log);
        }

        public Task Save(CertificateInfo input)
        {
            var existing = _storeClient.FindByThumbprint(input.Certificate.Thumbprint);
            if (existing != null)
            {
                _log.Warning("Certificate with thumbprint {thumbprint} is already in the store", input.Certificate.Thumbprint);
            }
            else
            {
                if (input.CacheFile == null)
                {
                    throw new InvalidOperationException();
                }
                var flags = X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet;
                if (_settings.Security.PrivateKeyExportable)
                {
                    flags |= X509KeyStorageFlags.Exportable;
                }

                var certificate = new X509Certificate2(
                    input.CacheFile.FullName,
                    input.CacheFilePassword,
                    flags);
                _log.Information("Installing certificate in the certificate store");
                _storeClient.InstallCertificate(certificate);
                _storeClient.InstallCertificateChain(input.Chain);

            }
            _ = input.StoreInfo.TryAdd(
                GetType(),
                new StoreInfo()
                {
                    Name = Name,
                    Path = DefaultStoreName
                });
            return Task.CompletedTask;
        }

        public Task Delete(CertificateInfo input)
        {
            _storeClient.UninstallCertificate(input.Certificate);
            return Task.CompletedTask;
        }

        #region IDisposable

        private bool disposedValue = false; // To detect redundant calls

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    _storeClient.Dispose();
                }
                disposedValue = true;
            }
        }

        public void Dispose() => Dispose(true);

        #endregion
    }
}