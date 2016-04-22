using System;
using System.Linq;
using Renci.SshNet.Messages.Authentication;
using Renci.SshNet.Messages;
using Renci.SshNet.Common;
using System.Threading;
using System.Collections.Generic;

namespace Renci.SshNet
{
    public interface IAgentProtocol
    {
        IEnumerable<IdentityReference> GetIdentities();

        byte[] SignData(IdentityReference identity, byte[] data);
    }

    public class IdentityReference
    {
        public string Type { get; private set; }
        public byte[] Blob { get; private set; }
        public string Comment { get; private set; }

        public IdentityReference(string type, byte[] blob, string comment)
        {
            this.Type = type;
            this.Blob = blob;
            this.Comment = comment;
        }

    }
    /// <summary>
    /// Provides connection information when private key authentication method is used
    /// </summary>
    public class AgentConnectionInfo : ConnectionInfo, IDisposable
    {
        /// <summary>
        /// Gets the key files used for authentication.
        /// </summary>
        public IAgentProtocol Protocol { get; private set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="PrivateKeyConnectionInfo"/> class.
        /// </summary>
        /// <param name="host">Connection host.</param>
        /// <param name="username">Connection username.</param>
        /// <param name="keyFiles">Connection key files.</param>
        public AgentConnectionInfo(string host, string username, IAgentProtocol protocol)
            : this(host, 22, username, ProxyTypes.None, string.Empty, 0, string.Empty, string.Empty, protocol)
        {

        }

        /// <summary>
        /// Initializes a new instance of the <see cref="PrivateKeyConnectionInfo"/> class.
        /// </summary>
        /// <param name="host">Connection host.</param>
        /// <param name="port">Connection port.</param>
        /// <param name="username">Connection username.</param>
        /// <param name="keyFiles">Connection key files.</param>
        public AgentConnectionInfo(string host, int port, string username, IAgentProtocol protocol)
            : this(host, port, username, ProxyTypes.None, string.Empty, 0, string.Empty, string.Empty, protocol)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="PasswordConnectionInfo"/> class.
        /// </summary>
        /// <param name="host">Connection host.</param>
        /// <param name="port">The port.</param>
        /// <param name="username">Connection username.</param>
        /// <param name="proxyType">Type of the proxy.</param>
        /// <param name="proxyHost">The proxy host.</param>
        /// <param name="proxyPort">The proxy port.</param>
        /// <param name="keyFiles">The key files.</param>
        public AgentConnectionInfo(string host, int port, string username, ProxyTypes proxyType, string proxyHost, int proxyPort, IAgentProtocol protocol)
            : this(host, port, username, proxyType, proxyHost, proxyPort, string.Empty, string.Empty, protocol)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="PasswordConnectionInfo"/> class.
        /// </summary>
        /// <param name="host">Connection host.</param>
        /// <param name="port">The port.</param>
        /// <param name="username">Connection username.</param>
        /// <param name="proxyType">Type of the proxy.</param>
        /// <param name="proxyHost">The proxy host.</param>
        /// <param name="proxyPort">The proxy port.</param>
        /// <param name="proxyUsername">The proxy username.</param>
        /// <param name="keyFiles">The key files.</param>
        public AgentConnectionInfo(string host, int port, string username, ProxyTypes proxyType, string proxyHost, int proxyPort, string proxyUsername, IAgentProtocol protocol)
            : this(host, port, username, proxyType, proxyHost, proxyPort, proxyUsername, string.Empty, protocol)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="PasswordConnectionInfo"/> class.
        /// </summary>
        /// <param name="host">Connection host.</param>
        /// <param name="username">Connection username.</param>
        /// <param name="proxyType">Type of the proxy.</param>
        /// <param name="proxyHost">The proxy host.</param>
        /// <param name="proxyPort">The proxy port.</param>
        /// <param name="keyFiles">The key files.</param>
        public AgentConnectionInfo(string host, string username, ProxyTypes proxyType, string proxyHost, int proxyPort, IAgentProtocol protocol)
            : this(host, 22, username, proxyType, proxyHost, proxyPort, string.Empty, string.Empty, protocol)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="PasswordConnectionInfo"/> class.
        /// </summary>
        /// <param name="host">Connection host.</param>
        /// <param name="username">Connection username.</param>
        /// <param name="proxyType">Type of the proxy.</param>
        /// <param name="proxyHost">The proxy host.</param>
        /// <param name="proxyPort">The proxy port.</param>
        /// <param name="proxyUsername">The proxy username.</param>
        /// <param name="keyFiles">The key files.</param>
        public AgentConnectionInfo(string host, string username, ProxyTypes proxyType, string proxyHost, int proxyPort, string proxyUsername, IAgentProtocol protocol)
            : this(host, 22, username, proxyType, proxyHost, proxyPort, proxyUsername, string.Empty, protocol)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="PasswordConnectionInfo"/> class.
        /// </summary>
        /// <param name="host">Connection host.</param>
        /// <param name="username">Connection username.</param>
        /// <param name="proxyType">Type of the proxy.</param>
        /// <param name="proxyHost">The proxy host.</param>
        /// <param name="proxyPort">The proxy port.</param>
        /// <param name="proxyUsername">The proxy username.</param>
        /// <param name="proxyPassword">The proxy password.</param>
        /// <param name="keyFiles">The key files.</param>
        public AgentConnectionInfo(string host, string username, ProxyTypes proxyType, string proxyHost, int proxyPort, string proxyUsername, string proxyPassword, IAgentProtocol protocol)
            : this(host, 22, username, proxyType, proxyHost, proxyPort, proxyUsername, proxyPassword, protocol)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="PasswordConnectionInfo"/> class.
        /// </summary>
        /// <param name="host">Connection host.</param>
        /// <param name="port">The port.</param>
        /// <param name="username">Connection username.</param>
        /// <param name="proxyType">Type of the proxy.</param>
        /// <param name="proxyHost">The proxy host.</param>
        /// <param name="proxyPort">The proxy port.</param>
        /// <param name="proxyUsername">The proxy username.</param>
        /// <param name="proxyPassword">The proxy password.</param>
        /// <param name="keyFiles">The key files.</param>
        public AgentConnectionInfo(string host, int port, string username, ProxyTypes proxyType, string proxyHost, int proxyPort, string proxyUsername, string proxyPassword, IAgentProtocol protocol)
            : base(host, port, username, proxyType, proxyHost, proxyPort, proxyUsername, proxyPassword, new AgentAuthenticationMethod(username, protocol))
        {
            this.Protocol = protocol;
        }

        #region IDisposable Members

        private bool isDisposed = false;

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);

            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Releases unmanaged and - optionally - managed resources
        /// </summary>
        /// <param name="disposing"><c>true</c> to release both managed and unmanaged resources; <c>false</c> to release only unmanaged resources.</param>
        protected virtual void Dispose(bool disposing)
        {
            // Check to see if Dispose has already been called.
            if (!this.isDisposed)
            {
                // If disposing equals true, dispose all managed
                // and unmanaged resources.
                if (disposing)
                {
                    // Dispose managed resources.
                    if (this.AuthenticationMethods != null)
                    {
                        foreach (var authenticationMethods in this.AuthenticationMethods.OfType<IDisposable>())
                        {
                            authenticationMethods.Dispose();
                        }
                    }
                }

                // Note disposing has been done.
                isDisposed = true;
            }
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="PasswordConnectionInfo"/> is reclaimed by garbage collection.
        /// </summary>
        ~AgentConnectionInfo()
        {
            // Do not re-create Dispose clean-up code here.
            // Calling Dispose(false) is optimal in terms of
            // readability and maintainability.
            Dispose(false);
        }

        #endregion
    }
    /// <summary>
    /// Provides functionality to perform private key authentication.
    /// </summary>
    public class AgentAuthenticationMethod : AuthenticationMethod, IDisposable
    {
        private AuthenticationResult _authenticationResult = AuthenticationResult.Failure;

        private EventWaitHandle _authenticationCompleted = new ManualResetEvent(false);

        private bool _isSignatureRequired;

        /// <summary>
        /// Gets authentication method name
        /// </summary>
        public override string Name
        {
            get { return "publickey"; }
        }


        public IAgentProtocol Protocol { get; private set; }


        /// <summary>
        /// Initializes a new instance of the <see cref="PrivateKeyAuthenticationMethod"/> class.
        /// </summary>
        /// <param name="username">The username.</param>
        /// <param name="keyFiles">The key files.</param>
        /// <exception cref="ArgumentException"><paramref name="username"/> is whitespace or null.</exception>
        public AgentAuthenticationMethod(string username, IAgentProtocol protocol)
            : base(username)
        {
            this.Protocol = protocol;
        }

        /// <summary>
        /// Authenticates the specified session.
        /// </summary>
        /// <param name="session">The session to authenticate.</param>
        /// <returns></returns>
        public override AuthenticationResult Authenticate(Session session)
        {
            if (this.Protocol == null)
                return AuthenticationResult.Failure;

            session.UserAuthenticationSuccessReceived += Session_UserAuthenticationSuccessReceived;
            session.UserAuthenticationFailureReceived += Session_UserAuthenticationFailureReceived;
            session.MessageReceived += Session_MessageReceived;

            session.RegisterMessage("SSH_MSG_USERAUTH_PK_OK");

            foreach (var identity in this.Protocol.GetIdentities())
            {
                this._authenticationCompleted.Reset();
                this._isSignatureRequired = false;

                var message = new RequestMessagePublicKey(ServiceName.Connection, this.Username, identity.Type, identity.Blob);


                //  Send public key authentication request
                session.SendMessage(message);

                session.WaitOnHandle(this._authenticationCompleted);

                if (this._isSignatureRequired)
                {
                    this._authenticationCompleted.Reset();

                    var signatureMessage = new RequestMessagePublicKey(ServiceName.Connection, this.Username, identity.Type, identity.Blob);

                    var signatureData = new SignatureData(message, session.SessionId).GetBytes();

                    signatureMessage.Signature = this.Protocol.SignData(identity, signatureData);

                    //  Send public key authentication request with signature
                    session.SendMessage(signatureMessage);
                }

                session.WaitOnHandle(this._authenticationCompleted);

                if (this._authenticationResult == AuthenticationResult.Success)
                {
                    break;
                }
            }

            session.UserAuthenticationSuccessReceived -= Session_UserAuthenticationSuccessReceived;
            session.UserAuthenticationFailureReceived -= Session_UserAuthenticationFailureReceived;
            session.MessageReceived -= Session_MessageReceived;

            session.UnRegisterMessage("SSH_MSG_USERAUTH_PK_OK");

            return this._authenticationResult;
        }

        private void Session_UserAuthenticationSuccessReceived(object sender, MessageEventArgs<SuccessMessage> e)
        {
            this._authenticationResult = AuthenticationResult.Success;

            this._authenticationCompleted.Set();
        }

        private void Session_UserAuthenticationFailureReceived(object sender, MessageEventArgs<FailureMessage> e)
        {
            if (e.Message.PartialSuccess)
                this._authenticationResult = AuthenticationResult.PartialSuccess;
            else
                this._authenticationResult = AuthenticationResult.Failure;

            //  Copy allowed authentication methods
            this.AllowedAuthentications = e.Message.AllowedAuthentications.ToList();

            this._authenticationCompleted.Set();
        }

        private void Session_MessageReceived(object sender, MessageEventArgs<Message> e)
        {
            var publicKeyMessage = e.Message as PublicKeyMessage;
            if (publicKeyMessage != null)
            {
                this._isSignatureRequired = true;
                this._authenticationCompleted.Set();
            }
        }

        #region IDisposable Members

        private bool isDisposed = false;

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);

            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Releases unmanaged and - optionally - managed resources
        /// </summary>
        /// <param name="disposing"><c>true</c> to release both managed and unmanaged resources; <c>false</c> to release only unmanaged resources.</param>
        protected virtual void Dispose(bool disposing)
        {
            // Check to see if Dispose has already been called.
            if (!this.isDisposed)
            {
                // If disposing equals true, dispose all managed
                // and unmanaged resources.
                if (disposing)
                {
                    // Dispose managed resources.
                    if (this._authenticationCompleted != null)
                    {
                        this._authenticationCompleted.Dispose();
                        this._authenticationCompleted = null;
                    }
                }

                // Note disposing has been done.
                isDisposed = true;
            }
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="PasswordConnectionInfo"/> is reclaimed by garbage collection.
        /// </summary>
        ~AgentAuthenticationMethod()
        {
            // Do not re-create Dispose clean-up code here.
            // Calling Dispose(false) is optimal in terms of
            // readability and maintainability.
            Dispose(false);
        }

        #endregion

        private class SignatureData : SshData
        {
            private RequestMessagePublicKey _message;

            private byte[] _sessionId;

            public SignatureData(RequestMessagePublicKey message, byte[] sessionId)
            {
                this._message = message;
                this._sessionId = sessionId;
            }

            protected override void LoadData()
            {
                throw new System.NotImplementedException();
            }

            protected override void SaveData()
            {
                WriteBinaryString(_sessionId);
                Write((byte)RequestMessage.AuthenticationMessageCode);
                WriteBinaryString(_message.Username);
                WriteBinaryString(ServiceName.Connection.ToArray());
                WriteBinaryString(Ascii.GetBytes("publickey"));
                Write((byte)1); // TRUE
                WriteBinaryString(_message.PublicKeyAlgorithmName);
                WriteBinaryString(_message.PublicKeyData);
            }
        }

    }
}