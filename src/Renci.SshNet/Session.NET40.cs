using System.Threading.Tasks;
using System.Linq;
using Renci.SshNet.Messages;
using Renci.SshNet.Messages.Authentication;
using Renci.SshNet.Messages.Connection;
using Renci.SshNet.Messages.Transport;

namespace Renci.SshNet
{
    /// <summary>
    /// Provides functionality to connect and interact with SSH server.
    /// </summary>
    public partial class Session
    {
        partial void HandleMessageCore(Message message)
        {
            switch (message.Type)
            {
                case MessageType.Failure: HandleMessage((FailureMessage)message); break;
                case MessageType.InformationRequest: HandleMessage((InformationRequestMessage)message); break;
                case MessageType.InformationResponse: HandleMessage((InformationResponseMessage)message); break;
                case MessageType.PasswordChangeRequired: HandleMessage((PasswordChangeRequiredMessage)message); break;
                case MessageType.PublicKey: HandleMessage((PublicKeyMessage)message); break;
                case MessageType.RequestMessageHost: HandleMessage((RequestMessageHost)message); break;
                case MessageType.RequestKeyboardInteractive: HandleMessage((RequestMessageKeyboardInteractive)message); break;
                case MessageType.RequestNone: HandleMessage((RequestMessageNone)message); break;
                case MessageType.RequestPassword: HandleMessage((RequestMessagePassword)message); break;
                case MessageType.Success: HandleMessage((SuccessMessage)message); break;
                case MessageType.ChannelClose: HandleMessage((ChannelCloseMessage)message); break;
                case MessageType.ChannelData: HandleMessage((ChannelDataMessage)message); break;
                case MessageType.ChannelEof: HandleMessage((ChannelEofMessage)message); break;
                case MessageType.ChannelExtendedData: HandleMessage((ChannelExtendedDataMessage)message); break;
                case MessageType.ChannelFailure: HandleMessage((ChannelFailureMessage)message); break;
                case MessageType.ChannelOpenConfirmation: HandleMessage((ChannelOpenConfirmationMessage)message); break;
                case MessageType.ChannelOpenFailure: HandleMessage((ChannelOpenFailureMessage)message); break;
                case MessageType.ChannelOpenMessage: HandleMessage((ChannelOpenMessage)message); break;
                case MessageType.ChannelRequestMessage: HandleMessage((ChannelRequestMessage)message); break;
                case MessageType.ChannelSuccessMessage: HandleMessage((ChannelSuccessMessage)message); break;
                case MessageType.ChannelWindowAdjustMessage: HandleMessage((ChannelWindowAdjustMessage)message); break;
                case MessageType.GlobalRequest: HandleMessage((GlobalRequestMessage)message); break;
                case MessageType.RequestFailure: HandleMessage((RequestFailureMessage)message); break;
                case MessageType.RequestSuccess: HandleMessage((RequestSuccessMessage)message); break;
                case MessageType.Debug: HandleMessage((DebugMessage)message); break;
                case MessageType.Ignore: HandleMessage((IgnoreMessage)message); break;
                case MessageType.KeyExchangeDhGroupExchangeInit: HandleMessage((KeyExchangeDhGroupExchangeInit)message); break;
                case MessageType.NewKeys: HandleMessage((NewKeysMessage)message); break;
                case MessageType.Disconnect: HandleMessage((DisconnectMessage)message); break;
                case MessageType.ServiceAccept: HandleMessage((ServiceAcceptMessage)message); break;
                case MessageType.ServiceRequest: HandleMessage((ServiceRequestMessage)message); break;
                case MessageType.Unimplemented: HandleMessage((UnimplementedMessage)message); break;

                case MessageType.Banner: HandleMessage((BannerMessage)message); break;
                case MessageType.KeyExchangeDhGroupExchangeGroup: HandleMessage((KeyExchangeDhGroupExchangeGroup)message); break;
                case MessageType.KeyExchangeDhGroupExchangeReply: HandleMessage((KeyExchangeDhGroupExchangeReply)message); break;
                case MessageType.KeyExchangeDhGroupExchangeRequest: HandleMessage((KeyExchangeDhGroupExchangeRequest)message); break;
                case MessageType.KeyExchangeDhInitMessage: HandleMessage((KeyExchangeDhInitMessage)message); break;
                case MessageType.KeyExchangeDhReplyMessage: HandleMessage((KeyExchangeDhReplyMessage)message); break;
                case MessageType.KeyExchangeEcdhInitMessage: HandleMessage((KeyExchangeEcdhInitMessage)message); break;
                case MessageType.KeyExchangeEcdhReplyMessage: HandleMessage((KeyExchangeEcdhReplyMessage)message); break;
                case MessageType.KeyExchangeInit: HandleMessage((KeyExchangeInitMessage)message); break;
                case MessageType.RequestPublicKey: HandleMessage((RequestMessagePublicKey)message); break;

            }
        }

        partial void InternalRegisterMessage(string messageName)
        {
            lock (_messagesMetadata)
            {
                Parallel.ForEach(
                    from m in _messagesMetadata where m.Name == messageName select m,
                    item => { item.Enabled = true; item.Activated = true; });
            }
        }

        partial void InternalUnRegisterMessage(string messageName)
        {
            lock (_messagesMetadata)
            {
                Parallel.ForEach(
                    from m in _messagesMetadata where m.Name == messageName select m,
                    item => { item.Enabled = false; item.Activated = false; });
            }
        }
    }
}
