
namespace Renci.SshNet.Messages.Connection
{
    /// <summary>
    /// Represents SSH_MSG_REQUEST_FAILURE message.
    /// </summary>
    [Message("SSH_MSG_REQUEST_FAILURE", 82)]
    public class RequestFailureMessage : Message
    {
        public override MessageType Type
        {
            get
            {
                return MessageType.RequestFailure;
            }
        }
        /// <summary>
        /// Called when type specific data need to be loaded.
        /// </summary>
        protected override void LoadData()
        {
        }

        /// <summary>
        /// Called when type specific data need to be saved.
        /// </summary>
        protected override void SaveData()
        {
        }
    }
}
