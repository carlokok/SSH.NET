namespace Renci.SshNet.Messages.Authentication
{
    /// <summary>
    /// Represents SSH_MSG_USERAUTH_SUCCESS message.
    /// </summary>
    [Message("SSH_MSG_USERAUTH_SUCCESS", 52)]
    public class SuccessMessage : Message
    {
        public override MessageType Type
        {
            get
            {
                return MessageType.Success;
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
