﻿namespace Renci.SshClient.Messages.Connection
{
    internal class ForwardedTcpipChannelInfo : ChannelOpenInfo
    {
        public const string NAME = "forwarded-tcpip";

        public override string ChannelType
        {
            get { return ForwardedTcpipChannelInfo.NAME; }
        }

        public string ConnectedAddress { get; set; }

        public uint ConnectedPort { get; set; }

        public string OriginatorAddress { get; set; }

        public uint OriginatorPort { get; set; }

        protected override void LoadData()
        {
            base.LoadData();

            this.ConnectedAddress = this.ReadString();
            this.ConnectedPort = this.ReadUInt32();
            this.OriginatorAddress = this.ReadString();
            this.OriginatorPort = this.ReadUInt32();
        }

        protected override void SaveData()
        {
            base.SaveData();

            this.Write(this.ConnectedAddress);
            this.Write(this.ConnectedPort);
            this.Write(this.OriginatorAddress);
            this.Write(this.OriginatorPort);
        }
    }
}