using System;
using System.Collections.Generic;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Renci.SshNet.Common;

namespace Renci.SshNet.Pageant
{
    class UnixEndPoint : EndPoint
    {
        string filename;
        public UnixEndPoint(string filename)
        {
            this.filename = filename;
        }

        public override AddressFamily AddressFamily
        {
            get
            {
                return AddressFamily.Unix;
            }
        }

        public override SocketAddress Serialize()
        {
            var data = Encoding.Default.GetBytes(filename);
            SocketAddress res = new SocketAddress(AddressFamily.Unix, data.Length + 3);
            for (int i = 0; i < data.Length; i++)
                res[i + 2] = data[i];

            return res;
        }
    }
    public class SshAgentProtocol : IAgentProtocol
    {

        #region  Constants

        private const int WM_COPYDATA = 0x004A;

        private const int AGENT_COPYDATA_ID = unchecked((int)0x804e50ba);

        private const int AGENT_MAX_MSGLEN = 8192;

        public const byte SSH2_AGENTC_REQUEST_IDENTITIES = 11;

        public const byte SSH2_AGENT_IDENTITIES_ANSWER = 12;

        public const byte SSH2_AGENTC_SIGN_REQUEST = 13;

        public const byte SSH2_AGENT_SIGN_RESPONSE = 14;

        #endregion


        public static bool IsRunning
        {
            get
            {
                var s = Environment.GetEnvironmentVariable("SSH_AUTH_SOCK");
                if (String.IsNullOrEmpty(s)) return false;

                return File.Exists(s);
            }
        }



        public SshAgentProtocol()
        {

        }


        #region Implementation of IAgentProtocol

        IEnumerable<IdentityReference> IAgentProtocol.GetIdentities()
        {
            if (!IsRunning) yield break;
            byte[] data;
            try
            {
                using (var sock = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.IP))
                {
                    sock.Connect(new UnixEndPoint(Environment.GetEnvironmentVariable("SSH_AUTH_SOCK")));
                    data = new byte[5];
                    Array.Copy(BitConverter.GetBytes(IPAddress.NetworkToHostOrder(1)), 0, data, 0, 4);
                    data[4] = SSH2_AGENTC_REQUEST_IDENTITIES;
                    var q = sock.Send(data, 0, 5, SocketFlags.None);
                    if (sock.Receive(data, 0, 4, SocketFlags.None) != 4)
                        yield break;
                    int len = IPAddress.HostToNetworkOrder(BitConverter.ToInt32(data, 0));
                    data = new byte[len];
                    int off = 0;
                    while (off < len)
                    {
                        int lendata = sock.Receive(data, 0, len - off, SocketFlags.None);
                        if (lendata == 0) yield break;
                        off += lendata;
                    }
                }
            }
            catch
            {
                yield break;  
            }

            if (data[0] != SSH2_AGENT_IDENTITIES_ANSWER) yield break;
                int numberOfIdentities = IPAddress.HostToNetworkOrder(BitConverter.ToInt32(data, 1));

                if (numberOfIdentities == 0)
                {
                    yield break;
                }

                int position = 5;
                for (int i = 0; i < numberOfIdentities; i++)
                {
                    int blobSize = IPAddress.HostToNetworkOrder(BitConverter.ToInt32(data, position));
                    position += 4;

                    var blob = new byte[blobSize];
                    Array.Copy(data, position, blob, 0, blobSize);

                    position += blobSize;
                    int commentLength = IPAddress.HostToNetworkOrder(BitConverter.ToInt32(data, position));
                    position += 4;
                    var commentChars = new byte[commentLength];
                    Array.Copy(data, position, commentChars, 0, commentLength);
                    position += commentLength;

                    string comment = Encoding.ASCII.GetString(commentChars);
                    string type = Encoding.ASCII.GetString(blob, 4, 7);// needs more testing kind of hack
                    Console.WriteLine("returning identity " + comment + "  " + type);
                    yield return new IdentityReference(type, blob, comment);


                }
        }

        byte[] IAgentProtocol.SignData(IdentityReference identity, byte[] data)
        {
            byte[] resdata;
            try
            {
                using (var sock = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.IP))
                {
                    sock.Connect(new UnixEndPoint(Environment.GetEnvironmentVariable("SSH_AUTH_SOCK")));
                    BinaryWriter bw = new BinaryWriter(new MemoryStream(AGENT_MAX_MSGLEN));
                    bw.Write((int)0);
                    bw.Write(SSH2_AGENTC_SIGN_REQUEST);
                    bw.Write(IPAddress.NetworkToHostOrder(identity.Blob.Length));
                    bw.Write(identity.Blob);
                    bw.Write(IPAddress.NetworkToHostOrder(data.Length));
                    bw.Write(data);
                    bw.Write((int)0); // flags
                    bw.Flush();
                    bw.BaseStream.Position = 0;
                    bw.Write(IPAddress.NetworkToHostOrder((int)(bw.BaseStream.Length - 4)));
                    bw.Flush();

                    sock.Send(((MemoryStream)bw.BaseStream).ToArray());
                    resdata = new byte[4];
                    if (sock.Receive(resdata, 0, 4, SocketFlags.None) != 4)
                        return new byte[0];

                    int len = IPAddress.HostToNetworkOrder(BitConverter.ToInt32(resdata, 0));
                    resdata = new byte[len];
                    int off = 0;
                    while (off < len)
                    {
                        int lendata = sock.Receive(resdata, 0, len - off, SocketFlags.None);
                        if (lendata == 0) return new byte[0];
                        off += lendata;
                    }
                }
            } catch
            {
                return new byte[0];
            }
            if (resdata[0] != SSH2_AGENT_SIGN_RESPONSE) return new byte[0];
            int size = IPAddress.HostToNetworkOrder(BitConverter.ToInt32(resdata, 1));
            var ret = new byte[size];
            Array.Copy(resdata, 5, ret, 0, size);
            return ret;
        }
 
        #endregion
    }
}
