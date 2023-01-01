using MySqlConnector;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace Nameserver
{
    //This class is used to initiate lists of local DNS cache. Translated NATted records are loaded from DB table dnsrecords into lists.
    // Later other external cache records will be added to the lists but not saved in DB.
    class DNSCache
    {
        public List<string> _name = new List<string>();
        public List<string> _localip = new List<string>();
        public List<string> _externalip = new List<string>();
        public List<DateTime> _lastupdated = new List<DateTime>();
        public List<int> _ttl = new List<int>();
        public string nextip = "10.0.0.1";

        public static string GetNextIpAddress(string ipAddress, uint increment)
        {
            byte[] addressBytes = IPAddress.Parse(ipAddress).GetAddressBytes().Reverse().ToArray();
            uint ipAsUint = BitConverter.ToUInt32(addressBytes, 0);
            var nextAddress = BitConverter.GetBytes(ipAsUint + increment);
            return String.Join(".", nextAddress.Reverse());
        }
        public DNSCache(string constr)
        {
            //Make SQL query to check dns rules for overriding
            Console2.WriteLine("Making SQL query to dnsrecords table...");
            using var connection = new MySqlConnection(constr);
            connection.Open();
            using var command = new MySqlCommand("SELECT * FROM dnsrecords;", connection);
            using var reader = command.ExecuteReader();
            int maxip = 0;
            string MAXIP = "10.0.0.0";
            while (reader.Read())
            {
                string name = (string)reader.GetValue(1);
                string localip = (string)reader.GetValue(2);
                string? externalip = (string)reader.GetValue(3);
                int ttl = (int)reader.GetValue(4);
                DateTime lastupdated = (DateTime)reader.GetValue(6);
                Console2.WriteLine("Domain=" + name + ", localip=" + localip + ", ttl=" + Convert.ToString(ttl) + ", lastupdated=" + Convert.ToString(lastupdated));
                _name.Add(name);
                _localip.Add(localip);
                if (externalip == null) externalip = "";
                _externalip.Add(externalip);
                _lastupdated.Add(lastupdated);
                _ttl.Add(ttl);
                //Looking for max local ip
                int address = BitConverter.ToInt32(IPAddress.Parse(localip).GetAddressBytes(), 0);
                if (address > maxip)
                {
                    maxip = address;
                    MAXIP = localip;
                }
            }
            nextip = GetNextIpAddress(MAXIP, 1);
            Console2.WriteLine("Max local IP address is " + MAXIP + ". Next IP address is " + nextip);

        }
        public void AddCache(string __name, string __localip, string __externalip, int __ttl) // Adds new record in local cache
        {
            if (_name.Contains(__name))
            {
                int ind = _name.IndexOf(__name);
                //_name[ind]=__name;
                _localip[ind] = __localip;
                _externalip[ind] = __externalip;
                _ttl[ind] = __ttl;
                _lastupdated[ind] = DateTime.Now;
            }
            else
            {
                _name.Add(__name);
                _localip.Add(__localip);
                _externalip.Add(__externalip);
                _ttl.Add(__ttl);
                _lastupdated.Add(DateTime.Now);
            }
        }
        public void RemoveCache(int ind)
        {
            _name.RemoveAt(ind);
            _localip.RemoveAt(ind);
            _externalip.RemoveAt(ind);
            _ttl.RemoveAt(ind);
            _lastupdated.RemoveAt(ind);
        }

        public void FlushCache()
        {
            _name.Clear();
            _localip.Clear();
            _externalip.Clear();
            _ttl.Clear();
            _lastupdated.Clear();
        }
    }
}
