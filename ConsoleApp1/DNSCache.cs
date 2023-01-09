using MySqlConnector;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace Nameserver
{
    class NameParams
    {
        public string localip { get; set; }
        public string remoteip { get; set; }
        public int ttl { get; set; }
        public bool allowsubdomains { get; set; }
        public DateTime lastupdated { get; set; }
    }
    class DNSCache
    {
        private Dictionary<string, NameParams> _dnsrules;
        public string nextip = "10.0.0.1";

        public DNSCache(string constr)
        {
            _dnsrules=new Dictionary<string, NameParams>();

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
                if (externalip == null) externalip = "";
                AddCache(name, localip, externalip, ttl, lastupdated);
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
        public string GetNextIpAddress(string ipAddress, uint increment)
        {
            byte[] addressBytes = IPAddress.Parse(ipAddress).GetAddressBytes().Reverse().ToArray();
            uint ipAsUint = BitConverter.ToUInt32(addressBytes, 0);
            var nextAddress = BitConverter.GetBytes(ipAsUint + increment);
            nextip = String.Join(".", nextAddress.Reverse());
            return nextip;
        }
        public bool IsInCache(string __name) //Checks if record already exists in the DNS cache
        {           
            return _dnsrules.ContainsKey(__name);
        }
        public string GetlocalIP(string __name) //Checks local IP in DNS cache
        {
            return _dnsrules[__name].localip;
        }
        public string GetremoteIP(string __name) //Checks remote IP in DNS cache
        {
            return _dnsrules[__name].remoteip;
        }
        public int Getttl(string __name) //Checks ttl in DNS cache
        {
            return _dnsrules[__name].ttl;
        }
        public DateTime Getlastupdated(string __name) //Checks last update timestamp in DNS cache
        {
            return _dnsrules[__name].lastupdated;
        }
        public NameParams GetRecord(string __name) //Returns record of NameParams type
        {
            return _dnsrules[__name];
        }
        public int GetCount()
        {
            return _dnsrules.Count();
        }
        public string[] GetNames()
        {
            return _dnsrules.Keys.ToArray();
        }

        public void AddCache(string __name, string __localip, string __externalip, int __ttl) // Adds new record in local cache
        {
            _dnsrules.Add(__name, new NameParams {localip=__localip, remoteip=__externalip, ttl=__ttl, lastupdated=DateTime.Now });
        }
        public void AddCache(string __name, string __localip, string __externalip, int __ttl, DateTime __lastupdated) // Adds new record in local cache
        {
            _dnsrules.Add(__name, new NameParams { localip = __localip, remoteip = __externalip, ttl = __ttl, lastupdated = __lastupdated });
        }
        public void ChangeCache(string __name, string __localip, string __externalip, int __ttl, DateTime __lastupdated) // Adds new record in local cache
        {
            _dnsrules[__name].localip = __localip;
            _dnsrules[__name].remoteip = __externalip;
            _dnsrules[__name].ttl = __ttl;
            _dnsrules[__name].lastupdated = __lastupdated;
        }
        public void RemoveCache(string __name)
        {
            _dnsrules.Remove(__name);
        }

        public void FlushCache()
        {
            _dnsrules.Clear();
        }
    }
}
    /*
    class DNSCache
    {
        public List<string> _name = new List<string>();
        public List<string> _localip = new List<string>();
        public List<string> _externalip = new List<string>();
        public List<DateTime> _lastupdated = new List<DateTime>();
        public List<int> _ttl = new List<int>();
        public string nextip = "10.0.0.1";

        public string GetNextIpAddress(string ipAddress, uint increment)
        {
            byte[] addressBytes = IPAddress.Parse(ipAddress).GetAddressBytes().Reverse().ToArray();
            uint ipAsUint = BitConverter.ToUInt32(addressBytes, 0);
            var nextAddress = BitConverter.GetBytes(ipAsUint + increment);
            nextip= String.Join(".", nextAddress.Reverse());
            return nextip;
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
        public bool IsInCache(string __name) //Checks if record already exists in the DNS cache
        {
            return _name.Contains(__name);
        }
        public string GetlocalIP(string __name) //Checks local IP in DNS cache
        {
            return _localip[_name.IndexOf(__name)];
        }

        public void AddCache(string __name, string __localip, string __externalip, int __ttl) // Adds new record in local cache
        {
            _name.Add(__name);
            _localip.Add(__localip);
            _externalip.Add(__externalip);
            _ttl.Add(__ttl);
            _lastupdated.Add(DateTime.Now);
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
    
} */
