
using ARSoft.Tools.Net;
using ARSoft.Tools.Net.Dns;
using MySqlConnector;
using System.Linq;
using System.Net;
using System.Reflection.PortableExecutable;
using System.Xml.Linq;

namespace dnsresolver;


class Dnsrules
{
    public List<string> domains = new List<string>();
    public List<bool> subdomains = new List<bool>();
    public Dnsrules(string constr) 
    {
        //Make SQL query to check dns rules for overriding
        Console.WriteLine("Making SQL query to dnsrules table...");
        using var connection = new MySqlConnection(constr);
        connection.Open();
        using var command = new MySqlCommand("SELECT * FROM dnsrules;", connection);
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {;
            string domain = (string)reader.GetValue(1);
            bool allowedsubdomains = (bool)reader.GetValue(2);
            Console.WriteLine("Domain="+domain+", allowed subdomains="+Convert.ToString(allowedsubdomains));
            domains.Add(domain);
            subdomains.Add(allowedsubdomains);
        }
    }

}


class DNSCache
{
    //public HashSet<string> cacheshot = new HashSet<string>();
    public List<string> _name = new List<string>();
    public List<string> _ip = new List<string>();
    public List<DateTime> _lastupdated = new List<DateTime>();
    public List<int> _ttl = new List<int>();
    public DNSCache(string constr)
    {
        //Make SQL query to check dns rules for overriding
        Console.WriteLine("Making SQL query to dnsrecords table...");
        using var connection = new MySqlConnection(constr);
        connection.Open();
        using var command = new MySqlCommand("SELECT * FROM dnsrecords;", connection);
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            string name = (string)reader.GetValue(1);
            string localip = (string)reader.GetValue(2);
            int ttl = (int)reader.GetValue(4);
            DateTime lastupdated = (DateTime)reader.GetValue(6);
            Console.WriteLine("Domain=" + name + ", localip=" + localip + ", ttl=" + Convert.ToString(ttl) + ", lastupdated=" + Convert.ToString(lastupdated));
            _name.Add(name);
            _ip.Add(localip);
            _lastupdated.Add(lastupdated);
            _ttl.Add(ttl);
        }
    }
    public void AddCache(string __name, string __ip, int __ttl)
    {
        _name.Add(__name);
        _ip.Add(__ip);
        _ttl.Add(__ttl);
        _lastupdated.Add(DateTime.Now);
    }
    

}
class Nameserver
{
    const string Constr = "Server=192.168.6.1;User ID=vScopeUserName;Password=password;Database=dns";
    const string DNSserver1 = "8.8.8.8";
    const int MAX_UPD_CONNS = 1000;
    const int MAX_TCP_CONNS = 100;
    static public Dnsrules? rules;
    static public DNSCache? dnscache;
    static void Main(string[] args)
    {
        
        Console.WriteLine("Starting DNS resolver...");
        
        //Forming list of domains for override
        rules = new Dnsrules(Constr);
        //Loading list of dns cache (overriden)
        dnscache = new DNSCache(Constr);
        
        using (DnsServer server = new DnsServer(IPAddress.Any, MAX_UPD_CONNS, MAX_TCP_CONNS))
        {
            server.QueryReceived += OnQueryReceived;

            server.Start();

            Console.WriteLine("Press any key to stop server");
            Console.ReadLine();
        }
    }

    static async Task OnQueryReceived(object sender, QueryReceivedEventArgs e)
    {
        Console.WriteLine("Processing DNS query");
        string IPresponse = null;
        bool NeedToUpdateList = false;
        string UpdateToList = null;
        try
        {
            DnsMessage query = e.Query as DnsMessage;

            if (query == null)
                return;
            DnsMessage response = query.CreateResponseInstance();

            if ((query.Questions.Count >= 1))
            {
                DnsQuestion question = query.Questions[0];

                Console.WriteLine("Record type=" + question.RecordType.ToString());
                if (question.RecordType.Equals(RecordType.A))
                {
                    string dname = question.Name.ToString();
                    if (dname[dname.Length - 1] == '.') dname = dname.Substring(0, dname.Length - 1);
                    if (dname != null) if (dname.Contains("."))
                        {
                            //Check if dns name is found in local cache
                            if (dnscache._name.Contains(dname)) //Name matched local cache
                            {
                                Console.WriteLine("Cache found for " + dname);
                                string LocalIP = dnscache._ip[dnscache._name.IndexOf(dname)];
                                Console.WriteLine("Local IP is " + LocalIP);
                                IPresponse = LocalIP;
                                response.ReturnCode = ReturnCode.NoError;
                                ARecord ar = new ARecord(DomainName.Parse(dname), 1, IPAddress.Parse(LocalIP));
                                response.AnswerRecords.Add(ar);

                            } else { //If record is not found in local cache
                                Console.WriteLine("No hit in cache. Checking against dns override list...");
                                //Compare requested a record to domain list
                                if (rules != null)
                                {
                                    string str = dname;
                                    int iter = 0;
                                    while (str.Contains('.'))
                                    {
                                        Console.WriteLine("Checking subdomain - " + str);
                                        if (rules.domains.Contains(str))
                                        {
                                            int ind1 = rules.domains.IndexOf(str);
                                            if (iter == 0)
                                            {
                                                Console.WriteLine("Explicit hit in dns override list for " + str);
                                                NeedToUpdateList = true;
                                                UpdateToList = str;
                                            }
                                            else
                                            {
                                                if (rules.subdomains[ind1] == true)
                                                {
                                                    Console.WriteLine("Allowed hit for subdomain - " + str);
                                                    NeedToUpdateList = true;
                                                    UpdateToList = str;
                                                }
                                                else
                                                {
                                                    Console.WriteLine("Not allowed hit for subdomain - " + str);
                                                }
                                            }
                                            break;
                                        }
                                        else
                                        {
                                            str = str.Substring(str.IndexOf(".") + 1);
                                            iter++;
                                        }
                                    }
                                    
                                }

                                //Initiate DNS resolution
                                var DNSClient2 = new DnsClient(IPAddress.Parse(DNSserver1), 3000, 53);
                                DNSClient2.IsUdpEnabled = true;
                                DNSClient2.IsTcpEnabled = false;
                                DnsQueryOptions opt2 = new DnsQueryOptions();
                                opt2.IsEDnsEnabled = false;
                                opt2.IsCheckingDisabled = false;
                                opt2.IsRecursionDesired = true;
                                opt2.IsDnsSecOk = false;
                                response.ReturnCode = ReturnCode.Refused;
                                DnsMessage upstreamResponse2 = await DNSClient2.ResolveAsync(question.Name, question.RecordType, question.RecordClass, opt2);
                                if ((upstreamResponse2 == null) || ((upstreamResponse2.ReturnCode != ReturnCode.NoError) && (upstreamResponse2.ReturnCode != ReturnCode.NxDomain)))
                                {
                                    Console.WriteLine("ERROR - DNS request to Upstream server failed");
                                    if (upstreamResponse2 != null) response.ReturnCode = upstreamResponse2.ReturnCode;
                                    //throw new Exception("DNS request failed");
                                }
                                // if got an answer, copy it to the message sent to the client
                                if (upstreamResponse2.AnswerRecords != null)
                                {
                                    foreach (DnsRecordBase record in (upstreamResponse2.AnswerRecords))
                                    {
                                        if (record is ARecord aRecord)
                                        {
                                            Console.WriteLine("Response: " + aRecord.Address.ToString());
                                            if (NeedToUpdateList == false) //DNS resolution successded. No need to translate the record
                                            {
                                                Console.WriteLine("DNS resolution successded. No need to translate the record");
                                                response.AnswerRecords.Add(record);
                                                string dname2 = aRecord.Name.ToString().ToLower();
                                                if (dname2[dname2.Length - 1] == '.') dname2 = dname2.Substring(0, dname2.Length - 1);
                                                dnscache.AddCache(dname2, aRecord.Address.ToString(), aRecord.TimeToLive);
                                                Console.WriteLine("Adding to local cache: name=" + dname2 + ", ip=" + aRecord.Address.ToString() + ", ttl=" + Convert.ToString(aRecord.TimeToLive));
                                            } else
                                            {
                                                //!!!!!!!!!!!!!!!Add code to translate IP
                                                Console.WriteLine("DNS resolution successded. Translating IP to local...");
                                                ARecord ar = new ARecord(DomainName.Parse(dname), 1, IPAddress.Parse("10.1.1.1"));
                                                response.AnswerRecords.Add(ar);
                                            }
                                            response.ReturnCode = ReturnCode.NoError;
                                            break; //We take only 1st IP from the list
                                        }
                                    }
                                    
                                }

                            }

                        }
                    
                } else // Request is NOT type A
                {

                    //Initiate DNS resolution of non-type A request
                    Console.WriteLine("Initiating DNS resolution for non-type A request - "+question.Name);
                    var DNSClient1 = new DnsClient(IPAddress.Parse(DNSserver1), 3000, 53);
                    DNSClient1.IsUdpEnabled = true;
                    DNSClient1.IsTcpEnabled = false;
                    DnsQueryOptions opt1 = new DnsQueryOptions();
                    opt1.IsEDnsEnabled = false;
                    opt1.IsCheckingDisabled = false;
                    opt1.IsRecursionDesired = true;
                    opt1.IsDnsSecOk = false;
                    response.ReturnCode = ReturnCode.Refused;
                    DnsMessage upstreamResponse1 = await DNSClient1.ResolveAsync(question.Name, question.RecordType, question.RecordClass, opt1);
                    if ((upstreamResponse1 == null) || ((upstreamResponse1.ReturnCode != ReturnCode.NoError) && (upstreamResponse1.ReturnCode != ReturnCode.NxDomain)))
                    {
                        Console.WriteLine("ERROR - DNS request to Upstream server failed");
                        if (upstreamResponse1 != null) response.ReturnCode = upstreamResponse1.ReturnCode;
                        //throw new Exception("DNS request failed");
                    }
                    // if got an answer, copy it to the message sent to the client
                    if (upstreamResponse1.AnswerRecords != null)
                    {
                        foreach (DnsRecordBase record in (upstreamResponse1.AnswerRecords))
                        {
                            response.AnswerRecords.Add(record);
                            Console.WriteLine("Adding DNS response - "+record.Name);
                        }
                        foreach (DnsRecordBase record in (upstreamResponse1.AdditionalRecords))
                        {
                            response.AdditionalRecords.Add(record);
                            Console.WriteLine("Adding DNS response - " + record.Name);
                        }
                        response.ReturnCode = ReturnCode.NoError;
                    }
                }

                // send the response
                Console.WriteLine("Sending DNS response");
                e.Response = response;
                
            }
        } catch(Exception ex) { 
            Console.WriteLine("ERROR HAS OCCURRED - "+ex.ToString());
        }
    }
}