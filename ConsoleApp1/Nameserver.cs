
using ARSoft.Tools.Net;
using ARSoft.Tools.Net.Dns;
using MySqlConnector;
using System;
using System.Data;
using System.Linq;
using System.Net;
using System.Reflection.PortableExecutable;
using System.Runtime.CompilerServices;
using System.Xml.Linq;

namespace dnsresolver;
/// <summary>
//TO DO:
// 1. flush and recreate of NAT transactions via iptables on the application init [in progress]
// 2. update method to create NAT via iptables [in progress]
// 3. create periodic task to 1). delete local cache entries with expired ttl 2). track changes in dnsrules table to update data in dnscache object
// 4. change IP address in local cache to list to support multiple IPs
// 5. add logging
/// </summary>
static public class Console
{
    public static bool Logging = false;

    static public void WriteLine (string s)
    {
        if (Logging) System.Console.WriteLine(s);
    }
}
//This class loads list of domains for DNS override from table dnsrules to the lists.
class Dnsrules
{
    public List<string> domains = new List<string>();
    public List<bool> subdomains = new List<bool>();
    public static int minlength = 1;
    public Dnsrules(string constr) 
    {
        //Make SQL query to check dns rules for overriding
        Console.WriteLine("Making SQL query to dnsrules table...");
        using var connection = new MySqlConnection(constr);
        connection.Open();
        using var command = new MySqlCommand("SELECT * FROM dnsrules;", connection);
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            string domain = (string)reader.GetValue(1);
            bool allowedsubdomains = (bool)reader.GetValue(2);
            Console.WriteLine("Domain="+domain+", allowed subdomains="+Convert.ToString(allowedsubdomains));
            domains.Add(domain);
            subdomains.Add(allowedsubdomains);
        }
    }

}



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
        Console.WriteLine("Making SQL query to dnsrecords table...");
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
            Console.WriteLine("Domain=" + name + ", localip=" + localip + ", ttl=" + Convert.ToString(ttl) + ", lastupdated=" + Convert.ToString(lastupdated));
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
        Console.WriteLine("Max local IP address is " + MAXIP+". Next IP address is "+nextip);

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
        } else
        {
            _name.Add(__name);
            _localip.Add(__localip);
            _externalip.Add(__externalip);
            _ttl.Add(__ttl);
            _lastupdated.Add(DateTime.Now);
        }
    }
}

class Nameserver
{
    public static string Constr = "";//"Server=192.168.6.1;User ID=vScopeUserName;Password=password;Database=dns;";
    public static string DNSserver1 = "";//"8.8.8.8";
    public static string BASH_PATH = "";//"/home/mikmon/";
    const int MAX_UPD_CONNS = 1000;
    const int MAX_TCP_CONNS = 100;
    public const int DNS_TTL = 60;
    static public Dnsrules? rules;
    static public DNSCache? dnscache;
    public static string nextip="10.0.0.1";

    static public void AddNAT(string localip, string externalip) //Execute Linux commands
    {
        try
        {
            string command = "addiptablesnat.sh " + localip + " " + externalip;
            using (System.Diagnostics.Process proc = new System.Diagnostics.Process())
            {
                proc.StartInfo.FileName = "/bin/bash";
                proc.StartInfo.Arguments = "-c \" " + BASH_PATH + command + " \"";
                proc.StartInfo.UseShellExecute = false;
                proc.StartInfo.RedirectStandardOutput = true;
                proc.StartInfo.RedirectStandardError = true;
                proc.Start();

                //result += proc.StandardOutput.ReadToEnd();
                //result += proc.StandardError.ReadToEnd();

                proc.WaitForExit();
            }
        }
        catch
        {
            System.Console.WriteLine("ERROR!!! Can't start the process for iptables nat creation.");
        }
    }

    static public void DeleteNAT()
    {
        try
        {
            string command = "deliptablesnat.sh";
            using (System.Diagnostics.Process proc = new System.Diagnostics.Process())
            {
                proc.StartInfo.FileName = "/bin/bash";
                proc.StartInfo.Arguments = "-c \" " + BASH_PATH + command + " \"";
                proc.StartInfo.UseShellExecute = false;
                proc.StartInfo.RedirectStandardOutput = true;
                proc.StartInfo.RedirectStandardError = true;
                proc.Start();

                //result += proc.StandardOutput.ReadToEnd();
                //result += proc.StandardError.ReadToEnd();

                proc.WaitForExit();
            }
        }
        catch
        {
           System.Console.WriteLine("ERROR!!! Can't start the process for iptables nat deletion.");
        }
    }
    static async Task<string> AddNatAsync(string _localip, string _externalip)
    {
        string result = "tyt";
        await Task.Run(() =>
        {
            AddNAT(_localip, _externalip);
        });
        return result;
    }

    static public void UpdateDNSrecords(string constr, string aname, string IP, string externalip)
    {
        //Make SQL query to insert record with NAT in dnsrecords table;
        Console.WriteLine("Make SQL query to insert record with NAT in dnsrecords table");
        string dt = DateTime.Now.ToString("s");
        dt = dt.Replace('T', ' ');
        string query = "INSERT INTO dnsrecords (aname, localIP, externalIP, ttl, lastupdated) VALUES ('" + aname + "', '" + IP + "', '" + externalip + "', '"+DNS_TTL+"', '" + dt + "');";
        Console.WriteLine(query);
        using (var connection1 = new MySqlConnection(constr)) { 
        connection1.Open();
        using var command1 = new MySqlCommand(query, connection1);
        command1.ExecuteNonQuery();
        }
    }

    static void Main(string[] args)
    {
        
        System.Console.WriteLine("Starting DNS resolver...");
        if (args.Length > 0) if (args[0].Equals("-debug")) Console.Logging = true;
        Console.WriteLine("Loading settings...");
        System.Console.WriteLine(System.IO.Directory.GetCurrentDirectory());
        string[] lines = System.IO.File.ReadAllLines(@"settings.txt");
        Constr = lines[1];
        DNSserver1 = lines[2];
        BASH_PATH = lines[3];
        //Forming list of domains for override
        rules = new Dnsrules(Constr);
        //Loading list of dns cache (overriden) and calculating next usable ip for NAT
        dnscache = new DNSCache(Constr);
        nextip = dnscache.nextip;
        //Flushing and recreating nat rules in iptables
        DeleteNAT();
        for (int ind=0; ind<dnscache._name.Count; ind++)
        {
            AddNAT(dnscache._localip[ind], dnscache._externalip[ind]);
        }

        using (DnsServer server = new DnsServer(IPAddress.Any, MAX_UPD_CONNS, MAX_TCP_CONNS))
        {
            server.QueryReceived += OnQueryReceived;

            server.Start();

            System.Console.WriteLine("Press any key to stop server. Type 'stats' to view local cache.");
            string s="stat";
            while (s.Contains("stat"))
            {
                for (int i=0; i<dnscache._name.Count; i++){
                    System.Console.WriteLine(dnscache._name[i] + "-" + dnscache._localip[i] + "-" + dnscache._ttl[i]);
                }
                System.Console.WriteLine("Total cache records: " + Convert.ToString(dnscache._name.Count));
                s = System.Console.ReadLine();
            }
        }
    }

    static async Task OnQueryReceived(object sender, QueryReceivedEventArgs e)
    {
        Console.WriteLine("Processing new DNS query...");
        string IPresponse = null;
        bool NeedToUpdateList = false;
        string UpdateToList = null;
        string? dname = null;
        string? needtoaddnat = null;
        string? needtoupdatenat_external = null;
        long milliseconds = DateTimeOffset.Now.ToUnixTimeMilliseconds();
        try
        {
            
            Console.WriteLine("Benchmark - before DNS request -"+Convert.ToString(milliseconds));
            DnsMessage query = e.Query as DnsMessage;

            if (query == null)
                return;
            DnsMessage response = query.CreateResponseInstance();
            response.ReturnCode = ReturnCode.Refused;

            if ((query.Questions.Count >= 1))
            {
                DnsQuestion question = query.Questions[0];

                Console.WriteLine("Record type=" + question.RecordType.ToString());
                if (question.RecordType.Equals(RecordType.A))
                {
                    dname = question.Name.ToString();
                    if (dname[dname.Length - 1] == '.') dname = dname.Substring(0, dname.Length - 1);
                    if (dname != null) if (dname.Contains("."))
                        {
                            Console.WriteLine("Record name: "+dname);
                            //Check if dns name is found in local cache
                            if (dnscache._name.Contains(dname)) //Name matched local cache
                            {
                                Console.WriteLine("Cache found for " + dname);
                                string LocalIP = dnscache._localip[dnscache._name.IndexOf(dname)];
                                Console.WriteLine("Local IP is " + LocalIP);
                                IPresponse = LocalIP;
                                response.ReturnCode = ReturnCode.NoError;
                                ARecord ar = new ARecord(DomainName.Parse(dname), 1, IPAddress.Parse(LocalIP));
                                response.AnswerRecords.Add(ar);
                                Console.WriteLine("Benchmark2 " + Convert.ToString(DateTimeOffset.Now.ToUnixTimeMilliseconds() -milliseconds));
                                milliseconds = DateTimeOffset.Now.ToUnixTimeMilliseconds(); ;

                            } else { //If record is not found in local cache
                                Console.WriteLine("No hit in cache. Checking against dns override list...");
                                //Compare requested a record to domain list

                                //string[] subdomains = dname.Split('.');

                                if (rules != null)
                                {
                                    string str = dname;
                                    int iter = 0;
                                    while (str.Contains('.'))
                                    {
                                        Console.WriteLine("Checking subdomain - " + str);
                                        Console.WriteLine("Benchmark3 " + Convert.ToString(DateTimeOffset.Now.ToUnixTimeMilliseconds() - milliseconds));
                                        milliseconds = DateTimeOffset.Now.ToUnixTimeMilliseconds(); ;
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
                                Console.WriteLine("Benchmark4 " + Convert.ToString(DateTimeOffset.Now.ToUnixTimeMilliseconds() - milliseconds));
                                milliseconds = DateTimeOffset.Now.ToUnixTimeMilliseconds(); ;
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
                                Console.WriteLine("Benchmark5 " + Convert.ToString(DateTimeOffset.Now.ToUnixTimeMilliseconds() - milliseconds));
                                milliseconds = DateTimeOffset.Now.ToUnixTimeMilliseconds(); ;
                                if ((upstreamResponse2 == null) || ((upstreamResponse2.ReturnCode != ReturnCode.NoError) && (upstreamResponse2.ReturnCode != ReturnCode.NxDomain)))
                                {
                                    Console.WriteLine("ERROR - DNS request to Upstream server failed");
                                    if (upstreamResponse2 != null) response.ReturnCode = upstreamResponse2.ReturnCode;
                                    //throw new Exception("DNS request failed");
                                } else if (upstreamResponse2.AnswerRecords != null)
                                {
                                    foreach (DnsRecordBase record in (upstreamResponse2.AnswerRecords))
                                    {
                                        if (record is ARecord aRecord)
                                        {
                                            Console.WriteLine("Response: " + aRecord.Address.ToString());
                                            if (NeedToUpdateList == false) //DNS resolution successded. No need to translate the record
                                            {
                                                Console.WriteLine("DNS resolution succeeded. No need to translate the record");
                                                response.AnswerRecords.Add(record);
                                                //string dname2 = aRecord.Name.ToString().ToLower();
                                                //if (dname2[dname2.Length - 1] == '.') dname2 = dname2.Substring(0, dname2.Length - 1);
                                                dnscache.AddCache(dname, aRecord.Address.ToString(), "", aRecord.TimeToLive);
                                                Console.WriteLine("Adding to local cache: name=" + dname + ", ip=" + aRecord.Address.ToString() + ", ttl=" + Convert.ToString(aRecord.TimeToLive));
                                            } else // DNS resolution succeeded. Need to add NAT
                                            {
                                                Console.WriteLine("DNS resolution successded. Translating IP to local...");                                               
                                                string _nextip = nextip;
                                                nextip = DNSCache.GetNextIpAddress(nextip, 1); //Incrementing next usabgle IP address
                                                Console.WriteLine("New IP: "+_nextip);
                                                dnscache.AddCache(dname, _nextip, aRecord.Address.ToString(), DNS_TTL);
                                                needtoaddnat = _nextip; //Will update dnsrecords table in the end of the task.
                                                needtoupdatenat_external = aRecord.Address.ToString();
                                                var task1 = AddNatAsync(needtoaddnat, needtoupdatenat_external); //Run syncroneously not to delay the response
                                                Console.WriteLine("Benchmark6 " + Convert.ToString(DateTimeOffset.Now.ToUnixTimeMilliseconds() - milliseconds));
                                                milliseconds = DateTimeOffset.Now.ToUnixTimeMilliseconds();
                                                ARecord ar = new ARecord(DomainName.Parse(dname), 1, IPAddress.Parse(_nextip));
                                                response.AnswerRecords.Add(ar);
                                                Console.WriteLine("Benchmark7 " + Convert.ToString(DateTimeOffset.Now.ToUnixTimeMilliseconds() - milliseconds));
                                                milliseconds = DateTimeOffset.Now.ToUnixTimeMilliseconds();
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
                    Console.WriteLine("Benchmark8 " + Convert.ToString(DateTimeOffset.Now.ToUnixTimeMilliseconds() - milliseconds));
                    milliseconds = DateTimeOffset.Now.ToUnixTimeMilliseconds();
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
                    DnsMessage upstreamResponse1 = await DNSClient1.ResolveAsync(question.Name, question.RecordType, question.RecordClass, opt1);
                    if ((upstreamResponse1 == null) || ((upstreamResponse1.ReturnCode != ReturnCode.NoError) && (upstreamResponse1.ReturnCode != ReturnCode.NxDomain)))
                    {
                        Console.WriteLine("ERROR - DNS request to Upstream server failed");
                        if (upstreamResponse1 != null) response.ReturnCode = upstreamResponse1.ReturnCode;
                        //throw new Exception("DNS request failed");
                    } else if (upstreamResponse1.AnswerRecords != null) // if got an answer, copy it to the message sent to the client
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
                Console.WriteLine("Benchmark10 " + Convert.ToString(DateTimeOffset.Now.ToUnixTimeMilliseconds() - milliseconds));
                milliseconds = DateTimeOffset.Now.ToUnixTimeMilliseconds();                
            }
            // send the response
            Console.WriteLine("Sending DNS response");
            e.Response = response;
            if (needtoaddnat != null) {
                Console.WriteLine("Updating dnsrecords table: "+dname+"-"+needtoaddnat+"-"+needtoupdatenat_external);
                UpdateDNSrecords(Constr, dname, needtoaddnat, needtoupdatenat_external);
                Console.WriteLine("Benchmark11 " + Convert.ToString(DateTimeOffset.Now.ToUnixTimeMilliseconds() - milliseconds));
                milliseconds = DateTimeOffset.Now.ToUnixTimeMilliseconds();
                Thread.Sleep(8000);
            }


        }
        catch (Exception ex) { 
            System.Console.WriteLine("ERROR HAS OCCURRED - "+ex.ToString());
        }

    }
}