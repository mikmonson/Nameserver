
using ARSoft.Tools.Net;
using ARSoft.Tools.Net.Dns;
using MySqlConnector;
using Nameserver;
using System;
using System.Data;
using System.Linq;
using System.Net;
using System.Reflection.PortableExecutable;
using System.Runtime.CompilerServices;
using System.Xml.Linq;
using static System.Collections.Specialized.BitVector32;

namespace dnsresolver;
/// <summary>
//TO DO:
// 1. flush and recreate of NAT transactions via iptables on the application init [in progress]
// 2. update method to create NAT via iptables [in progress]
// 3. create periodic task to 1). delete local cache entries with expired ttl 2). track changes in dnsrules table to update data in dnscache object
// 4. change IP address in local cache to list to support multiple IPs
// 5. add logging
/// </summary>

class Nameserver
{
    public static string Constr = "";//"Server=192.168.6.1;User ID=vScopeUserName;Password=password;Database=dns;";
    public static string DNSserver1 = "";//"8.8.8.8";
    public static string BASH_PATH = "";//"/home/mikmon/";
    const int MAX_UPD_CONNS = 1000;
    const int MAX_TCP_CONNS = 100;
    public const int DNS_TTL = 60;
    static public DNSRules? rules;
    static public DNSCache? dnscache;
    public static string nextip = "10.0.0.1";

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
            Console2.WriteLineCritical("ERROR!!! Can't start the process for iptables nat creation.");
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
            Console2.WriteLineCritical("ERROR!!! Can't start the process for iptables nat deletion.");
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

    static public void AddDNSrecord(string constr, string aname, string IP, string externalip, int ttl)
    {
        //Make SQL query to insert record with NAT in dnsrecords table;
        Console2.WriteLine("Make SQL query to insert record with NAT in dnsrecords table");
        string dt = DateTime.Now.ToString("s");
        dt = dt.Replace('T', ' ');
        string query = "INSERT INTO dnsrecords (aname, localIP, externalIP, ttl, lastupdated) VALUES ('" + aname + "', '" + IP + "', '" + externalip + "', '" + ttl + "', '" + dt + "');";
        Console2.WriteLine(query);
        using var connection1 = new MySqlConnection(constr);
        connection1.Open();
        using var command1 = new MySqlCommand(query, connection1);
        command1.ExecuteNonQuery();
    }

    static public void DeleteDNSrecord(string constr, string aname, string IP)
    {
        //Make SQL query to delete record with NAT in dnsrecords table;
        Console2.WriteLine("Make SQL query to delete record with NAT in dnsrecords table");
        string dt = DateTime.Now.ToString("s");
        dt = dt.Replace('T', ' ');
        string query = "DELETE FROM dnsrecords WHERE aname='" + aname + "' and localIP='" + IP + "';";
        Console2.WriteLine(query);
        using var connection1 = new MySqlConnection(constr);
        connection1.Open();
        using var command1 = new MySqlCommand(query, connection1);
        command1.ExecuteNonQuery();
    }

    static public void FlushDNSrecords(string constr)
    {
        //Make SQL query to delete all dns records;
        Console2.WriteLine("Make SQL query to delete all DNS records");
        string dt = DateTime.Now.ToString("s");
        dt = dt.Replace('T', ' ');
        string query = "DELETE FROM dnsrecords;";
        Console2.WriteLine(query);
        using var connection1 = new MySqlConnection(constr);
        connection1.Open();
        using var command1 = new MySqlCommand(query, connection1);
        command1.ExecuteNonQuery();
    }

    //Compare records in local cache with DB and checking expired TTL
    private static void CompareDNSrules()
    {
        
        //The below code is to track changes in SQL DB if local dnsrules were not changed.
        //Make SQL query to check dns rules for overriding
        Console2.WriteLine("Loading data from DB table dnsrules and comparing to local dnsrules list...");
        List<string> _domains = new List<string>();
        List<bool> _subdomains = new List<bool>();
        List<string> del_domains = new List<string>(); //To delete absolete
        List<bool> del_subdomains = new List<bool>(); //To delete absolete
        using var connection = new MySqlConnection(Constr);
        connection.Open();
        using var command = new MySqlCommand("SELECT * FROM dnsrules;", connection);
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            string domain = (string)reader.GetValue(1);
            bool allowedsubdomains = (bool)reader.GetValue(2);
            Console2.WriteLine("Domain=" + domain + ", allowed subdomains=" + Convert.ToString(allowedsubdomains));
            _domains.Add(domain);
            _subdomains.Add(allowedsubdomains);
            if (rules.domains.Contains(domain)) //Domains matched
            {
                if (rules.subdomains[rules.domains.IndexOf(domain)] != allowedsubdomains) // If subdomain value was changed
                {
                    rules.subdomains[rules.domains.IndexOf(domain)] = allowedsubdomains;
                    //If allowedsubdomains flag was changed we won't touch existing records. Need to do manual flush of cache.
                }
            }
            else // If some rules were added in DB and need to be added in dnsrules list -> no changes in dnscache/nat
            {
                rules.domains.Add(domain);
                rules.subdomains.Add(allowedsubdomains);
                Console2.WriteLine("Domains for addition: " + domain + " - Allowed subdomains: "+Convert.ToString(allowedsubdomains));
            }
        }
        if (rules.domains.Count > _domains.Count) //If some dns rules were removed from the DB and need to be deleted from dnsrules list
        {
            for (int i = rules.domains.Count - 1; i >= 0; i--) //Back loop for all elements to be able removing elements from the same list
            {
                if (!_domains.Contains(rules.domains[i])) //If DB is missing a record from dnsrules -> record was removed
                {
                    Console2.WriteLine("Domains for deletion: " + rules.domains[i] + " - Allowed subdomains: "+ rules.subdomains[i]);
                    del_domains.Add(rules.domains[i]);
                    del_subdomains.Add(rules.subdomains[i]);
                    rules.domains.RemoveAt(i);
                    rules.subdomains.RemoveAt(i);
                }
            }

        }
        
        //Now we need to check every dnscache record to see 1) if it needs to be deleted 2) if TTL expired
        //for (int i = dnscache._name.Count - 1; i >= 0; i--)
        foreach (string dn in dnscache.GetNames())
        {
            //string str = dnscache._name[i];
            bool removed = false;
            string resolvedip= dnscache.GetremoteIP(dn);
            string localip = dnscache.GetlocalIP(dn);
            int ttl = dnscache.Getttl(dn);
            DateTime lastupdated = dnscache.Getlastupdated(dn);
            //if (dnscache._localip[i].Substring(0, 3).Equals("10.")) //If local IP
            if (localip.Substring(0, 3).Equals("10.")) //If local IP
            {
                //resolvedip = dnscache._externalip[i];
                int iter = 0;
                string str = dn;
                while (str.Contains('.'))
                {
                    Console2.WriteLine("Checking subdomains of " + str + " against dnsrules for removal...");
                    if (del_domains.Contains(str))
                    {
                        int ind1 = del_domains.IndexOf(str);
                        if (iter == 0)
                        {
                            Console2.WriteLine("Explicit hit - domain/subdomain " + str + " matches one of dnsrules for removal.");
                            //remove domain -> we keep NAT unchanged to retain existing connections
                            //dnscache.RemoveCache(i);
                            dnscache.RemoveCache(str);
                            removed = true;
                        }
                        else
                        {
                            if (del_subdomains[ind1] == true)
                            {
                                Console2.WriteLine("Allowed hit for subdomain " + str + " for removal");
                                //remove subdomain -> we keep NAT unchanged to retain existing connections
                                //dnscache.RemoveCache(i);
                                dnscache.RemoveCache(str);
                                removed = true;
                            }
                            else
                            {
                                Console2.WriteLine("Not allowed hit for subdomain - " + str);
                            }
                        }
                        //break;
                    }
                    else
                    {
                        str = str.Substring(str.IndexOf(".") + 1);
                        iter++;
                    }
                }

            }
            else //If this is external record
            {
                //resolvedip = dnscache._localip[i];
                resolvedip = localip;
            }
            if (!removed) //If record wasn't deleted by above code
            {
                //str = dnscache._name[i];
                string str = dn;
                DateTime endTime = DateTime.Now;
                //TimeSpan span = endTime.Subtract(dnscache._lastupdated[i]);
                TimeSpan span = endTime.Subtract(lastupdated);
                //Console2.WriteLine("Comparing TTL=" + Convert.ToString(dnscache._ttl[i]) + " for " + str + " with time passed since last update: " + Convert.ToString(span.TotalSeconds));
                Console2.WriteLine("Comparing TTL=" + Convert.ToString(ttl) + " for " + str + " with time passed since last update: " + Convert.ToString(span.TotalSeconds));
                //if (span.TotalSeconds > dnscache._ttl[i])
                if (span.TotalSeconds > ttl)
                {
                    //Refreshing DNS entry
                    Console2.WriteLine("DNS record update is required! Initiating DNS request...");
                    removed = true;
                    string newip = null;
                    int newttl = DNS_TTL;
                    DnsMessage upstreamResponse2 = DNSRequest(DomainName.Parse(str), RecordType.A, RecordClass.INet);
                    if ((upstreamResponse2 == null) || ((upstreamResponse2.ReturnCode != ReturnCode.NoError) && (upstreamResponse2.ReturnCode != ReturnCode.NxDomain)))
                    {
                        Console2.WriteLine("ERROR - DNS request to Upstream server failed");
                    }
                    else if (upstreamResponse2.AnswerRecords != null)
                    {
                        bool match = false;
                        foreach (DnsRecordBase record in (upstreamResponse2.AnswerRecords))
                        {
                            if (record is ARecord aRecord)
                            {
                                if (aRecord.Address.ToString().Equals(resolvedip)) //If DNS still points to the same IP
                                {
                                    match = true;
                                    removed = false;
                                }
                                else
                                {
                                    newip = aRecord.Address.ToString(); //If no match we store resolved IP (will be used below)
                                    newttl = Math.Max(DNS_TTL,aRecord.TimeToLive); //If not match we store resolved TTL
                                }

                            }
                        }
                    }
                    if (removed) //If DNS record changed
                    {
                        if (newip != null)
                        {
                            //if (dnscache._localip[i].Substring(0, 3).Equals("10.")) //If local record needs to be refreshed
                            if (localip.Substring(0, 3).Equals("10.")) //If local record needs to be refreshed
                            {
                                string _nextip = dnscache.nextip;
                                nextip = dnscache.GetNextIpAddress(nextip, 1);
                                AddNAT(_nextip, newip); //We add new NAT but retain old NAT to keep existing connections
                                //DeleteDNSrecord(Constr, str, dnscache._localip[i]); //Update DNS record in DB by removing old record and inserving new record
                                DeleteDNSrecord(Constr, str, localip); //Update DNS record in DB by removing old record and inserving new record
                                //AddDNSrecord(Constr, str, _nextip, newip, dnscache._ttl[i]);
                                AddDNSrecord(Constr, str, _nextip, newip, newttl);
                                //dnscache._externalip[i] = newip;
                                //dnscache._localip[i] = _nextip;
                                //dnscache._lastupdated[i] = DateTime.Now;
                                dnscache.ChangeCache(str, _nextip, newip, newttl, DateTime.Now);
                            }
                            else //If external record needs to be refreshed
                            {
                                //dnscache._localip[i] = newip;
                                //dnscache._lastupdated[i] = DateTime.Now;
                                dnscache.ChangeCache(str, newip, newip, newttl, DateTime.Now);
                            }
                        }
                        else //If DNS resolution failed we just remove expired record
                        {
                            //if (dnscache._localip[i].Substring(0, 3).Equals("10.")) //If local record need to update DB "dnsrecords"
                            if (localip.Substring(0, 3).Equals("10.")) //If local record need to update DB "dnsrecords"
                            {
                                //DeleteDNSrecord(Constr, str, dnscache._localip[i]);
                                DeleteDNSrecord(Constr, str, localip);
                            }
                            //dnscache.RemoveCache(i);
                            dnscache.RemoveCache(str);
                        }
                    }
                }

            }


        }
        Console2.WriteLine("DNS cache refresh has finished.");

    }

    static private void MainLoop()
    {
        //Loading settings
        Console2.WriteLineCritical("Loading settings...");
        Console2.WriteLine(System.IO.Directory.GetCurrentDirectory()+"settings.txt");
        string[] lines = System.IO.File.ReadAllLines(@"settings.txt");
        Constr = lines[1];
        DNSserver1 = lines[2];
        BASH_PATH = lines[3];

        //Forming list of domains for override
        rules = new DNSRules(Constr);

        //Loading list of dns cached records (overriden) and calculating next usable ip for NAT
        dnscache = new DNSCache(Constr);
        nextip = dnscache.nextip;

        Console2.WriteLineCritical("Resetting NAT rules (ip tables)...");
        //Flushing and recreating nat rules in iptables
        DeleteNAT();
        //for (int ind = 0; ind < dnscache._name.Count; ind++)
        foreach (string dn in dnscache.GetNames())
        {
            //AddNAT(dnscache._localip[ind], dnscache._externalip[ind]);
            AddNAT(dnscache.GetlocalIP(dn), dnscache.GetremoteIP(dn));
        }

        Console2.WriteLine("Scheduling cache refresh task...");
        //Starting a task on the background to check ttl of cached records, remove outdated records and compare dns cache to DB in case any changes were made in DB.
        Task.Factory.StartNew(() =>
        {
            bool notexisting = false;
            while (notexisting == false)
            {
                Thread.Sleep(3600000);
                Console2.WriteLineCritical("Starting process to refresh local dns cache...");
                CompareDNSrules();
            }
        });

        //Starting DNS server
        Console2.WriteLineCritical("Starting DNS server...");
        using (DnsServer server = new DnsServer(IPAddress.Any, MAX_UPD_CONNS, MAX_TCP_CONNS))
        {
            server.QueryReceived += OnQueryReceived;
            server.Start();

            //!!! Add commands for adding and removing DB records, clearing tables/lists.
            //Loop to read commands
            string s = "show cache";
            while (!s.Equals("quit"))
            {
                //try
                {
                    Console2.WriteLineCritical("Type one of the following: 'show cache' to view dns cache, 'debug' to turn on/off debugging, 'quit' to stop the app, 'show rules' to view dns rules, 'add rule' or 'delete rule' to create/delete dns rule, 'refresh' to update dns cache, 'flush cache' to clear all dns cache.'");

                    if (s.Equals("show cache")) //Show local cache statistics
                    {
                        //for (int i = 0; i < dnscache._name.Count; i++)
                        foreach (string dn in dnscache.GetNames())
                        {
                            Console2.WriteLineCritical(dn + " - " + dnscache.GetlocalIP(dn) + " - " + dnscache.Getttl(dn));
                        }
                        Console2.WriteLineCritical("Total cache records: " + Convert.ToString(dnscache.GetCount()) + ". Next IP for local NAT: " + dnscache.nextip);
                    }
                    else if (s.Equals("show rules")) //Show dns rules
                    {
                        for (int i = 0; i < rules.domains.Count; i++)
                        {
                            Console2.WriteLineCritical(Convert.ToString(i + 1) + " - " + rules.domains[i] + " - Allowed subdomains: " + rules.subdomains[i]);
                        }
                        Console2.WriteLineCritical("Total dns rules: " + Convert.ToString(rules.domains.Count) + ". Next IP for local NAT: " + dnscache.nextip);
                    }
                    else if (s.Equals("debug")) //Enable/disable debugging
                    {
                        Console2.Debugging = !Console2.Debugging;
                        Console2.WriteLineCritical("System debug = " + Console2.Debugging.ToString());
                    }
                    else if (s.Equals("add rule")) //Add dns rule
                    {
                        string domain = "";
                        bool _allowedsubdomains = false;
                        Console2.WriteLineCritical("Enter domain name:");
                        domain = System.Console.ReadLine();
                        Console2.WriteLineCritical("Type yes to allow subdomains. Any other input will mean no.");
                        if (System.Console.ReadLine().Equals("yes"))
                        {
                            _allowedsubdomains = true;
                        }
                        if (domain.Length >= 4) if (domain.IndexOf('.') > 0)
                            {
                                if (rules.domains.Contains(domain))
                                {
                                    Console2.WriteLineCritical("DNS rule with this name already exists!");
                                }
                                else
                                {
                                    //Adding new dns rule
                                    rules.AddRule(Constr, domain, _allowedsubdomains);
                                    Console2.WriteLineCritical("DNS rule has been added.");
                                }
                            }
                            else //Wrong input
                            {
                                Console2.WriteLineCritical("Wrong input!");
                            }

                    }
                    else if (s.Equals("delete rule")) //Delete dns rule
                    {
                        Console2.WriteLineCritical("Choose rule number: 1.." + Convert.ToString(rules.domains.Count) + " to delete");
                        int rnum = 0;
                        try
                        {
                            rnum = Convert.ToInt16(System.Console.ReadLine());
                        }
                        catch { };
                        if ((rnum <= 0) || (rnum > rules.domains.Count))
                        {
                            Console2.WriteLineCritical("Wrong input!");
                        }
                        else //Removing rule
                        {
                            rules.DeleteRule(Constr, rnum - 1,false);
                            Console2.WriteLineCritical("DNS rule has been deleted from DB. Starting DNS cache refresh...");
                            CompareDNSrules();
                        }
                    }
                    else if (s.Equals("refresh")) //Refresh DNS rules, dnscache and TTL
                    {
                        Console2.WriteLineCritical("Starting refresh of dns cache... Enable debug to see details.");
                        CompareDNSrules();
                    }
                    else if (s.Equals("flush cache")) //Delete all NAT rules and local dnscache
                    {
                        //Flushing dns cached records in DB
                        FlushDNSrecords(Constr);
                        //Removing all cache
                        dnscache.FlushCache();
                        //Flushing nat rules in iptables
                        DeleteNAT();
                        //Resetting next ip for nat
                        dnscache.nextip = "10.0.0.1";
                    }
                    else Console2.WriteLineCritical("Input was not recognized");
                }
                //catch (Exception e)
                //{
                //    Console2.WriteLineCritical("Error occurred - "+e.ToString());
                //}
                s = System.Console.ReadLine();
            }
        }
    }
    static void Main(string[] args)
    {

        Console2.WriteLineCritical("Starting DNS resolver...");

        //Checking start arguments
        if (args.Length > 0) if (args[0].Equals("-debug")) Console2.Debugging = true;

        //Initiating DNS server
        MainLoop();
    }

    private static string RemoveLastDot(string name)
    {
        string result = name;
        if (name[name.Length - 1] == '.') result = name.Substring(0, name.Length - 1);
        return result;
    }

    private static DnsMessage DNSRequest(DomainName dn, RecordType rt, RecordClass rc)
    {
        //Initiate DNS resolution
        Console2.WriteLine("Initiating DNS resolution for request-" + rt.ToString() + " type, name: " + dn);
        try
        {
            var DNSClient1 = new DnsClient(IPAddress.Parse(DNSserver1), 3000, 53);
            DNSClient1.IsUdpEnabled = true;
            DNSClient1.IsTcpEnabled = false;
            DnsQueryOptions opt1 = new DnsQueryOptions();
            opt1.IsEDnsEnabled = false;
            opt1.IsCheckingDisabled = false;
            opt1.IsRecursionDesired = true;
            opt1.IsDnsSecOk = false;
            DnsMessage upstreamResponse1 = DNSClient1.Resolve(dn, rt, rc, opt1);
            return upstreamResponse1;
        }
        catch (Exception e)
        {
            Console2.WriteLineCritical("ERROR occurred during DNS request - " + e.Message);
            return null;
        }
    }
    static async Task OnQueryReceived(object sender, QueryReceivedEventArgs e)
    {
        Console2.WriteLine("Processing new DNS query...");
        string IPresponse = null;
        bool NeedToUpdateList = false;
        string UpdateToList = null;
        string? dname = null;
        string? needtoaddnat = null;
        string? needtoupdatenat_external = null;
        int req_ttl = DNS_TTL;
        long milliseconds = DateTimeOffset.Now.ToUnixTimeMilliseconds();
        try
        {

            DnsMessage query = e.Query as DnsMessage;

            if (query == null)
                return;
            DnsMessage response = query.CreateResponseInstance();
            response.ReturnCode = ReturnCode.Refused;

            if ((query.Questions.Count >= 1))
            {
                DnsQuestion question = query.Questions[0];

                Console2.WriteLine("Record type=" + question.RecordType.ToString());
                if (question.RecordType.Equals(RecordType.A))
                {
                    dname = RemoveLastDot(question.Name.ToString());
                    if (dname.Contains("."))
                    {
                        Console2.WriteLine("Record name: " + dname);
                        //Check if dns name is found in local cache
                        //if (dnscache._name.Contains(dname)) //Name matched local cache
                        if (dnscache.IsInCache(dname)) //Name matched local cache
                        {
                            Console2.WriteLine("Cache found for " + dname);
                            //string LocalIP = dnscache._localip[dnscache._name.IndexOf(dname)];
                            string LocalIP = dnscache.GetlocalIP(dname);
                            Console2.WriteLine("Local IP is " + LocalIP);
                            IPresponse = LocalIP;
                            response.ReturnCode = ReturnCode.NoError;
                            ARecord ar = new ARecord(DomainName.Parse(dname), DNS_TTL, IPAddress.Parse(LocalIP));
                            response.AnswerRecords.Add(ar);
                            milliseconds = Console2.Benchmark(milliseconds, 1);

                        }
                        else
                        { //If record is not found in local cache
                            Console2.WriteLine("No hit in cache. Checking against dns override list...");
                            if (rules != null)
                            {
                                string str = dname;
                                int iter = 0;
                                while (str.Contains('.'))
                                {
                                    Console2.WriteLine("Checking subdomain - " + str);
                                    milliseconds = Console2.Benchmark(milliseconds, 2);
                                    if (rules.domains.Contains(str))
                                    {
                                        int ind1 = rules.domains.IndexOf(str);
                                        if (iter == 0)
                                        {
                                            Console2.WriteLine("Explicit hit in dns override list for " + str);
                                            NeedToUpdateList = true;
                                            UpdateToList = str;
                                        }
                                        else
                                        {
                                            if (rules.subdomains[ind1] == true)
                                            {
                                                Console2.WriteLine("Allowed hit for subdomain - " + str);
                                                NeedToUpdateList = true;
                                                UpdateToList = str;
                                            }
                                            else
                                            {
                                                Console2.WriteLine("Not allowed hit for subdomain - " + str);
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
                            milliseconds = Console2.Benchmark(milliseconds, 3);
                            response.ReturnCode = ReturnCode.Refused;
                            DnsMessage upstreamResponse2 = DNSRequest(question.Name, question.RecordType, question.RecordClass);
                            milliseconds = Console2.Benchmark(milliseconds, 4);
                            if ((upstreamResponse2 == null) || ((upstreamResponse2.ReturnCode != ReturnCode.NoError) && (upstreamResponse2.ReturnCode != ReturnCode.NxDomain)))
                            {
                                Console2.WriteLine("ERROR - DNS request to Upstream server failed");
                                if (upstreamResponse2 != null) response.ReturnCode = upstreamResponse2.ReturnCode;
                                //throw new Exception("DNS request failed");
                            }
                            else if (upstreamResponse2.AnswerRecords != null)
                            {
                                foreach (DnsRecordBase record in (upstreamResponse2.AnswerRecords))
                                {
                                    if (record is ARecord aRecord)
                                    {
                                        Console2.WriteLine("Response: " + aRecord.Address.ToString());
                                        if (!dnscache.IsInCache(dname)) //Check if same record for some reason already exists in cache - it might be created within another DNS query which ran almost in parallel
                                        {
                                            if (NeedToUpdateList == false) //DNS resolution successded. No need to translate the record
                                            {
                                                Console2.WriteLine("DNS resolution succeeded. No need to translate the record");
                                                response.AnswerRecords.Add(record);
                                                dnscache.AddCache(dname, aRecord.Address.ToString(), "", aRecord.TimeToLive);
                                                Console2.WriteLine("Adding to local cache: name=" + dname + ", ip=" + aRecord.Address.ToString() + ", ttl=" + Convert.ToString(aRecord.TimeToLive));
                                            }
                                            else // DNS resolution succeeded. Need to add NAT
                                            {
                                                Console2.WriteLine("DNS resolution succeded. Translating IP to local...");
                                                string _nextip = nextip;
                                                nextip = dnscache.GetNextIpAddress(nextip, 1); //Incrementing next usabgle IP address
                                                Console2.WriteLine("New IP: " + _nextip);
                                                req_ttl = Math.Max(aRecord.TimeToLive, DNS_TTL);
                                                dnscache.AddCache(dname, _nextip, aRecord.Address.ToString(), req_ttl);
                                                needtoaddnat = _nextip; //Will update dnsrecords table in the end of the task.
                                                needtoupdatenat_external = aRecord.Address.ToString();
                                                var task1 = AddNatAsync(needtoaddnat, needtoupdatenat_external); //Run syncroneously not to delay the response
                                                milliseconds = Console2.Benchmark(milliseconds, 5);
                                                ARecord ar = new ARecord(DomainName.Parse(dname), 60, IPAddress.Parse(_nextip));
                                                response.AnswerRecords.Add(ar);
                                                milliseconds = Console2.Benchmark(milliseconds, 6);
                                            }
                                        } else //If record was already added in cache/DB by another parralel query
                                        {
                                            Console2.WriteLine("DNS resolution succeded. But record already exists in cache/DB.");
                                            needtoaddnat = null;
                                            NeedToUpdateList = false;
                                            ARecord ar = new ARecord(DomainName.Parse(dname), 60, IPAddress.Parse(dnscache.GetlocalIP(dname)));
                                            response.AnswerRecords.Add(ar);
                                            milliseconds = Console2.Benchmark(milliseconds, 6);
                                        }
                                        response.ReturnCode = ReturnCode.NoError;
                                        break; //We take only 1st IP from the list
                                    }
                                }

                            }

                        }

                    }

                }
                else // Request is NOT type A
                {
                    milliseconds = Console2.Benchmark(milliseconds, 7);
                    //Initiate DNS resolution of non-type A request
                    DnsMessage upstreamResponse1 = DNSRequest(question.Name, question.RecordType, question.RecordClass);
                    if ((upstreamResponse1 == null) || ((upstreamResponse1.ReturnCode != ReturnCode.NoError) && (upstreamResponse1.ReturnCode != ReturnCode.NxDomain)))
                    {
                        Console2.WriteLine("ERROR - DNS request to Upstream server failed");
                        if (upstreamResponse1 != null) response.ReturnCode = upstreamResponse1.ReturnCode;
                        //throw new Exception("DNS request failed");
                    }
                    else if (upstreamResponse1.AnswerRecords != null) // if got an answer, copy it to the message sent to the client
                    {
                        foreach (DnsRecordBase record in (upstreamResponse1.AnswerRecords))
                        {
                            response.AnswerRecords.Add(record);
                            Console2.WriteLine("Adding DNS response - " + record.Name);
                        }
                        foreach (DnsRecordBase record in (upstreamResponse1.AdditionalRecords))
                        {
                            response.AdditionalRecords.Add(record);
                            Console2.WriteLine("Adding DNS response - " + record.Name);
                        }
                        response.ReturnCode = ReturnCode.NoError;
                    }
                }
                milliseconds = Console2.Benchmark(milliseconds, 8);
            }
            // send the response
            Console2.WriteLine("Sending DNS response");
            e.Response = response;
            if (needtoaddnat != null)
            {
                Console2.WriteLine("Updating dnsrecords table: " + dname + "-" + needtoaddnat + "-" + needtoupdatenat_external);
                AddDNSrecord(Constr, dname, needtoaddnat, needtoupdatenat_external, req_ttl);
                milliseconds = Console2.Benchmark(milliseconds, 9);
            }


        }
        catch (Exception ex)
        {
            Console2.WriteLineCritical("ERROR HAS OCCURRED - " + ex.ToString());
        }

    }
}
