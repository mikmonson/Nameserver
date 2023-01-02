using MySqlConnector;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Nameserver
{
    //This class loads list of domains for DNS override from table dnsrules to the lists.
    class DNSRules
    {
        public List<string> domains = new List<string>();
        public List<bool> subdomains = new List<bool>();
        public static int minlength = 1;
        public DNSRules(string constr)
        {
            //Make SQL query to check dns rules for overriding
            Console2.WriteLine("Making SQL query to dnsrules table...");
            using var connection = new MySqlConnection(constr);
            connection.Open();
            using var command = new MySqlCommand("SELECT * FROM dnsrules;", connection);
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                string domain = (string)reader.GetValue(1);
                bool allowedsubdomains = (bool)reader.GetValue(2);
                Console2.WriteLine("Domain=" + domain + ", allowed subdomains=" + Convert.ToString(allowedsubdomains));
                domains.Add(domain);
                subdomains.Add(allowedsubdomains);
            }
        }

        public void AddRule(string constr, string domain, bool allowedsubdomains) //Add new rule in DB
        {
            //Make SQL query to insert dns rule in DB;
            Console2.WriteLine("Make SQL query to insert DNS rule");
            int allowed = 0;
            if (allowedsubdomains) allowed = 1; //converting bool to int for SQL query
            string query = "INSERT INTO dnsrules (aname, subdomains) VALUES ('" + domain + "', " + Convert.ToString(allowed) + ");";
            Console2.WriteLine(query);
            using var connection1 = new MySqlConnection(constr);
            connection1.Open();
            using var command1 = new MySqlCommand(query, connection1);
            command1.ExecuteNonQuery();
            //Adding record in the lists
            domains.Add(domain);
            subdomains.Add(allowedsubdomains);
        }

        public void DeleteRule(string constr, int ind, bool updatednsrules) //Remove rule from DB
        {
            //Make SQL query to delete DNS rule;
            string aname = domains[ind];
            Console2.WriteLine("Make SQL query to delete DNS rule");
            string query = "DELETE FROM dnsrules WHERE aname='" + aname + "';";
            Console2.WriteLine(query);
            using var connection1 = new MySqlConnection(constr);
            connection1.Open();
            using var command1 = new MySqlCommand(query, connection1);
            command1.ExecuteNonQuery();
            if (updatednsrules)
            {
                //Removing record from the lists
                domains.RemoveAt(ind);
                subdomains.RemoveAt(ind);
            }
        }

    }
}
