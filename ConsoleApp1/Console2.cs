using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Nameserver
{
    static public class Console2
    {
        public static bool Debugging = false;
        static public void WriteLine(string s)
        {
            if (Debugging) System.Console.WriteLine(DateTime.Now.ToString() + " - " + s);
        }
        static public void WriteLineCritical(string s)
        {
            System.Console.WriteLine(s);
        }
        static public long Benchmark(long milliseconds, int step)
        {
            long result = DateTimeOffset.Now.ToUnixTimeMilliseconds();
            WriteLine("Benchmark #" + Convert.ToString(step) + " - " + Convert.ToString(result - milliseconds) + "ms");
            return result;
        }
    }
}
