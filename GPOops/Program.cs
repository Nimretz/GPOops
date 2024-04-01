using System;
using System.Collections.Generic;
using Newtonsoft.Json;
using System.DirectoryServices;
using System.Text.RegularExpressions;
using System.DirectoryServices.ActiveDirectory;
using System.IO;
using Formatting = Newtonsoft.Json.Formatting;
using System.IO.Compression;

namespace GPOops
{
    class Program
    {
        private static bool debugMode = false;
        private static bool folderMode = false;
        private static bool CollectServices = false;
        private static bool deletus = false;
        static void DebugLine(string message)
        {
            if (debugMode)
            {
                Console.WriteLine(message);
            }
        }
        public static List<string> gPLinksList = new List<string>();
        public static Dictionary<string, List<ServiceInfo>> clsidServices = new Dictionary<string, List<ServiceInfo>>();
        
        public static string GetGPOFromOU(string input)
        {
            string pattern = @"CN\={(.*?)}\,";

            // Create a Regex object
            Regex regex = new Regex(pattern);

            // Match the pattern against the input string
            MatchCollection matches = regex.Matches(input);
            // Print out the matched substrings
            foreach (Match match in matches)
            {
                return match.Value.ToString().Split('{')[1].Split('}')[0];
            }
            return "None";
        }
        public static void ShowList(ResultPropertyValueCollection my_list)
        {
            foreach (var my_string in my_list)
            {
                Console.WriteLine(my_string.ToString());
            }
        }
        static string ConstructUri(string clsid, string domain)
        {
            //Console.WriteLine("[*] Constructing URI");
            DebugLine("[*] Constructing URI for: "+ domain +"," +clsid);
            // Construct the URI using the provided CLSID and domain
            return @"\\" + domain + @"\sysvol\" + domain + @"\Policies\{" + clsid + "}";
            //MACHINE\Microsoft\Windows NT\SecEdit
        }
        public static bool FileExists(string filePath)
        {
            DebugLine("[*] Checking if file exists");
            return File.Exists(filePath);
        }
        public static string[] ReadFile(string filePath)
        {
            try
            {
                DebugLine("[*] Reading File " + filePath);
                string[] content = File.ReadAllLines(filePath);
                return content;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error reading file: {ex.Message}");
                return null;
            }
        }

        public static bool GptTMPLisExists(string filepath)
        {
            try
            {
                string[] text = ReadFile(filepath);
                Console.WriteLine("[+] Read this from " + filepath);
                Console.WriteLine(text);
                //TODO analize
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine("GptTMPL failed" + ex.ToString());
                return false;
            }
        }

        public static void GPTParsush(List<string> content)
        {
            string[] privileges = new string[] { "SeBackupPrivilege",
                "SeCreateTokenPrivilege",
                "SeDebugPrivilege",
                "SeEnableDelegationPrivilege",
                "SeSyncAgentPrivilege",
                "SeTakeOwnershipPrivilege",
                "SeTcbPrivilege",
                "SeTrustedCredManAccessPrivilege", };

            string[] PasswordSettings = new string[] {
                "MinimumPasswordAge",
                "MaximumPasswordAge",
                "MinimumPasswordLength",
                "PasswordComplexity",
                "PasswordHistorySize",
                "LockoutBadCount",
                "ResetLockoutCount",
                "LockoutDuration",
                "RequireLogonToChangePassword",
                "ClearTextPassword",
            };
            string[] LsaSettings = new string[] {
                @"EveryoneIncludesAnonymous",
                @"ForceGuest",
                @"LimitBlankPasswordUse",
                @"LmCompatibilityLevel",
                //@"NTLMMinClientSec",
                //@"NTLMMinServerSec",
                @"NoLMHash",
                @"RestrictAnonymous",
                @"RestrictAnonymousSAM",
            };
            foreach (string skibidy in content)
            {
                Console.WriteLine(skibidy);

            }
        }

        public static void SIDtoNAME()
        {

        }
        //public static string ServiceParse(string lineService)
        public class ServiceInfo
        {
            public string ServiceName { get; set; }
            public string ServiceStatus { get; set; }
        }

        public static ServiceInfo ServiceParse(string clsid, string lineService)
        {
            var serviceInfo = new ServiceInfo();
            string[] arrayService = lineService.Split(',');

            if (arrayService.Length > 0)
            {
                serviceInfo.ServiceName = arrayService[0].Trim('"');

            }

            if (arrayService.Length > 1)
            {
                switch (arrayService[1])
                {
                    case "2":
                        serviceInfo.ServiceStatus = "Enabled";
                        break;
                    case "3":
                        serviceInfo.ServiceStatus = "Installed";
                        break;
                    case "4":
                        serviceInfo.ServiceStatus = "Disabled";
                        break;
                    default:
                        serviceInfo.ServiceStatus = "Unknown";
                        break;
                }
                if (!clsidServices.ContainsKey(clsid))
                {
                    clsidServices[clsid] = new List<ServiceInfo>();
                }
                clsidServices[clsid].Add(serviceInfo);
            }
            DebugLine(serviceInfo.ServiceName + " is " + serviceInfo.ServiceStatus);
            return serviceInfo;
        }

        public static void GPTAnalyze(string clsid, string filepath)
        {
            string[] services = new string[] { "WebClient", "EFS", "Spool" };

            if (FileExists(filepath))
            {
                string[] content = ReadFile(filepath);
                foreach (string line in content)
                {
                    foreach (string keywordService in services)

                        if (line.Contains(keywordService))
                        {
                            //var Status = ServiceParse(line);
                            ServiceInfo serviceInfo = ServiceParse(clsid, line);
                            DebugLine(serviceInfo.ServiceName + " is " + serviceInfo.ServiceStatus);
                        }
                }
            }
        }
        public static void AccessSYSVOL(string domain,string outputPath)
        {
            // string uri =  "\\\\" + domain + "\\sysvol\\" + domain + "\\Policies";
            foreach (string CLSID in gPLinksList)
            {
                // Construct SYSVOL Location
                string uri = ConstructUri(CLSID, domain);
                DebugLine($"Processing CLSID: {CLSID}");

                // files locations
                string gptlocation = uri + "\\MACHINE\\Microsoft\\Windows NT\\SecEdit\\Gpttmpl.inf";
                string grouplocation = uri + "\\Machine\\Preferences\\Groups\\Groups.xml";
                if (folderMode)
                {
                    //string destinationDirectory = @"GPOs\{" + CLSID + "}";
                    string destinationDirectory = Path.Combine(outputPath, "GPOs", "{" + CLSID + "}");
                    CopyDirectory(uri, destinationDirectory);
                }
                else
                {
                    DebugLine("[!] FolderMode not enabled");
                }

                if (CollectServices)
                {
                    DebugLine($"Analyzing with GPTAnalyze: {gptlocation}");
                    GPTAnalyze(CLSID, gptlocation);
                    DebugLine($"Analysis complete for: {CLSID}");
                }
                else
                {
                    DebugLine("[!] CollectServices not enabled");
                }

            }



            //string servicesxml = uri + "\\MACHINE\\Preferences\\Services\\Services.xml";
            //string scheduledtasklocation = uri + "\\Machine\\Preferences\\ScheduledTasks\\ScheduledTasks.xml";
        }

        public static string GetCurrentDomainPathViaContext()
        { //Add GetDomainContext - to be able to run with alternate credentials and extract context from session (runas)
            try
            {
                DebugLine("[+] Getting current domain context");
                Domain domainName = Domain.GetCurrentDomain(); //current domain context
                Console.WriteLine("[+] Domain obtained: " + domainName?.Name);
                return domainName.Name;
            }
            catch (Exception ex)
            {
                Console.WriteLine("An error occurred on GetCurrentDomainPathViaContext: " + ex.Message);
                return ex.Message;
            }
        }

        public static string GetCurrentDomainPath4LDAP()
        {
            string ldapConnectionString;
            string defaultNamingContext = new DirectoryEntry("LDAP://RootDSE").Properties["defaultNamingContext"][0].ToString();
            if (defaultNamingContext != null || !defaultNamingContext.ToLower().Contains("workgroup"))
            {
                ldapConnectionString = "LDAP://" + defaultNamingContext;
                DebugLine("[+] Domain via Default Naming Context: " + ldapConnectionString);
                return ldapConnectionString;
            }
            else
            {
                // Prompt the user for the domain controller address
                Console.WriteLine("[!] Unable to dynamically discover the naming context. Is the computer domain joined? ");
                Console.Write("Please enter the domain FQDN (e.g., example.com): ");
                string domainFQDN = Console.ReadLine();
                // derive the DN from the FQDN
                string[] domainParts = domainFQDN.Split('.');
                string distinguishedName = string.Join(",", Array.ConvertAll(domainParts, part => $"DC={part}"));
                ldapConnectionString = $"LDAP://{distinguishedName}";
                Console.WriteLine("Using provided information: " + ldapConnectionString);
                return ldapConnectionString;
            }
        }

        public static void GetOUEnabled(string LDAPdomain)
        {
            gPLinksList.Clear(); //clear the list before populatingush
            try
            {
                DebugLine("[+] Connecting to domain: " + LDAPdomain);
                // Set up LDAP connection to Active Directory
                DirectoryEntry entry = new DirectoryEntry(LDAPdomain);
                DebugLine("[+] LDAP connection established.");
                DirectorySearcher searcher = new DirectorySearcher(entry);

                // Set up search filter to find all Group Policy Objects
                //Ensure domain gplink is also taken--todo
                searcher.Filter = "(gPLink=*CN*)";

                // Perform the search
                DebugLine("[+] Searching for Group Policy Objects...");
                SearchResultCollection results = searcher.FindAll();
                Console.WriteLine("[+] Search completed. Total results: " + results.Count);

                // Iterate through the search results
                foreach (SearchResult result in results)
                {
                    DebugLine("------- GPO ------");
                    // Retrieve the name of the OU
                    ResultPropertyValueCollection ous = result.Properties["ou"];
                    DebugLine("OUs:");
                    foreach (var ou in ous)
                    {
                        DebugLine(ou.ToString());
                    }
                    DebugLine("Linked-GPO CLSID:");
                    ResultPropertyValueCollection gPLinks = result.Properties["gPLink"]; //Need to save gPLinks into list to use later
                    foreach (var gp in gPLinks)
                    {
                        DebugLine(GetGPOFromOU(gp.ToString().ToUpper()));
                        gPLinksList.Add(GetGPOFromOU(gp.ToString().ToUpper()));
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("An error occurred on GetOUEnabled: " + ex.ToString());
            }
        }

        public static void AllGPO(string domain)
        {
            try
            {
                // Set up LDAP connection to Active Directory
                DirectoryEntry entry = new DirectoryEntry(domain);
                DirectorySearcher searcher = new DirectorySearcher(entry);

                // Set up search filter to find all Group Policy Objects
                searcher.Filter = "(objectClass=groupPolicyContainer)";

                // Perform the search
                SearchResultCollection results = searcher.FindAll();

                // Iterate through the search results
                foreach (SearchResult result in results)
                {
                    // Retrieve the name of the GPO
                    string gpoGUID = result.Properties["cn"][0].ToString();
                    string gpoName = result.Properties["displayName"][0].ToString();
                    Console.WriteLine(gpoName + ":" + gpoGUID);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("An error occurred: " + ex.Message);
            }
        }


        static void CopyDirectory(string sourceDir, string destDir)
        {
            // Get the subdirectories for the specified directory.
            string DestDirush = Path.Combine(destDir, "GPOs");
            DirectoryInfo dir = new DirectoryInfo(sourceDir);

            if (!dir.Exists)
            {
                throw new DirectoryNotFoundException("Source directory does not exist or could not be found: " + sourceDir);
            }

            DirectoryInfo[] dirs = dir.GetDirectories();
            if (!Directory.Exists(DestDirush))
            {
                Directory.CreateDirectory(DestDirush);
            }
            FileInfo[] files = dir.GetFiles();
            foreach (FileInfo file in files)
            {
                string tempPath = Path.Combine(DestDirush, file.Name);
                file.CopyTo(tempPath, true);
            }
            foreach (DirectoryInfo subdir in dirs)
            {
                string tempPath = Path.Combine(DestDirush, subdir.Name);
                CopyDirectory(subdir.FullName, tempPath);
            }
        }
        static void Zippiel(string outputPath)
        {
            try
            {
                string sourceDirectory = Path.Combine(outputPath, "GPOs");
                string zipFilePath = Path.Combine(outputPath, "GPOs.zip");

                if (File.Exists(zipFilePath))
                {
                    Console.WriteLine("[!] GPOs.zip already exists. Attempting to create a new archive.");
                    zipFilePath = Path.Combine(outputPath, "GPOs_" + DateTime.Now.ToString("yyyyMMddHHmmss") + ".zip");
                }

                ZipFile.CreateFromDirectory(sourceDirectory, zipFilePath);
                Console.WriteLine($"[!] {Path.GetFileName(zipFilePath)} archive created successfully.");
            }
            catch (Exception e)
            {
                Console.WriteLine($"[!] An error occurred while creating the ZIP archive: {e.Message}");
            }
        }

        static void DisplayHelpMessage()
        {
            Console.WriteLine("Usage: GPOops.exe [options]");
            Console.WriteLine("Options:");
            Console.WriteLine("  --help, -h, /?\tShow this help message and exit.");
            Console.WriteLine("  -debug\t\tEnable debug mode.");
            Console.WriteLine("  --services, -s\t\tCollect Services from GPO.");
            Console.WriteLine("  --folders, -f\t\tCollect entire GPO folders, will be saved under GPOs folder.");
            Console.WriteLine("  --output, -o\t\tSave output to folder.");
        }
        static void Main(string[] args)
        {

            Console.WriteLine(@"
           (   )
        (   ) (
         ) _   )
          ( \_
        _(_\ \)__
       / _  \___))
      / /     \ \
     / /       \ \
    / / ¯\_(ツ)_/¯\ \
    \ \           / /
     \_\         /_/
        \_______/
    ");

            Console.WriteLine(@"
      ▄████  ██▓███   ▒█████   ▒█████   ██▓███    ██████ 
     ██▒ ▀█▒▓██░  ██▒▒██▒  ██▒▒██▒  ██▒▓██░  ██▒▒██    ▒ 
    ▒██░▄▄▄░▓██░ ██▓▒▒██░  ██▒▒██░  ██▒▓██░ ██▓▒░ ▓██▄   
    ░▓█  ██▓▒██▄█▓▒ ▒▒██   ██░▒██   ██░▒██▄█▓▒ ▒  ▒   ██▒
    ░▒▓███▀▒▒██▒ ░  ░░ ████▓▒░░ ████▓▒░▒██▒ ░  ░▒██████▒▒
     ░▒   ▒ ▒▓▒░ ░  ░░ ▒░▒░▒░ ░ ▒░▒░▒░ ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░
      ░   ░ ░▒ ░       ░ ▒ ▒░   ░ ▒ ▒░ ░▒ ░     ░ ░▒  ░ ░
    ░ ░   ░ ░░       ░ ░ ░ ▒  ░ ░ ░ ▒  ░░       ░  ░  ░  
          ░              ░ ░      ░ ░                 ░  
                                                     
    ");
            string outputPath = "bababooei";
            for (int i = 0; i < args.Length; i++)
            {
                var arg = args[i];
                switch (arg.ToLower())
                {
                    case "--help":
                    case "-h":
                    case "/?":
                        DisplayHelpMessage();
                        return;
                    case "-debug":
                    case "-d":
                        debugMode = true;
                        Console.WriteLine("[!] Debug Mode is on");
                        break;
                    case "-output":
                    case "-o":
                        if (i + 1 < args.Length)
                        {
                            outputPath = args[++i];
                            Console.WriteLine($"[!] Output will be saved to: {outputPath}");
                        }
                        else
                        {
                            Console.WriteLine("Error: --output requires a path argument.");
                            return;
                        }
                        break;
                    case "--folders":
                    case "-f":
                        folderMode = true;
                        Console.WriteLine("[!] Folder mode activated.");
                        break;
                    case "--services":
                    case "-s":
                        CollectServices = true;
                        Console.WriteLine("[!] Service collection mode activated.");
                        break;
                }
            }

            string gpoDirectoryPath = Path.Combine(outputPath, "GPOs");
            if (!Directory.Exists(gpoDirectoryPath))
            {
                Directory.CreateDirectory(gpoDirectoryPath);
            }
            else
            {
                Console.WriteLine(gpoDirectoryPath+ " Directory Exists, will not delete");
                deletus = true;

            }

            string LDAPdomain = GetCurrentDomainPath4LDAP();
            string domain = GetCurrentDomainPathViaContext();
            GetOUEnabled(LDAPdomain);
            AccessSYSVOL(domain, outputPath);

            if (folderMode)
            {
                Zippiel(outputPath);
            }
            if (CollectServices)
            {
                string jsonOutput = JsonConvert.SerializeObject(clsidServices, Formatting.Indented);
                File.WriteAllText(Path.Combine(gpoDirectoryPath, "Services.json"), jsonOutput);
                Console.WriteLine("[*] JSON output saved to Services.json: \n" + jsonOutput);
                DebugLine("[!] JSON output saved to Services.json: \n" + jsonOutput);
            }
            if (!deletus)
            {
                Directory.Delete(gpoDirectoryPath, true);
            }
        }

        internal class CLSID
        {
        }
    }
}
