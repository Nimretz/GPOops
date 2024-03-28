Usage: GPOops.exe [options]

Options:
  --help, -h, /?        Show this help message and exit.
  
  --debug, -d           Enable debug mode.
  
  --services, -s        Collect Services from GPO.
  
  --folders, -f         Collect entire GPO folders, will be saved under GPOs folder.
  
  --privileges, -p              Collect interesting privileges and settings from GPO.
  
  --output, -o          Save output to folder.

Take the Services.json output file
and run:
Loadiel.py Services.json
  

Functionality:
1. Get current domain context(domain-joined machine or user input)
2. LDAP query to extract LINKED GPOs by parsing CLSIDs from GpLink attribute (on OUs and Domain). Save linked CLSIDs to global list.
4. Construct "\\domain\sysvol\domain\Policies\{clsid}" url and access via SYSVOL.
5. --folders : copy full content of "\\domain\sysvol\domain\Policies\{clsid}" and subdirectories.
6. --services : OpenFile "\MACHINE\Microsoft\Windows NT\SecEdit\Gpttmpl.inf", parse for [Service General Setting] - return interesting services status and export to "Services.json" to load into bloodhound via Loadiel.py


TODOS:
1. GPTAnalyze - finish the collection and parse of privilegs and LsaSettings. Add PasswordSettings. (should be combined with --services, to avoid opening the gpttmpl.inf)
3. groups.xml analyze
4. Loadiel.py - add privileges/lsasettings/password settings in bloodhound? in GPO attribute as well.
