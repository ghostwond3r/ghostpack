#!/bin/bash
# by wondR & Userware
# installation: +- 3 hours
# Last update: June 30 2022
# OS: Kali Linux / version:2022.2
# ** You must run this script as ROOT **
# TURN OFF THE SCREEN SAVER !!!
ROOT_DIR=/opt
RESPONDER_DIR=/usr/share/responder/tools/
PTF_DIR=/opt/package-manager/ptf

apt-get install lolcat

lolcat <<"EOF"

    __
    ----__                               
    --------__
    -------------__
    ------------------__
    ----------------------__ 
    :'######:::'##::::'##::'#######:::'######::'########:'########:::::'###:::::'######::'##:::'##:
    '##... ##:: ##:::: ##:'##.... ##:'##... ##:... ##..:: ##.... ##:::'## ##:::'##... ##: ##::'##::
     ##:::..::: ##:::: ##: ##:::: ##: ##:::..::::: ##:::: ##:::: ##::'##:. ##:: ##:::..:: ##:'##:::
     ##::'####: #########: ##:::: ##:. ######::::: ##:::: ########::'##:::. ##: ##::::::: #####::::
     ##::: ##:: ##.... ##: ##:::: ##::..... ##:::: ##:::: ##.....::: #########: ##::::::: ##. ##:::
     ##::: ##:: ##:::: ##: ##:::: ##:'##::: ##:::: ##:::: ##:::::::: ##.... ##: ##::: ##: ##:. ##::
    . ######::: ##:::: ##:. #######::. ######::::: ##:::: ##:::::::: ##:::: ##:. ######:: ##::. ##:
    :......::::..:::::..:::.......::::......::::::..:::::..:::::::::..:::::..:::......:::..::::..::
              _                                               ___                              
             ((_          \-^-/          (((      < - - - - -()_ \      |||           '*`      
            (o o)         (o o)         (o o)             !!   | |     (o o)         (o o)     
        ooO--(_)--Ooo-ooO--(_)--Ooo-ooO--(_)--Ooo------------------ooO--(_)--Ooo-ooO--(_)--Ooo-                

\\------____-------//-------____-------\\ wondR // Userware \\----\\

EOF

current_date=$(date)
echo "Starting at $current_date"

# check if we are ROOT
if [ $EUID -ne 0 ]; then
  echo "This script must be run as root."
  exit 1
fi

# enable command aliasing
shopt -s expand_aliases

# skip prompts in apt-upgrade...
export DEBIAN_FRONTEND=noninteractive
alias apt-get='yes "" | apt-get -o Dpkg::Options::="--force-confdef" -y'
apt-get update

# fix bashrc
cp /root/.bashrc /root/.bashrc.bak
cp "/home/$(grep -F 1000:1000 /etc/passwd | cut -d: -f1)/.bashrc" /root/.bashrc
. /root/.bashrc


lolcat <<"EOF"

ADDING 🆂🅾🆄🆁🅲🅴-🅻🅸🆂🆃

EOF

echo "adding sources list.."
echo "deb http://http.kali.org/kali kali-rolling main contrib non-free" | sudo tee /etc/apt/sources.list
echo "deb-src http://http.kali.org/kali kali-rolling main contrib non-free" | sudo tee -a /etc/apt/sources.list

# upgrade distro
apt-get dist-upgrade -y
printf '\n---//---\\-----//---\\---\n\n'

printf '\n      ▌│█║▌║▌║ Installing Packages ▌│█║▌║▌║\n'
printf '\n      -------------------------------------\n\n'
dpkg --add-architecture i386
apt install -y git wget gnupg2 build-essential binutils-dev vim unzip libssl-dev autoconf automake libtool npm graphviz golang gfw bleachbit konsole xclip freerdp2-x11 powershell tor torsocks wine64 mingw-w64 binutils-mingw-w64-i686 binutils-mingw-w64-x86-64 g++-mingw-w64 g++-mingw-w64-i686 g++-mingw-w64-x86-64 gcc-mingw-w64 gcc-mingw-w64-base gcc-mingw-w64-i686 gcc-mingw-w64-x86-64 mingw-w64 mingw-w64-common mingw-w64-i686-dev mingw-w64-x86-64-dev golang rustc gcc ttf-mscorefonts-installer python3-pip python3-wheel libcompress-raw-lzma-perl python3-venv fpc gdc ldc ca-certificates lsb-release gem software-properties-common debian-keyring cargo geany gdebi gufw bleachbit iptables tmux libffi-dev docker.io aptitude libunwind-dev awscli doona dotdotpwn linux-exploit-suggester oscanner siparmyknife xsser knockpy urlextractor pompem dirsearch python3-xlrd python-xlrd-docs
printf '\n---//---\\-----//---\\---\n\n'


printf '\n-----------------------------------------------------\n'
printf '\nCreating Directory in /opt:\n'
printf '\n                     - data (wordlist && dic\n'
printf '\n                     - utils (local management)\n'
printf '\n                     - tools (with sub-category)\n'
printf '\n                     - work (personal folder)\n'
printf '\n-----------------------------------------------------\n\n'
cd $ROOT_DIR
mkdir {data,utils,tools,work}

echo "Downloading..."
cd $ROOT_DIR/utils
git clone https://github.com/Arr0way/linux-local-enumeration-script.git
git clone https://github.com/CISOfy/lynis.git
printf '\n---//---\\-----//---\\---\n\n'


printf '\n      ▌│█║▌║▌║ Installing PTF ▌│█║▌║▌║\n'
printf '\n      --------------------------------\n\n'
git clone https://github.com/trustedsec/ptf/ /opt/package-manager/ptf
printf '\n---//---\\-----//---\\---\n\n'


printf '\n      ▌│█║▌║▌║ Installing Python3 ▌│█║▌║▌║\n'
printf '\n      ------------------------------------\n\n'
apt-get -y install python3-venv 
python3 -m pip install pipenv
pip3 install pyReadline habu getips virtualenvwrapper uncompyle6 git-filter-repo python-whois colorama bs4 virtualenv wheel boto3 botocore termcolor requests pycryptodome
printf '\n---//---\\-----//---\\---\n\n'
 

printf '\n      ▌│█║▌║▌║ Information Gathering ▌│█║▌║▌║\n'
printf '\n      ---------------------------------------\n\n'
apt autoremove -y dmitry
apt install -y ike-scan legion maltego netdiscover nmap p0f recon-ng spiderfoot dnsenum dnsmap dnsrecon dnstracer dnswalk fierce urlcrazy firewalk lbd wafw00f arping fping hping3 masscan zmap ncat thc-ipv6 unicornscan theharvester netmask enum4linux polenum nbtscan nbtscan-unixwiz smbmap smtp-user-enum swaks braa onesixtyone snmp ssldump sslh sslscan sslyze fragrouter ftester arp-scan t50 ipv6-toolkit
printf '\n---//---\\-----//---\\---\n\n'


printf '\n      ▌│█║▌║▌║ Vulnerability Analysis ▌│█║▌║▌║\n'
printf '\n      ----------------------------------------\n\n'
apt install -y lynis nikto unix-privesc-check linux-exploit-suggester windows-privesc-check yersinia bed sfuzz siparmyknife spike iaxflood inviteflood siege thc-ssl-dos rtpbreak rtpflood rtpinsertsound sctpscan sipp sipsak sipvicious cisco-auditing-tool cisco-global-exploiter cisco-ocs cisco-torch copy-router-config perl-cisco-copyconfig
printf '\n---//---\\-----//---\\---\n\n'


printf '\n      ▌│█║▌║▌║ Web Application Analysis ▌│█║▌║▌║\n'
printf '\n      ------------------------------------------\n\n'
apt install -y burpsuite commix skipfish sqlmap wpscan zaproxy cutycapt dirb dirbuster wfuzz ffuf cadaver davtest wapiti whatweb xsser dotdotpwn sublist3r gobuster apache-users hurl jboss-autopwn jsql jsql-injection
printf '\n---//---\\-----//---\\---\n\n'


printf '\n      ▌│█║▌║▌║ Database Assessment ▌│█║▌║▌║\n'
printf '\n      -------------------------------------\n\n'
apt install -y oscanner sidguesser sqlitebrowser sqsh
printf '\n---//---\\-----//---\\---\n\n'


printf '\n      ▌│█║▌║▌║ Password Attacks ▌│█║▌║▌║\n'
printf '\n      ----------------------------------\n\n'
apt install -y cewl crunch hashcat john medusa ophcrack wordlists seclists chntpw crackle fcrackzip hashid hash-identifier samdump2 hydra patator thc-pptp-bruter mimikatz passing-the-hash rsmangler pdfcrack

cd $ROOT_DIR/data
git clone https://github.com/fuzzdb-project/fuzzdb.git
git clone https://github.com/danielmiessler/SecLists.git
git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git
git clone https://github.com/1N3/IntruderPayloads
cd $ROOT_DIR
printf '\n---//---\\-----//---\\---\n\n'


printf '\n      ▌│█║▌║▌║ Wireless Attacks ▌│█║▌║▌║\n'
printf '\n      ----------------------------------\n\n'
apt install -y aircrack-ng chirp cowpatty fern-wifi-cracker kismet mfoc mfterm pixiewps reaver wifite bully wifi-honey bluelog btscanner redfang spooftooph ubertooth ubertooth-firmware gnuradio gqrx-sdr rfcat rfdump rtlsdr-scanner
printf '\n---//---\\-----//---\\---\n\n'


printf '\n      ▌│█║▌║▌║ Reverse Engineering ▌│█║▌║▌║\n'
printf '\n      -------------------------------------\n\n'
apt install -y apktool bytecode-viewer clang dex2jar edb-debugger javasnoop ollydbg radare2 radare2-cutter
printf '\n---//---\\-----//---\\---\n\n'


printf '\n      ▌│█║▌║▌║ Exploitation Tools ▌│█║▌║▌║\n'
printf '\n      ------------------------------------\n\n'
apt install -y metasploit-framework powershell-empire msfpc exploitdb shellnoob termineter beef-xss merlin-agent merlin-server koadic kerberoast routersploit payloadsallthethings upx-ucl
printf '\n---//---\\-----//---\\---\n\n'


printf '\n      ▌│█║▌║▌║ Sniffing & Spoofing ▌│█║▌║▌║\n'
printf '\n      -------------------------------------\n\n'
apt install -y bettercap bettercap-caplets bettercap-ui ettercap-common ettercap-graphical macchanger mitmproxy netsniff-ng responder wireshark dnschef hexinject tcpflow isr-evilgrade fiked rebind sslsplit tcpreplay
printf '\n---//---\\-----//---\\---\n\n'


printf '\n      ▌│█║▌║▌║ Multirelay ▌│█║▌║▌║\n'
printf '\n      ----------------------------\n\n'
cd $RESPONDER_DIR
apt install -y gcc-mingw-w64-x86-64 && \
sudo x86_64-w64-mingw32-gcc ./MultiRelay/bin/Runas.c -o ./MultiRelay/bin/Runas.exe -municode -lwtsapi32 -luserenv && \
sudo x86_64-w64-mingw32-gcc ./MultiRelay/bin/Syssvc.c -o ./MultiRelay/bin/Syssvc.exe -municode
cd $ROOT_DIR
printf '\n---//---\\-----//---\\---\n\n'


printf '\n      ▌│█║▌║▌║ Post Exploitation ▌│█║▌║▌║\n'
printf '\n      -----------------------------------\n\n'
apt install -y exe2hexbat powersploit nishang proxychains4 privoxy shellter veil weevely unicorn-magic dbd sbd dns2tcp iodine miredo proxytunnel ptunnel-ng pwnat stunnel4 udptunnel 6tunnel httptunnel chisel laudanum powercat ncat-w32 cryptcat dnscat2 winexe windows-binaries secure-socket-funneling-windows-binaries crackmapexec rlwrap putty-tools pwncat sshuttle
printf '\n---//---\\-----//---\\---\n\n'


printf '\n      ▌│█║▌║▌║ Installing tools ▌│█║▌║▌║\n'
printf '\n      ----------------------------------\n\n'
git clone https://github.com/GreatSCT/GreatSCT.git /opt/av-bypass/GreatSct/ && \
git clone https://github.com/mdsecactivebreach/SharpShooter.git /opt/av-bypass/SharpShooter/
git clone https://github.com/84KaliPleXon3/GitHackTools-TorghostNG /opt/anonymity/TorghostNG/
git clone https://github.com/Kevin-Robertson/Inveigh /opt/exploitation/Inveigh/ && \
git clone https://github.com/bettercap/bettercap.git /opt/exploitation/bettercap && \
git clone https://github.com/ropnop/kerbrute /opt/exploitation/kerbrute/
git clone https://github.com/carlospolop/PEASS-ng /opt/intelligence-gathering/PEASS-ng/ && \
git clone https://github.com/jondonas/linux-exploit-suggester-2.git /opt/intelligence-gathering/linux-exploit-suggester-2/ && \
git clone https://github.com/rebootuser/LinEnum.git /opt/intelligence-gathering/LinEnum/ && \
git clone https://github.com/diego-treitos/linux-smart-enumeration.git /opt/intelligence-gathering/linux-smart-enumeration && \
git clone https://github.com/linted/linuxprivchecker.git /opt/intelligence-gathering/linuxprivchecker && \
git clone https://github.com/mostaphabahadou/postenum.git /opt/intelligence-gathering/postenum/ && \
git clone https://github.com/bitsadmin/wesng /opt/intelligence-gathering/wesng/ && \
git clone https://github.com/GhostPack/SharpUp /opt/intelligence-gathering/SharpUp/ && \
git clone https://github.com/GhostPack/Seatbelt /opt/intelligence-gathering/Seatbelt/
git clone --recurse-submodules https://github.com/cobbr/Covenant /opt/post-exploitation/Covenant && \
git clone https://github.com/n1nj4sec/pupy/ /opt/post-exploitation/pupy/ && \
git clone https://github.com/SafeBreach-Labs/SirepRAT /opt/post-exploitation/SirepRAT/
git clone https://github.com/nil0x42/phpsploit /opt/webshells/phpsploit/
git clone https://github.com/gchq/CyberChef.git /opt/reversing/CyberChef/
git clone https://github.com/sundowndev/covermyass.git /opt/anti-forensics/covermyass/
git clone https://github.com/leostat/rtfm /opt/miscellaneous/rtfm/
printf '\n---//---\\-----//---\\---\n\n'


printf '\n      ▌│█║▌║▌║ Installing pwncat ▌│█║▌║▌║\n'
printf '\n      -----------------------------------\n\n'
python3 -m venv /opt/pwncat
/opt/pwncat/bin/pip install 'git+https://github.com/calebstewart/pwncat'
ln -s /opt/pwncat/bin/pwncat /usr/local/bin
git clone https://github.com/calebstewart/pwncat.git /opt/post-exploitation/pwncat/ 
printf '\n---//---\\-----//---\\---\n\n'


printf '\n      ▌│█║▌║▌║ Forensics ▌│█║▌║▌║\n'
printf '\n      ---------------------------\n\n'
apt install -y autopsy binwalk bulk-extractor chkrootkit foremost hashdeep rkhunter yara extundelete magicrescue recoverjpeg safecopy scalpel scrounge-ntfs guymager pdfid pdf-parser python3-pdfminer
printf '\n---//---\\-----//---\\---\n\n'


printf '\n      ▌│█║▌║▌║ Anti-Forensics ▌│█║▌║▌║\n'
printf '\n      --------------------------------\n\n'
apt install -y mat2 wipe
printf '\n---//---\\-----//---\\---\n\n'


printf '\n      ▌│█║▌║▌║ Reporting Tools ▌│█║▌║▌║\n'
printf '\n      ---------------------------------\n\n'
apt install -y dradis eyewitness faraday pipal metagoofil
printf '\n---//---\\-----//---\\---\n\n'


printf '\n      ▌│█║▌║▌║ Social Engineering Tools ▌│█║▌║▌║\n'
printf '\n      ------------------------------------------\n\n'
apt install -y set king-phisher wifiphisher
printf '\n---//---\\-----//---\\---\n\n'


printf '\n      ▌│█║▌║▌║ PTF ▌│█║▌║▌║\n'
printf '\n      ---------------------\n\n'
cd $PTF_DIR
./ptf <<EOF
use modules/pivoting/3proxy
run
use modules/pivoting/meterssh
run
use modules/pivoting/pivoter
run
use modules/pivoting/rpivot
run
use modules/av-bypass/pyobfuscate
run
use modules/exploitation/fido
run
use modules/exploitation/fuxploider
run
use modules/exploitation/impacket
run
use modules/exploitation/inception
run
use modules/exploitation/kerberoast
run
use modules/exploitation/mitm6
run
use modules/exploitation/pwntools
run
use modules/webshells/b374k
run
use modules/webshells/blackarch
run
use modules/webshells/wso
run
use modules/intelligence-gathering/amass
run
use modules/intelligence-gathering/autorecon
run
use modules/intelligence-gathering/awsbucket
run
use modules/intelligence-gathering/massdns
run
use modules/intelligence-gathering/windows-exploit-suggester
run
use modules/password-recovery/statistically-likely-usernames
run
use modules/post-exploitation/donut
run
use modules/post-exploitation/evilwinrm
run
use modules/vulnerability-analysis/golismero
run
use modules/powershell/obfuscation
run
use modules/powershell/powersccm
run
EOF
cd $ROOT_DIR
printf '\n---//---\\-----//---\\---\n\n'


printf '\n      ▌│█║▌║▌║ Putty binaries ▌│█║▌║▌║\n'
printf '\n      --------------------------------\n\n'
mkdir /opt/Putty/ && \
wget https://the.earth.li/~sgtatham/putty/latest/w64/putty.zip -O /opt/Putty/putty64.zip && \
wget https://the.earth.li/~sgtatham/putty/latest/w32/putty.zip -O /opt/Putty/putty32.zip && \
wget https://the.earth.li/~sgtatham/putty/latest/wa64/putty.zip -O /opt/Putty/puttywa64.zip && \
wget https://the.earth.li/~sgtatham/putty/latest/wa32/putty.zip -O /opt/Putty/puttywa32.zip && \
unzip /opt/Putty/putty32.zip -d /opt/Putty/x64/ && \
unzip /opt/Putty/putty64.zip -d /opt/Putty/x86/ && \
unzip /opt/Putty/puttywa32.zip -d /opt/Putty/ARM-32 && \
unzip /opt/Putty/puttywa64.zip -d /opt/Putty/ARM-64
printf '\n---//---\\-----//---\\---\n\n'


printf '\n      ▌│█║▌║▌║ Windows Sysinternals Suite ▌│█║▌║▌║\n'
printf '\n      --------------------------------------------\n\n'
mkdir /opt/SysinternalsSuite/ && \
wget https://download.sysinternals.com/files/SysinternalsSuite.zip -O /opt/SysinternalsSuite/SysinternalsSuite.zip && \
wget https://download.sysinternals.com/files/SysinternalsSuite-Nano.zip -O /opt/SysinternalsSuite/SysinternalsSuite-Nano.zip && \
wget https://download.sysinternals.com/files/SysinternalsSuite-ARM64.zip -O /opt/SysinternalsSuite/SysinternalsSuite-ARM64.zip && \
wget https://eternallybored.org/misc/netcat/netcat-win32-1.12.zip -O /usr/share/windows-resources/binaries/netcat-win32-1.12.zip && \
unzip /opt/SysinternalsSuite/SysinternalsSuite.zip -d /opt/SysinternalsSuite/x64_x86 && \
unzip /opt/SysinternalsSuite/SysinternalsSuite-Nano.zip -d /opt/SysinternalsSuite/NANO/ && \
unzip /opt/SysinternalsSuite/SysinternalsSuite-ARM64.zip -d /opt/SysinternalsSuite/ARM-64/ && \
unzip /usr/share/windows-resources/binaries/netcat-win32-1.12.zip -d /usr/share/windows-resources/binaries/nc/
printf '\n---//---\\-----//---\\---\n\n'


printf '\n      ▌│█║▌║▌║ Install Rustscan ▌│█║▌║▌║\n'
printf '\n      ----------------------------------\n\n'
cargo install rustscan
printf '\n---//---\\-----//---\\---\n\n'


printf '\n-----------------------------------------------------\n'
printf '\nCreating Directory in /opt/tools:\n'
printf '\n                     - bruteforce\n'
printf '\n                     - dorkfuzz\n'
printf '\n                     - recon\n'
printf '\n                     - SE\n'
printf '\n                     - Ddos\n'
printf '\n                     - shells\n'
printf '\n                     - web\n'
printf '\n                     - windows\n'
printf '\n-----------------------------------------------------\n\n'
cd $ROOT_DIR/tools
mkdir {bruteforce,windows,SE,recon,web,dorkfuzz,Ddos,shells}

echo "Installing tools..."

pushd bruteforce 
git clone https://github.com/NeverWonderLand/d00r.git
git clone https://github.com/lanjelot/patator.git
git clone https://github.com/galkan/crowbar.git
git clone https://github.com/vanhauser-thc/thc-hydra.git
cd thc-hydra
  ./configure
  make
  make install
cd ..
popd 
printf '\n---//---\\-----//---\\---\n\n'


pushd dorkfuzz 
git clone https://github.com/s0md3v/Photon.git
git clone https://github.com/FrancescoDiSalesGithub/dorker
git clone https://github.com/tomato42/tlsfuzzer.git
git clone https://github.com/GerbenJavado/LinkFinder.git
popd 
printf '\n---//---\\-----//---\\---\n\n'


pushd recon 
git clone https://github.com/AlisamTechnology/ATSCAN.git
git clone https://github.com/projectdiscovery/nuclei.git
git clone https://github.com/projectdiscovery/nuclei-templates.git
git clone https://github.com/tahmed11/DeepScan.git
git clone https://github.com/machine1337/fast-scan.git
git clone https://github.com/FortyNorthSecurity/EyeWitness.git
git clone https://github.com/smicallef/spiderfoot.git
git clone https://github.com/michenriksen/aquatone.git
git clone https://github.com/kakawome/Lethe.git
git clone https://github.com/leebaird/discover.git
git clone https://github.com/evyatarmeged/Raccoon.git 
git clone https://github.com/rbsec/sslscan.git
git clone https://github.com/drwetter/testssl.sh.git
git clone https://github.com/Ha3MrX/Hacking.git
popd 
printf '\n---//---\\-----//---\\---\n\n'


pushd SE 
git clone https://github.com/BullsEye0/ghost_eye.git
git clone https://github.com/trustedsec/social-engineer-toolkit.git
git clone https://github.com/Ignitetch/AdvPhishing.git
git clone https://github.com/sherlock-project/sherlock.git
git clone https://github.com/Anish-M-code/URL-obfuscator.git 
git clone https://github.com/BLINKING-IDIOT/Aliens_eye
popd 
printf '\n---//---\\-----//---\\---\n\n'


pushd Ddos 
git clone https://github.com/NeverWonderLand/Impulse.git
git clone https://github.com/7zx/overload.git
git clone https://github.com/H1R0GH057/Anonymous.git
git clone https://github.com/firstapostle/Blood
git clone https://github.com/UBISOFT-1/AnonymousPAK-DDoS
popd 
printf '\n---//---\\-----//---\\---\n\n'


pushd shells 
git clone https://github.com/machine1337/mafiahacks.git
git clone https://github.com/BlackArch/webshells.git
git clone https://github.com/t0thkr1s/revshellgen.git
popd 
printf '\n---//---\\-----//---\\---\n\n'


pushd web 
git clone https://github.com/commixproject/commix.git
git clone https://github.com/droope/droopescan.git
git clone https://github.com/beefproject/beef/
cd beef 
yes | ./install
cd ..
git clone https://github.com/mitmproxy/mitmproxy.git
git clone https://github.com/sqlmapproject/sqlmap.git
git clone https://github.com/wpscanteam/wpscan.git
git clone https://github.com/OJ/gobuster.git
git clone https://github.com/OWASP/Amass.git
git clone https://github.com/arthaud/git-dumper.git
git clone https://github.com/bambish/ScanQLi.git
git clone https://github.com/projectdiscovery/httpx
git clone https://github.com/EnableSecurity/wafw00f
git clone https://github.com/Tuhinshubhra/CMSeeK
git clone https://github.com/ffuf/ffuf
git clone https://github.com/jaeles-project/gospider
git clone https://github.com/lc/gau
git clone https://github.com/tomnomnom/waybackurls
popd 
printf '\n---//---\\-----//---\\---\n\n'


pushd windows 
git clone https://github.com/lgandx/Responder.git
git clone https://github.com/PowerShellMafia/PowerSploit.git
git clone https://github.com/samratashok/nishang.git
popd 
printf '\n---//---\\-----//---\\---\n\n'


echo "Updating.."
apt-get update -y


printf '\n      ▌│█║▌║▌║ Installing gem.. ▌│█║▌║▌║\n'
printf '\n      ----------------------------------\n\n'
gem install bundler && bundle config set --locale without test
gem install rubygems-update
apt full-upgrade
gem install wpscan
printf '\n---//---\\-----//---\\---\n\n'
 

printf '\n      ▌│█║▌║▌║ Docker ▌│█║▌║▌║\n'
printf '\n      ------------------------\n\n'
# enable and start docker
systemctl stop docker &>/dev/null
echo '{"bip":"172.16.199.1/24"}' >/etc/docker/daemon.json
systemctl enable docker --now
printf '\n---//---\\-----//---\\---\n\n'


printf '\n Installation of Metasploit-framework \n'
printf '\n------------------------------------------------------------------\n\n'

curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb >msfinstall &&
    chmod 755 msfinstall &&
    ./msfinstall

# to avoide issue with apt-key 
echo 'deb http://apt.metasploit.com/ lucid main' > /etc/apt/sources.list.d/metasploit-framework.list
wget -nc http://apt.metasploit.com/metasploit-framework.gpg.key
cat metasploit-framework.gpg.key | gpg --dearmor  > metasploit-framework.gpg
install -o root -g root -m 644 metasploit-framework.gpg /etc/apt/trusted.gpg.d/
apt-get update

# Initializing Metasploit Database
systemctl start postgresql
systemctl enable postgresql
msfdb init

printf '\n---//---\\-----//---\\---\n\n'


# starting service
service postgresql start
service tor start
service mysql start
/etc/init.d/apache2 start
echo "
Starting services.. 
======================
-PostgreSQL
-Tor
-Apache
-Mysql
...
"

printf '\n---//---\\-----//---\\---\n\n'

printf '\n▌│█║▌║▌║ Installing Armitage ▌│█║▌║▌║\n'
printf '\n-------------------------------------\n\n'

git clone https://github.com/r00t0v3rr1d3/armitage.git /opt/armitage
cd /opt/armitage
chmod +x package.sh
./package.sh
cd



printf '\n▌│█║▌║▌║ Configuration of GO ▌│█║▌║▌║\n'
printf '\n-------------------------------------\n\n'
cd $ROOT_DIR/
wget -q -O - https://raw.githubusercontent.com/canha/golang-tools-install-script/master/goinstall.sh | bash

printf '\n---//---\\-----//---\\---\n\n'

# -------------------------------------------------------
# Settings
# -------------------------------------------------------

echo "Updating..."
apt-get update
apt-get upgrade

printf '\n---//---\\-----//---\\---\n\n'
 

# default tmux config
cat <<EOF >$HOME/.tmux.conf
    set -g mouse on
    set -g history-limit 50000
    set -g prefix2 C-a
    bind C-a send-prefix 
    unbind C-b
    set-window-option -g mode-keys vi

    run-shell /opt/tmux-logging/logging.tmux

    # List of plugins
    set -g @plugin 'tmux-plugins/tmux-logging'

    # Initialize TMUX plugin manager (keep this line at the very bottom of tmux.conf)
    run '~/.tmux/plugins/tpm/tpm'
EOF

# =======================================================

#Cloudflare DNS
echo -e "\n2.\tSetting up Cloudflare DNS...\n"
sudo echo -e "nnameserver 1.1.1.1\nnameserver 1.0.0.1" > /etc/resolv.conf

printf '\n---//---\\-----//---\\---\n\n'



printf '\n[+] Enabling bash session logging\n\n'

grep -q 'UNDER_SCRIPT' ~/.bashrc || echo "if [[ -z "$UNDER_SCRIPT" && -z "$TMUX" && ! -z "$PS1" ]]; then
    logdir=$HOME/Logs 
    if [ ! -d $logdir ]; then
            mkdir $logdir
    fi
    #gzip -q $logdir/*.log &>/dev/null
    logfile=$logdir/$(date +%F_%H_%M_%S).$$.log
    export UNDER_SCRIPT=$logfile
    script -f -q $logfile
    exit
fi" >>~/.bashrc

printf '\n---//---\\-----//---\\---\n\n' 

echo "Finalizing..."

echo "Cleaning Up..."
apt-get autoremove -y
apt-get autoclean -y
updatedb


#--------------------------------------------------

# ENVIRONMENT VARIABLES
PROMPT_CHAR=$(if [ "$(whoami)" == "root" ]; then echo "#"; else echo "$"; fi)
HOST_COLOR=$(if [ "$(whoami)" == "root" ]; then echo "6"; else echo "1"; fi)
export PS1="\[\e[0;3${HOST_COLOR}m\]\H\[\e[0;37m\]|\[\e[0;32m\]\A\[\e[0;37m\]|\[\e[0;33m\]\w\[\e[0;3${HOST_COLOR}m\] ${PROMPT_CHAR} \[\e[1;0m\]"
export PATH="$PATH:$HOME/.cargo/bin"
export DOTNET_CLI_TELEMETRY_OPTOUT=1
export MSF_DATABASE_CONFIG=~/.msf4/database.yml

# =======================================================

# OTHER TWEAKS & HACKS
export HISTCONTROL=ignoredups:erasedups # no duplicate entries
export HISTSIZE=100000                  # big big history
export HISTFILESIZE=100000              # big big history
shopt -s histappend                     # append to history, don't overwrite it
# Save and reload the history after each command finishes
export PROMPT_COMMAND="history -a; history -c; history -r; $PROMPT_COMMAND"

# =======================================================

lolcat <<"EOF"


        GGGGGGGGGGGGGHHHHHHHHH     HHHHHHHHH     OOOOOOOOO        SSSSSSSSSSSSSSS TTTTTTTTTTTTTTTTTTTTTTT    
     GGG::::::::::::GH:::::::H     H:::::::H   OO:::::::::OO    SS:::::::::::::::ST:::::::::::::::::::::T    
   GG:::::::::::::::GH:::::::H     H:::::::H OO:::::::::::::OO S:::::SSSSSS::::::ST:::::::::::::::::::::T    
  G:::::GGGGGGGG::::GHH::::::H     H::::::HHO:::::::OOO:::::::OS:::::S     SSSSSSST:::::TT:::::::TT:::::T    
 G:::::G       GGGGGG  H:::::H     H:::::H  O::::::O   O::::::OS:::::S            TTTTTT  T:::::T  TTTTTT    
G:::::G                H:::::H     H:::::H  O:::::O     O:::::OS:::::S                    T:::::T            
G:::::G                H::::::HHHHH::::::H  O:::::O     O:::::O S::::SSSS                 T:::::T            
G:::::G    GGGGGGGGGG  H:::::::::::::::::H  O:::::O     O:::::O  SS::::::SSSSS            T:::::T            
G:::::G    G::::::::G  H:::::::::::::::::H  O:::::O     O:::::O    SSS::::::::SS          T:::::T            
G:::::G    GGGGG::::G  H::::::HHHHH::::::H  O:::::O     O:::::O       SSSSSS::::S         T:::::T            
G:::::G        G::::G  H:::::H     H:::::H  O:::::O     O:::::O            S:::::S        T:::::T            
 G:::::G       G::::G  H:::::H     H:::::H  O::::::O   O::::::O            S:::::S        T:::::T            
  G:::::GGGGGGGG::::GHH::::::H     H::::::HHO:::::::OOO:::::::OSSSSSSS     S:::::S      TT:::::::TT          
   GG:::::::::::::::GH:::::::H     H:::::::H OO:::::::::::::OO S::::::SSSSSS:::::S      T:::::::::T          
     GGG::::::GGG:::GH:::::::H     H:::::::H   OO:::::::::OO   S:::::::::::::::SS       T:::::::::T          
        GGGGGG   GGGGHHHHHHHHH     HHHHHHHHH     OOOOOOOOO      SSSSSSSSSSSSSSS         TTTTTTTTTTT          
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         
     SSSSSSSSSSSSSSS EEEEEEEEEEEEEEEEEEEEEE       CCCCCCCCCCCCC      
   SS:::::::::::::::SE::::::::::::::::::::E    CCC::::::::::::C      
  S:::::SSSSSS::::::SE::::::::::::::::::::E  CC:::::::::::::::C      
  S:::::S     SSSSSSSEE::::::EEEEEEEEE::::E C:::::CCCCCCCC::::C      
  S:::::S              E:::::E       EEEEEEC:::::C       CCCCCC      
  S:::::S              E:::::E            C:::::C                    
   S::::SSSS           E::::::EEEEEEEEEE  C:::::C                    
    SS::::::SSSSS      E:::::::::::::::E  C:::::C                    
      SSS::::::::SS    E:::::::::::::::E  C:::::C                    
         SSSSSS::::S   E::::::EEEEEEEEEE  C:::::C                    
              S:::::S  E:::::E            C:::::C                    
              S:::::S  E:::::E       EEEEEEC:::::C       CCCCCC      
  SSSSSSS     S:::::SEE::::::EEEEEEEE:::::E C:::::CCCCCCCC::::C      
  S::::::SSSSSS:::::SE::::::::::::::::::::E  CC:::::::::::::::C      
  S:::::::::::::::SS E::::::::::::::::::::E    CCC::::::::::::C      
   SSSSSSSSSSSSSSS   EEEEEEEEEEEEEEEEEEEEEE       CCCCCCCCCCCCC                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   
                                                                                                                                                                                                                                                                                                                                             
 MMMMMMMM               MMMMMMMM               AAA               FFFFFFFFFFFFFFFFFFFFFFIIIIIIIIII               AAA               
 M:::::::M             M:::::::M              A:::A              F::::::::::::::::::::FI::::::::I              A:::A              
 M::::::::M           M::::::::M             A:::::A             F::::::::::::::::::::FI::::::::I             A:::::A             
 M:::::::::M         M:::::::::M            A:::::::A            FF::::::FFFFFFFFF::::FII::::::II            A:::::::A            
 M::::::::::M       M::::::::::M           A:::::::::A             F:::::F       FFFFFF  I::::I             A:::::::::A           
 M:::::::::::M     M:::::::::::M          A:::::A:::::A            F:::::F               I::::I            A:::::A:::::A          
 M:::::::M::::M   M::::M:::::::M         A:::::A A:::::A           F::::::FFFFFFFFFF     I::::I           A:::::A A:::::A         
 M::::::M M::::M M::::M M::::::M        A:::::A   A:::::A          F:::::::::::::::F     I::::I          A:::::A   A:::::A        
 M::::::M  M::::M::::M  M::::::M       A:::::A     A:::::A         F:::::::::::::::F     I::::I         A:::::A     A:::::A       
 M::::::M   M:::::::M   M::::::M      A:::::AAAAAAAAA:::::A        F::::::FFFFFFFFFF     I::::I        A:::::AAAAAAAAA:::::A      
 M::::::M    M:::::M    M::::::M     A:::::::::::::::::::::A       F:::::F               I::::I       A:::::::::::::::::::::A     
 M::::::M     MMMMM     M::::::M    A:::::AAAAAAAAAAAAA:::::A      F:::::F               I::::I      A:::::AAAAAAAAAAAAA:::::A    
 M::::::M               M::::::M   A:::::A             A:::::A   FF:::::::FF           II::::::II   A:::::A             A:::::A   
 M::::::M               M::::::M  A:::::A               A:::::A  F::::::::FF           I::::::::I  A:::::A               A:::::A  
 M::::::M               M::::::M A:::::A                 A:::::A F::::::::FF           I::::::::I A:::::A                 A:::::A 
 MMMMMMMM               MMMMMMMMAAAAAAA                   AAAAAAAFFFFFFFFFFF           IIIIIIIIIIAAAAAAA                   AAAAAAA                                                                                                                                                                                                                                                                                                                                    




Now you need to complete manualy few step...

# For you do not need to remember to run msfupdate all the time, 
# metasploit will update at 1am every day and you can focus on using the tool. 
# Keeping it simple as always, run:
crontab -e
# Using your preferred editor, add the following line, replace $name with your username:
`0 1 * * * /home/$name/apps/metasploit-framework/msfupdate > /dev/null 2>&amp;1`


# pwncat installation:
cd /opt/post-exploitation/pwncat/
python3 -m venv pwncat-env
source pwncat-env/bin/activate
pip install pwncat-cs


# Armitage
# Configure the database location for Armitage (append this in .bashrc file)
sudo msfdb init
sudo nano /etc/postgresql/14/main/pg_hba.conf
# on the line 97 (IPV4 local connections) : switch “scram-sha-256” to “trust”
# Then:
sudo systemctl enable postgresql
sudo systemctl start postgresql


# gufw
gufw enable


# Setup iptables
# these are the minimum need;
iptables -L -v
iptables -L
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp --dport ssh -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables-save 

EOF

sed -i -r "s:~/:$ROOT_DIR/:" $ROOT_DIR/.bashrc
