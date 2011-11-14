#!/usr/bin/python
import socket, sys, smtplib, json, thread, time, os, logging, signal
from subprocess import Popen, PIPE

try:
    from googlevoice import Voice
except:
    # if need be, change this to the location 
    # of your googlevoice module!
    sys.path.append("/opt/googlevoice/")
    from googlevoice import Voice

#######################################################################
# This is completely optional, otherwise it will create a more secure #
# configuration file in /root (or your home if running under sudo!)   #
#######################################################################

# Username and password for gmail account
# usr       = 'derp@gmail.com'
usr         = None
# pwd       = 'thisismypassword'
pwd         = None

# Cell phone and email for alerts (and to accept commands from)
# cell      = '1234567890'
cell        = None
# email     = 'derp@derp.com'
email       = None

# Ping length to listen for
# magicping = 1
magicping   = None

# Tuple of ports
#ports      = ('22','80')
ports       = None

# Timeout for checking text messages
#timeout    = 30
timeout     = None

#############
# Functions #
#############

# Test for None variables 
def testconfig():
    if pwd is None:
        home = os.environ['HOME']
        if not os.path.exists(home + '/.pyknock.cfg'):
            logging.info('Config file not found!')
            makeconfig(home)
            readconfig()
        else:
            readconfig()
    else:
        logging.info('Config is in-line')

# Create a new config file 
def makeconfig(home):
    import ConfigParser, getpass
    logging.info('Creating new config file')
    config = ConfigParser.ConfigParser()
    cfg = open(home + '/.pyknock.cfg', 'w')

    logging.info('Creating new config file')
    user    = raw_input("Username? (username@gmail.com) => ")
    passwd  = getpass.getpass("Password? [Will not be echoed] => ")
    cell    = raw_input("Cell number? (1112223456)      => ")
    email   = raw_input("Alert email? (blah@blah.com)   => ")
    magic   = raw_input("Magic ping length? (1-4190)    => ")
    ports   = raw_input("Ports to unlock? (80,22,443)   => ")
    timeout = raw_input("Timeout for sms check? (secs)  => ")

    config.add_section('Thresholds')
    config.set('Thresholds','Packet',magic)
    config.set('Thresholds','Ports',ports)
    config.set('Thresholds','Timeout',timeout)
    
    config.add_section('Alerts')
    config.set('Alerts','Cell',cell)
    config.set('Alerts','Email',email)

    config.add_section('User')
    config.set('User','User',user)
    config.set('User','Pass',passwd)

    config.write(cfg)
    cfg.close()
    os.chmod(os.environ['HOME'] + '/.pyknock.cfg',0600)

# Parse config file into global variables
def readconfig():
    import ConfigParser
    global usr,pwd,cell,email,magicping,ports,timeout
    logging.info('Reading config from file => ' + os.environ['HOME'] + '/.pyknock.cfg')
    config = ConfigParser.ConfigParser()
    config.read(os.environ['HOME'] + '/.pyknock.cfg')
    usr       = config.items('User')[0][1]
    pwd       = config.items('User')[1][1]
    cell      = config.items('Alerts')[0][1]
    email     = config.items('Alerts')[1][1]
    timeout   = int(config.items('Thresholds')[0][1])
    portlist  = config.items('Thresholds')[1][1]
    magicping = int(config.items('Thresholds')[2][1])
    ports     = tuple(portlist.split(','))

# Parses out text and number from google voice
def readtext(jsondata):
    logging.debug("[T2] Reading text")
    allsms = []
    d = json.loads(jsondata)
    for key in d['messages'].keys():
        sms           = {}
        sms['text']   = d['messages'][key]['messageText']
        sms['number'] = d['messages'][key]['phoneNumber']
        allsms.append(sms)
    return allsms 

# Send text message
def sendsms(msg):
    voice.send_sms(cell, msg)

# Email iptables config
def sendiptables():
    logging.info("[T2] Sending IPTables info to " + email)
    subject = "Ohai! Here's your firewall config :)"
    msg = Popen(["/sbin/iptables","-L","-n"], stdout=PIPE, stderr=PIPE).communicate()[0]
    header = "From: %s\r\nTo: %s\r\nSubject: %s\r\nX-Mailer: My-Mail\r\n\r\n" % (usr, email, subject)
    server = smtplib.SMTP('smtp.gmail.com:587')
    server.starttls()
    server.login(usr,pwd)
    server.sendmail(usr, email, header+msg)
    server.quit()

# Unlock port for specified ip address
def unlockfw(source):
    logging.info('[T3] Thread 3 started successfully')
    logging.info("[T3] Unlockfw called, unlocking for %s" % source)
    if type(ports) == str:
        text = "Unlocking port %s for %s" % (ports,source)
        Popen(["/sbin/iptables","-I","INPUT","-s",source,"-p","tcp","--dport",ports,"-j","ACCEPT"]).communicate()
    else:
        p = ''
        for port in ports:
            if port == ports[-1]:
                p += port 
            else:
                p = p + port + ', '
            Popen(["/sbin/iptables","-I","INPUT","-s",source,"-p","tcp","--dport",port,"-j","ACCEPT"]).communicate()
        text = "Unlocking ports %s for %s" % (p,source)
    global ips
    ips.append(source)
    logging.debug("[T3] IPs in whitelist == " + str(ips))
    logging.info("[T3] Sending SMS to " + cell)
    sendsms(text)
    logging.info("[T3] Sleeping for 5 mins while it's open")
    time.sleep(300)
    if len(ips) != 0:
        logging.info("[T3] Calling lockfw for " + source)
        lockfw(source)

# Lock firewall for given IP
def lockfw(source):
    if type(ports) == str:
        text = "Locking port %s for %s" % (ports,source) 
        Popen(["/sbin/iptables","-D","INPUT","-s",source,"-p","tcp","--dport",ports,"-j","ACCEPT"]).communicate()
    else:
        p = ''
        for port in ports:
            if port == ports[-1]:
                p += port 
            else:
                p = p + port + ', '
            Popen(["/sbin/iptables","-D","INPUT","-s",source,"-p","tcp","--dport",port,"-j","ACCEPT"]).communicate()
        text = "Locking ports %s for %s" % (p,source)
    global ips
    ips.pop()
    sendsms(text)

# Make new google voice object and login
def login():
    logging.info('Logging in as ' + usr)
    voice = Voice()
    voice.login(usr,pwd)
    return voice

# Basic checking to make sure we can get icmp requests
def checkicmp():
    logging.info('Checking out iptables situation')
    iptables = Popen(["/sbin/iptables","-L","-n"], stdout=PIPE, stderr=PIPE).communicate()[0]
    if 'ACCEPT     icmp --  0.0.0.0/0            0.0.0.0/0' not in iptables and 'DROP       all  --  0.0.0.0/0            0.0.0.0/0' in iptables:
        print "You drop all packets, but don't allow for ICMP!"
        logging.warning('ICMP rule missing from itables!')
        valid  = ['yes','y']
        choice = raw_input("Do you want me to add a rule for you? [Y/n] => ").lower()
        if choice in valid or choice == '':
            Popen(["/sbin/iptables","-I","INPUT","-p","icmp","-j","ACCEPT"]).communicate()
            print "Done!"
        else:
            print "If you can't accept ICMP, this won't work!"
            sys.exit(1)

# Handle our exit signals gracefully
def exithandle(*args):
    logging.info('CTRL+C detected, exiting.')
    logging.info('=============================\n')
    exit(0)

# Daemonize that bitch!
def daemon():
    try: 
        pid = os.fork() 
        if pid > 0:
            sys.exit(0) 
    except OSError, e: 
        print >>sys.stderr, "fork #1 failed: %d (%s)" % (e.errno, e.strerror) 
        sys.exit(1)

    os.chdir("/") 
    os.umask(0) 
    os.setsid() 

    # Second fork magic
    try: 
        pid = os.fork() 
        if pid > 0:
            logging.info('Daemonized...PID: %d' % (pid))
            print "Daemon PID %d" % pid 
            h = open('/var/run/pyknock.pid','w')
            h.write('%s' % pid)
            h.close()
            sys.exit(0) 
    except OSError, e: 
        print >>sys.stderr, "fork #2 failed: %d (%s)" % (e.errno, e.strerror) 
        sys.exit(1) 
    si = open('/dev/null', 'r')
    so = open('/dev/null', 'a+')
    se = open('/dev/null', 'a+', 0)
    os.dup2(si.fileno(), sys.stdin.fileno())
    os.dup2(so.fileno(), sys.stdout.fileno())
    os.dup2(se.fileno(), sys.stderr.fileno())

# Thread 1
# Listens for magic ICMP request
def listen():
    global ips
    logging.info('[T1] Thread 1 Started Successfully!')
    while (1):
        data = sock.recv(1024)    
        length = int(ord(data[3])) - 28
        ip = data[12:16]
        source = '%d.%d.%d.%d' % (ord(ip[0]), ord(ip[1]), ord(ip[2]), ord(ip[3]))

        if magicping == length:
            logging.info('[T1] [%s] Ping (%d) from %s' % ("Magic!",length,source))
            if source not in ips:
                logging.info("[T1] Magic packet found, starting new thread")
                thread.start_new_thread(unlockfw,(source,))
                time.sleep(2)
        elif length == 56:
            logging.info('[T1] [%s] Ping (%d) from %s' % ("Linux",length,source))
        elif length == 32:
            logging.info('[T1] [%s] Ping (%d) from %s' % ("Windows",length,source))
        elif length == 8:
            # Keep getting one of these stupid pings at work every 10 mins lol
            logging.debug('[T1] [%s] Ping (%d) from %s' % ("Switch",length,source))
        elif length == 20: 
            logging.info('[T1] [%s] Ping (%d) from %s' % ("Mac",length,source))
        else:
            logging.info('[T1] [%s] Ping (%d) from %s' % ("Unknown",length,source))

# Thread 2
# Check for new text messages, and call functions based on that
def smscheck():
    global ips
    logging.info('[T2] Thread 2 Started Successfully!')
    while (1):
        logging.debug('[T2] Fetching new SMS\'s')
        voice.sms()
        for msg in readtext(voice.sms.json):
            logging.info('[T2] Got text (' + msg['text'] + ') from ' + msg['number'])
            if msg['number'] == '+1' + cell:
                if '#config' in msg['text']:
                    logging.debug("[T2] Got config text...")
                    sendiptables()
                elif '#block' in msg['text']:
                    logging.debug("[T2] Got block text...")
                    if len(ips) == 0:   
                        logging.info("[T2] Got block text even though no port active")
                        sendsms('Um...nothing to block dude!')
                    else:
                        # Block all ip's, may make it smarter in the future
                        for ip in ips:
                            logging.info('[T2] Calling lockfw for ' + ip)
                            lockfw(ip)
                elif '#unlock' in msg['text']:
                    logging.debug("[T2] Got an unlock text...")
                    ip = msg['text'].split(' ')[-1]
                    # Simple sanity checking to make sure an IP was supplied
                    try:
                        socket.inet_aton(ip)
                        sendsms('Got unlock request for ' + ip)
                        unlockfw(ip)
                    except socket.error:
                        sendsms('Invalid IP! This is what I got => ' + ip)
        for message in voice.sms().messages:
            logging.info('[T2] Deleting stale SMS\'s')
            message.delete()
        logging.debug('[T2] Sleeping for ' + str(timeout) + ' seconds')
        time.sleep(timeout)

  #                 #
####               #####
##### Entry Point ######
####               #####
  #                 #

if __name__ == "__main__":
    # Check for root
    if os.getuid() != 0:
        print "Must be run as root!"
        sys.exit(1)

    # Set up our logger
    logging.basicConfig(level=logging.INFO,
                        filename='/var/log/pyknock.log',
                        format='%(asctime)s [%(levelname)s] \t=> %(message)s', 
                        datefmt='%m-%d-%Y %I:%M:%S%p')    
    logging.info('===== Starting pyknock! =====')

    # Test if we're configured, otherwise create a new config file
    logging.info('Testing for config...')
    testconfig()
    # Check for ICMP firewall rules
    logging.info('Testing for ICMP availiliblity...')
    checkicmp()

    # Bind to our ICMP socket
    try:
        logging.info('Attempting to bind to ICMP socket...')
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.bind(('0.0.0.0', 1))
    except:
        logging.error('Can\'t bind to socket!')
        print "Unable to bind to socket! :("
        exit(1)
    
    # Login to google voice
    try:
        voice = login()
    except:
        print "Couldn't log in! "
        sys.exit(1)
    
    # Global active ip list
    global ips 
    ips = []

    # Start daemonizing
    daemon()

    # Start our threads and login to google voice
    logging.info("Starting socket thread ([T1])")
    thread.start_new_thread(listen,())
    logging.info("Starting textcheck thread ([T2])")
    thread.start_new_thread(smscheck,())

    # Catch all exit signals
    signal.signal(signal.SIGINT, exithandle) 
    signal.signal(signal.SIGTERM, exithandle) 


    # Ugly hack to keep program running after spinning off threads
    while(1):
        time.sleep(10)

