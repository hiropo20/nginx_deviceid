
export default {setDeviceid, delDeviceid, getState , echo} ;

function setDeviceid(r) {
        var flag = 0;
        r.variables.auth_user = r.variables.arg_auth_user ;
        // check cookie and url parameter


        if (!r.variables.cookie__imp_di_pc_ ) {
                r.error("setDeviceid: Missing deviceID ");
                r.return(403, "Missing deviceID. This req can be malicious access.");
                return;
        }
        if (!r.variables.arg_auth_user ) {
                r.error("setDeviceid: Missing authentication user name");
                r.return(403, "Missing authentication user name. This req can be malicious access.");
                return;
        }
        // this is another device
        if ( r.variables.auth_dev && r.variables.cookie__imp_di_pc_ != r.variables.auth_dev ) {
                flag = 0 ;
                r.error("Other device of current user");
        }
        // new device
        if ( ! r.variables.auth_dev  || r.variables.cookie__imp_di_pc_  == r.variables.auth_dev ) {
                flag = 1 ;
                r.variables.auth_dev = r.variables.cookie__imp_di_pc_ ;
                r.error("New device of current user");
        }
        r.headersOut['Set-Cookie'] = [
                "auth_user="+ r.variables.arg_auth_user,
                "auth_flag="+ flag,
                "auth_dev="+ r.variables.auth_dev,
                "user_dev="+ r.variables.cookie__imp_di_pc_
        ];

        // current connection
        r.return(302, "/");
        return;

}
function delDeviceid(r) {
        if ( r.variables.cookie_auth_flag == 1 ) {
                r.variables.auth_dev = "";
        }
        r.headersOut['Set-Cookie'] = [
                "auth_user=" ,
                "auth_flag=" ,
                "auth_dev=" ,
                "user_dev="
        ];

        r.return(302, "/device-logout.html");
        return;

}
function getState(r) {

        var auth_info = {}
        auth_info.current_device    = r.variables.cookie__imp_di_pc_;
        auth_info.current_user      = r.variables.cookie_auth_user;
        auth_info.current_flag      = r.variables.cookie_auth_flag;
        auth_info.primary_device    = r.variables.auth_dev;
        //auth_info.primary_user      = r.variables.auth_user;

        r.return(200, JSON.stringify(auth_info));
        return;

}
function echo(r){
        var delay = Number( (!r.variables.arg_delay)? 0 : r.variables.arg_delay ) ;
        setTimeout(function(){
                r.return (200, "*");
        },delay)
}
