import ballerina/http;
import ballerina/io;
import ballerina/oauth2;
import ballerina/time;
import wso2/choreo.sendemail;

// Configurable variables.
configurable string CLIENT_KEY =?;
configurable string CLIENT_SECRET =?;
configurable int EXPIRED_AFTER_IN_DAYS =?;
configurable string ORG_NAME =?;

// Email template constants.
const EMAIL_SUBJECT = "Reset your password";
const EMAIL_CONTENT = "Your password has been expired.";

// API related constants.
string inactiveUserRetrivalEndpointUrl = "https://dev.api.asgardeo.io/t/" + ORG_NAME + "/api/idle-account-identification/v1/inactive-users";
string scim2Endpoint = "https://dev.api.asgardeo.io/t/" + ORG_NAME + "/scim2/Users/";
string tokenEndpoint = "https://dev.api.asgardeo.io/t/" + ORG_NAME + "/oauth2/token";
string[] requiredScopeList = ["internal_user_mgt_list", "internal_user_mgt_view"];

public function main() returns error? {

    // Inactive userList.
    string bearerToken = check getBearerToken();
    json[] inactiveUsersList = check getInactiveUsersList(bearerToken);

    http:Client scim2Client = check createHttpClient(scim2Endpoint, bearerToken);

    // Send for each inactive user.
    foreach var user in inactiveUsersList {

        // Get the email of the user via SCIM2 API.
        string userId = (check user.userId).toString();
        string username = (check user.username).toString();
        map<json> userInfo = check scim2Client->get(userId);
        sendemail:Client emailClient = check new ();

        emailListOfUser emailList = check userInfo.cloneWithType();
        if (emailList.length() > 0) {
            sendEmail(emailClient, emailList.emails.pop());  
        } else {
            io:println("Email is not found for the user " + username + ".");
        }
        
    }
}

// Get bearer token with client credentials.
function getBearerToken() returns string|error {

    oauth2:ClientOAuth2Provider tokenProvider = new({
            tokenUrl: tokenEndpoint,
            clientId: CLIENT_KEY,
            clientSecret: CLIENT_SECRET,
            scopes: requiredScopeList
        });

    return tokenProvider.generateToken();
}

// Create a http client to invoke given API with bearer token.
function createHttpClient(string endpoint, string bearerToken) returns http:Client|error {

    http:Client httpClient = check new (endpoint,
            auth = {
                token: bearerToken
            }
        );

    return httpClient;
}

// Get inactive userList.
function getInactiveUsersList(string bearerToken) returns json[]|error {

    [string, string] [expiredBeforeTimeStamp, expiredAfterTimeStamp] = getExpiredTimeRange();
    http:Client inactiveUserRetrivalClient = check createHttpClient(inactiveUserRetrivalEndpointUrl, bearerToken);
    
    json[] inactiveUsersList;
    inactiveUsersList = check inactiveUserRetrivalClient->/(inactiveBefore=expiredBeforeTimeStamp, inactiveAfter=expiredAfterTimeStamp);
        
    return inactiveUsersList;
}

// Send email to given EmailAddress
function sendEmail(sendemail:Client emailClient, string emailAddress) {

    string|error result = emailClient->sendEmail(emailAddress, EMAIL_SUBJECT, EMAIL_CONTENT);

    if (result is string) {
        io:println("Successfully sent the email to the " + emailAddress + ".");
    } else {
        io:println("Error occured while sending the email to the " + emailAddress + ".");
    }
}

function utcSubSeconds(time:Utc utc, time:Seconds seconds) returns time:Utc {

    [int, decimal] [secondsFromEpoch, lastSecondFraction] = utc;
    secondsFromEpoch = secondsFromEpoch - <int>seconds.floor();

    return [secondsFromEpoch, lastSecondFraction];
}

function getExpiredTimeRange() returns [string ,string] {

    time:Seconds secondsInDays = 86400;
    time:Seconds expiredAfterInSec = EXPIRED_AFTER_IN_DAYS*secondsInDays;
    time:Seconds expiredBeforeInSec = (EXPIRED_AFTER_IN_DAYS+1)*secondsInDays;

    time:Utc expiredAfterTimeStamp = utcSubSeconds(time:utcNow(), expiredAfterInSec);
    time:Utc expiredBeforeTimeStamp = utcSubSeconds(time:utcNow(), expiredBeforeInSec);

    return [time:utcToString(expiredBeforeTimeStamp).substring(0, 10), time:utcToString(expiredAfterTimeStamp).substring(0, 10)];
}
