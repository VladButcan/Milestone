import std.conv;
import std.digest;
import std.digest.sha;
import std.stdio;
 
import vibe.d;
import vibe.web.auth;
 
import db_conn;
 
static struct AuthInfo
{
@safe:
    string userEmail;
}
 
@path("api/v1")
@requiresAuth
interface VirusTotalAPIRoot
{
    // Users management
    @noAuth
    @method(HTTPMethod.POST)
    @path("signup")
    Json addUser(string userEmail, string username, string password, string name = "", string desc = "");
 
    @noAuth
    @method(HTTPMethod.POST)
    @path("login")
    Json authUser(string userEmail, string password);
 
    @anyAuth
    @method(HTTPMethod.POST)
    @path("delete_user")
    Json deleteUser(string userEmail);
 
    // URLs management
    @anyAuth
    @method(HTTPMethod.POST)
    @path("add_url") // the path could also be "/url/add", thus defining the url "namespace" in the URL
    Json addUrl(string userEmail, string urlAddress);
 
    @noAuth
    @method(HTTPMethod.GET)
    @path("url_info")
    Json getUrlInfo(string urlAddress);
 
    @noAuth
    @method(HTTPMethod.GET)
    @path ("user_urls")
    Json getUserUrls(string userEmail);
 
    @anyAuth
    @method(HTTPMethod.POST)
    @path("delete_url")
    Json deleteUrl(string userEmail, string urlAddress);
 
    // Files management
    @anyAuth
    @method(HTTPMethod.POST)
    @path("add_file")
    Json addFile(string userEmail, immutable ubyte[] binData, string fileName);
 
    @noAuth
    @method(HTTPMethod.GET)
    @path("file_info")
    Json getFileInfo(string fileSHA512Digest);
 
    @noAuth
    @method(HTTPMethod.GET)
    @path("user_files")
    Json getUserFiles(string userEmail);
 
    @anyAuth
    @method(HTTPMethod.POST)
    @path("delete_file")
    Json deleteFile(string userEmail, string fileSHA512Digest);
}
 
class VirusTotalAPI : VirusTotalAPIRoot
{
    this(DBConnection dbClient)
    {
        this.dbClient = dbClient;
    }
 
    @noRoute AuthInfo authenticate(scope HTTPServerRequest req, scope HTTPServerResponse res)
    {
        // If "userEmail" is not present, an error 500 (ISE) will be returned
        string userEmail = req.json["userEmail"].get!string;
        string userAccessToken = dbClient.getUserAccessToken(userEmail);
        // Use headers.get to check if key exists
        string headerAccessToken = req.headers.get("AccessToken");
        if (headerAccessToken && headerAccessToken == userAccessToken)
            return AuthInfo(userEmail);
        throw new HTTPStatusException(HTTPStatus.unauthorized);
    }
 
override:
 
    Json addUser(string userEmail, string username, string password, string name = "", string desc = "")
    {
        auto returnValue = dbClient.addUser(userEmail, username, password, name, desc);
        if (returnValue == dbClient.UserRet.ERR_NULL_PASS) {
            throw new HTTPStatusException(HTTPStatus.badRequest, "[ERR_NULL_PASS] badRequest");
        }
        if (returnValue == dbClient.UserRet.ERR_INVALID_EMAIL) {
            throw new HTTPStatusException(HTTPStatus.badRequest, "[ERR_INVALID_EMAIL] badRequest");
        }
        if (returnValue == dbClient.UserRet.ERR_USER_EXISTS) {
            throw new HTTPStatusException(HTTPStatus.unauthorized, "[ERR_USER_EXISTS] unauthorized");
        }
        return serializeToJson(["addUser": "success"]);
    }
 
    Json authUser(string userEmail, string password)
    {
        auto returnValue = dbClient.authUser(userEmail, password);
        if (returnValue == dbClient.UserRet.ERR_NULL_PASS) {
            throw new HTTPStatusException(HTTPStatus.badRequest, "[ERR_NULL_PASS] badRequest");
        }
        if (returnValue == dbClient.UserRet.ERR_INVALID_EMAIL) {
            throw new HTTPStatusException(HTTPStatus.badRequest, "[ERR_INVALID_EMAIL] badRequest");
        }
        if (returnValue == dbClient.UserRet.ERR_WRONG_PASS) {
            throw new HTTPStatusException(HTTPStatus.unauthorized, "[ERR_WRONG_PASS] unauthorized");
        }
        if (returnValue == dbClient.UserRet.ERR_WRONG_USER) {
            throw new HTTPStatusException(HTTPStatus.unauthorized, "[ERR_WRONG_USER] unauthorized");
        }
        string actualToken = dbClient.generateUserAccessToken(userEmail);
        return serializeToJson(["AccessToken": actualToken]);
    }
 
    Json deleteUser(string userEmail)
    {
        auto returnValue = dbClient.deleteUser(userEmail);
        if (returnValue == dbClient.UserRet.ERR_INVALID_EMAIL)
            throw new HTTPStatusException(HTTPStatus.badRequest, "[ERR_INVALID_EMAIL] badRequest");
        return serializeToJson(["userDelete": "success"]);
    }
 
    // URLs management
 
    Json addUrl(string userEmail, string urlAddress)
    {
        if (urlAddress.empty)
            throw new HTTPStatusException(HTTPStatus.badRequest, "[URL_EMPTY] badRequest");
        auto returnValue = dbClient.addUrl(userEmail, urlAddress);
        if (returnValue == dbClient.UrlRet.URL_EXISTS)
            throw new HTTPStatusException(HTTPStatus.ok, "[URL_EXISTS] ok");
        throw new HTTPStatusException(HTTPStatus.ok, "[URL_OK] has added");
    }   
 
    Json deleteUrl(string userEmail, string urlAddress)
    {
        if (urlAddress.empty)
            throw new HTTPStatusException(HTTPStatus.badRequest, "[URL_EMPTY] badRequest");
        dbClient.deleteUrl(userEmail, urlAddress);
        return serializeToJson(["urlDelete" : "success"]);
    }
 
    Json getUrlInfo(string urlAddress)
    {
        auto returnValue = dbClient.getUrl(urlAddress);
        if (returnValue.isNull)
            throw new HTTPStatusException(HTTPStatus.notFound, "[GET_URL_ERROR] url not found");
        return serializeToJson(returnValue);
    }
 
    Json getUserUrls(string userEmail)
    {
        auto returnValue = dbClient.getUrls(userEmail);
        return serializeToJson(returnValue);
    }
 
    // Files management
 
    Json addFile(string userEmail, immutable ubyte[] binData, string fileName)
    {
        auto returnValue = dbClient.addFile(userEmail, binData, fileName);
        if (returnValue == dbClient.FileRet.ERR_EMPTY_FILE) {
            throw new HTTPStatusException(HTTPStatus.badRequest, "[ERR_EMPTY_FILE] badRequest");
        }
        throw new HTTPStatusException(HTTPStatus.ok, "[ok] file exist or has added");
    }
 
    Json getFileInfo(string fileSHA512Digest)
    {
        // TODO
        auto returnValue = dbClient.getFile(fileSHA512Digest);
        if (returnValue.isNull)
            throw new HTTPStatusException(HTTPStatus.notFound, "[GET_FILE_ERROR] file not found");
        return serializeToJson(returnValue);
    }
 
    Json getUserFiles(string userEmail)
    {
        auto returnValue = dbClient.getFiles(userEmail);
        return serializeToJson(returnValue);
    }
 
    Json deleteFile(string userEmail, string fileSHA512Digest)
    {
        // TODO
        if (fileSHA512Digest.empty)
            throw new HTTPStatusException(HTTPStatus.badRequest, "[URL_EMPTY] badRequest");
        dbClient.deleteFile(userEmail, fileSHA512Digest);
        return serializeToJson(["fileDelete" : "success"]);
    }
 
private:
    DBConnection dbClient;
}