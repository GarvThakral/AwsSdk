#include <stdio.h>
#include <curl/curl.h>
#include <iostream>
#include <ctime>
#include <unordered_map>
#include <map>
#include <sstream>
#include <cryptopp/cryptlib.h>
#include <cryptopp/sha.h>
#include <cryptopp/hmac.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/secblock.h>
#include <cryptopp/filters.h>
using namespace std;
using namespace CryptoPP;

string getDateFormat(){
    time_t currentTime = time(nullptr);
    tm* timeInfo = localtime(&currentTime);
    char buffer[11];
    strftime(buffer, sizeof(buffer), "%Y%m%d", timeInfo);
    return buffer;
}

string hmac_sha256_binary(const string& key, const string& message) {
    string mac;
    SecByteBlock keyBlock(reinterpret_cast<const CryptoPP::byte*>(key.data()), key.size());
    
    HMAC<SHA256> hmac(keyBlock, keyBlock.size());
    
    StringSource(message, true,
        new HashFilter(hmac,
            new StringSink(mac)  // Note: No HexEncoder here
        )
    );
    
    return mac;
}

// For final signature (returns hex)
string hmac_sha256(const string& key, const string& message) {
    string mac;
    SecByteBlock keyBlock(reinterpret_cast<const CryptoPP::byte*>(key.data()), key.size());
    
    HMAC<SHA256> hmac(keyBlock, keyBlock.size());
    
    StringSource(message, true,
        new HashFilter(hmac,
            new HexEncoder(
                new StringSink(mac)
            )
        )
    );
    
    return mac;
}

string sha256(string payload) {
    CryptoPP::SHA256 hash;
    std::string digest;

    CryptoPP::StringSource s(payload, true,
        new CryptoPP::HashFilter(hash,
            new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(digest)
            )
        )
    );
    return digest;
}

string LowerCase(string val){
    
    for (auto& x : val) { 
        x = tolower(x); 
    } 
    
    return val;
}

string Trim(string toTrim){
    string newString;
    int i = 0, j = toTrim.size()-1;
    if(toTrim[0] == ' '){
        while(toTrim[i] == ' '){
            i++;
        }
    }
    if(toTrim[toTrim.size()-1] == ' '){        
        while(toTrim[j] == ' '){
            j--;
        }
    }
    for(int k = i ; k <= j ; k++){
        newString += toTrim[k];
    }

    return newString ;
}

string UriEncode(string toEncode){
    string final ;
    for(int i = 0 ; i < toEncode.size() ; i++){
        if((toEncode[i] >= 'a' && toEncode[i] <= 'z') || (toEncode[i] >= 'A' && toEncode[i] <= 'Z')){
            final += toEncode[i];
            continue;
        }else if(toEncode[i] >= '0' && toEncode[i] <= '9'){
            final += toEncode[i];
            continue;
        }else{
            int splChar = toEncode[i];
            stringstream ss;
            ss << hex << uppercase  << splChar;
            string hexVal = ss.str();
            string conCat = "%" + hexVal; 
            final += conCat;

        }
    }
    return final ;
}

string canocialHeaders(map<string,string> allHeaders){
    string canocialHeadersString;
    for(auto& [key, value]:allHeaders){
        string final = LowerCase(key)+ ':' + Trim(value) + '\n';
        canocialHeadersString += final;
    }
    return canocialHeadersString;
}

string SignedHeaders(map<string,string> allHeaders){
    string signedHeadersString;
    for(auto& [key, value]:allHeaders){
        string final = LowerCase(key)+ ';';
        signedHeadersString += final;
    }
    return signedHeadersString;
}

string calculateScope(string region , string service){
    string scopeString = getDateFormat() + "/" + region + "/" + service + "/aws4_request";
    return scopeString;
}

string UriEncodeCanonicalURI(string fullUrl){
    int uriStartIndex;
    for(int i = 0 ; i < fullUrl.size() ; i++){
        if(fullUrl[i] == '.' && fullUrl[i+1] == 'c' && fullUrl[i+2] == 'o' && fullUrl[i+3] == 'm'){
            uriStartIndex = i+4;
            break;
        }
    }
    string uriValue;
    
    if(fullUrl[uriStartIndex+1] == '?'){
        return "";
    }
    for(int i = uriStartIndex ; i < fullUrl.size() ;i++){
        uriValue += fullUrl[i];
        if(fullUrl[i] == '?'){
            cout << uriValue;
            break;
        }
    }
    cout << uriValue << '\n';
    return uriValue;
}

map<string,string> UriEncodeCanonicalQueryString(string fullUrl){
    int uriStartIndex;
    for(int i = 0 ; i < fullUrl.size() ; i++){
        if(fullUrl[i] == '.' && fullUrl[i+1] == 'c' && fullUrl[i+2] == 'o' && fullUrl[i+3] == 'm'){
            uriStartIndex = i+4;
            break;
        }
    }
    string queryValue;
    int queryStringStartIndex;
    for(int i = uriStartIndex ; i < fullUrl.size() ;i++){
        if(fullUrl[i] == '?'){
            queryStringStartIndex = i+1;
            break;
        }
    }

    for(int i = queryStringStartIndex;i<fullUrl.size() ; i++){
        queryValue += fullUrl[i];
    }


    map<string, string> keyValMap; 

    string key;
    string value;
    for(int i = 0 ; i < queryValue.size() ; i++){
        //prefix=somePrefix&marker=someMarker&max-keys=20
        if(queryValue[i] == '='){
            i++;
            while(queryValue[i]!='&' && i!=queryValue.size()){
                value += queryValue[i];                
                i++;
            }
            keyValMap[key] = value;
            key = "";
            value="";
        }else{
            key += queryValue[i];
        }
    }
    // for (auto& [key, value]: keyValMap) {  std::cout << key << " " << value << endl; }
    return keyValMap;
}

string canonicalRequest(string httpMethod , string fullUrl , map<string,string> allHeaders , string payload)  {
    string canocialURI = UriEncodeCanonicalURI(fullUrl);
    map<string,string> canocialQueryKeyVal = UriEncodeCanonicalQueryString(fullUrl);
    string canocialQueryString;
    for(auto& [key,value]:canocialQueryKeyVal){
        string temp = UriEncode(key)+"=" + UriEncode(value) + "&";
        canocialQueryString+=temp;
    }
    string canocialString = httpMethod + "\n" + canocialURI + "\n" + canocialQueryString + "\n" + canocialHeaders(allHeaders) + "\n" + SignedHeaders(allHeaders)+ "\n" + sha256(payload) ;

    return canocialString;
}

size_t got_data(char *buffer, size_t itemsize, size_t nitems, void* ignorethis) {
    size_t bytes = itemsize * nitems;    
    for(int i = 0; i < bytes; i++) {
        cout << buffer[i];
    }
    return bytes;
}

string getIsoTime(){
    time_t now;
    time(&now);
    char buf[sizeof "2011-10-08T07:07:09Z"];
    strftime(buf, sizeof buf, "%FT%TZ", gmtime(&now));
    std::cout << buf << "\n";
    return buf;
}

string signSignature(string scope , string hashedCanocialRequest){
    string timeStamp = getIsoTime();
    string signString = "AWS4-HMAC-SHA256\n" + timeStamp + "\n" + scope + "\n" + hashedCanocialRequest; //+hex(sha256hash(canocial request))
    return signString;
}

void calculate_auth_header(string access_key_id , string region , string service){
    string year = getDateFormat();
    string authString = access_key_id + "/" + year + "/" + region + "/" + service + "/" + "aws4_request";
    signSignature("cyx","xyz");
}

string calculateSignature(string secretAccessKey , string region , string service , string stringToSign){
    string DateKey = hmac_sha256_binary("AWS4" + secretAccessKey , getDateFormat());
    string DateRegionKey = hmac_sha256_binary(DateKey, region);
    string DateRegionServiceKey = hmac_sha256_binary(DateRegionKey , service);
    string SigningKey = hmac_sha256_binary(DateRegionServiceKey,"aws4_request");
    string FinalSignature = hmac_sha256(SigningKey,stringToSign);
    return FinalSignature;
}

string authorizationHeader(string accessKeyId , string secretAccessKey , string region , string service , string stringToSign , map<string,string> allHeaders ){
    string authorizationString = "AWS4-HMAC-SHA256 Credential=" + accessKeyId + calculateScope(region , service) + ",SignedHeaders=" + SignedHeaders(allHeaders)+  ",Signature="+ calculateSignature(secretAccessKey , region , service , stringToSign);
    return authorizationString;
}

string jsonString(map<string,string> payloadMap){
    string finalString = "{";
    for(auto& [key,value] : payloadMap){
        string temp;
        temp += "\\\""+key+"\\\":""\\\""+value+"\\\",";
        finalString+=temp;
    }
    finalString[finalString.size()-1] = '}';
    return finalString;
}

int main() {
    // CURL *curl = curl_easy_init();
    // if(!curl){
    //     cout << stderr << " Curl initialisation failed";
    //     return EXIT_FAILURE;
    // }
    // //set option 
    // curl_easy_setopt(curl , CURLOPT_URL , "https://s3.amazonaws.com");
    // curl_easy_setopt(curl , CURLOPT_WRITEFUNCTION , got_data);
    // CURLcode result = curl_easy_perform(curl);
    // if(!result == CURLE_OK){
    //     cout << "Error connecting again";
    // }
    
    // // set option
    // cout << "Curl initialised";
    // calculate_auth_header("new","new","new");
    // UriEncodeCanonicalQueryString("http://s3.amazonaws.com/examplebucket?prefix=somePrefix&marker=someMarker&max-keys=20");
    // string newString = sha256("Garvisthebest");
    // cout << newString;
    // map<string,string> canocialHeadersMap;
    // canocialHeadersMap["host"] = "amazon.com";
    // canocialHeadersMap["password"] = "garv123";
    // canocialHeadersMap["id"] = "garv";
    // string newString = calculateScope("thisisscope" , "thisisHash");


    // Payload calc
    map<string,string> payloadMap;
    payloadMap["username"] = "testuser";    
    payloadMap["action"] = "login";    
    payloadMap["timestamp"] = "2025-03-21t10:00:00z";    
    string payload = jsonString(payloadMap);

    // Canocial Request
    string fullUrl = "https://ec2.us-east-1.amazonaws.com/?Action=RunInstances&ImageId=ami-0c55b159cbfafe1f0&InstanceType=t2.micro&MinCount=1&MaxCount=1&KeyName=my-key-pair&SecurityGroupId.1=sg-0123456789abcdef&SubnetId=subnet-0123456789abcdef&Version=2016-11-15";
    string uriString = UriEncodeCanonicalURI(fullUrl);
    map<string,string> queryMap = UriEncodeCanonicalQueryString(fullUrl);
    string headerString = canocialHeaders(queryMap);
    // for(auto& [key,value]:newString){cout << key << " " << value << '\n';}
    string canocialString = canonicalRequest("GET" , fullUrl , queryMap ,payload);
    string hashedCanocialString = sha256(canocialString);

    //StringToSign
    string scopeString = calculateScope("us-east-1" , "s3");
    string signedString = signSignature(scopeString , hashedCanocialString);
    cout << signedString;

    
    return 0;
}
