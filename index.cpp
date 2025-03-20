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

string sha256(const string& input) {
    CryptoPP::SHA256 hash;
    std::string digest;

    CryptoPP::StringSource s(input, true,
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

void UriEncode(string toEncode){
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
    cout << final ;
}

string canocialHeaders(unordered_map<string,string> allHeaders){
    string canocialHeadersString;
    for(auto& [key, value]:allHeaders){
        string final = LowerCase(key)+ ':' + Trim(value) + '\n';
        canocialHeadersString += final;
    }
    return canocialHeadersString;
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
    for(int i = uriStartIndex ; i < fullUrl.size() ;i++){
        uriValue += fullUrl[i];
        if(fullUrl[i] == '?'){
            cout << uriValue;
            return;
        }
    }
    cout << uriValue << '\n';
    return uriValue;
}
string UriEncodeCanonicalQueryString(string fullUrl){
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


    unordered_map<string, string> keyValMap; 

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
    for (auto& [key, value]: keyValMap) {  std::cout << key << " " << value << endl; }
    return "making";
}

string canonicalRequest(string httpMethod , string fullUrl)  {
    string canocialURI = UriEncodeCanonicalURI(fullUrl);
    string canocialQueryString = UriEncodeCanonicalQueryString(fullUrl);
    string canocialString = httpMethod + '\n' + canocialString;
    
    return "0";
}

size_t got_data(char *buffer, size_t itemsize, size_t nitems, void* ignorethis) {
    size_t bytes = itemsize * nitems;    
    for(int i = 0; i < bytes; i++) {
        cout << buffer[i];
    }
    return bytes;
}

string getDateFormat(){
    time_t currentTime = time(nullptr);
    tm* timeInfo = localtime(&currentTime);
    char buffer[11];
    strftime(buffer, sizeof(buffer), "%Y%m%d", timeInfo);
    return buffer;
}

string getIsoTime(){
    time_t now;
    time(&now);
    char buf[sizeof "2011-10-08T07:07:09Z"];
    strftime(buf, sizeof buf, "%FT%TZ", gmtime(&now));
    std::cout << buf << "\n";
    return buf;
}

void signSignature(string scope){
    string timeStamp = getIsoTime();
    string signString = "AWS4-HMAC-SHA256" + '\n' + timeStamp + '\n' + scope + '\n' ; //+hex(sha256hash(canocial request))
}

void calculate_auth_header(string access_key_id , string region , string service){
    string year = getDateFormat();
    string authString = access_key_id + "/" + year + "/" + region + "/" + service + "/" + "aws4_request";
    signSignature("cyx");
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
    // UriEncodeCanonicalURI("http://s3.amazonaws.com/examplebucket/myphoto.jpg");
    // UriEncodeCanonicalQueryString("http://s3.amazonaws.com/examplebucket?prefix=somePrefix&marker=someMarker&max-keys=20");
    string newString = sha256("Garvisthebest");
    cout << newString;
    map<string,string> newMap;
    newMap["garv"] = "thakral";
    newMap["garv1"] = "thakral1";
    newMap["garv0"] = "thakral0";
    for(auto& [key , value]:newMap){cout << key << " " << value};
    return 0;
}
