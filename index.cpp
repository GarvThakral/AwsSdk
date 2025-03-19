#include <stdio.h>
#include <curl/curl.h>
#include <iostream>
#include <ctime>
#include <unordered_map>

using namespace std;

void UriEncodeCanonicalURI(string fullUrl){
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
    
}
void UriEncodeCanonicalQueryString(string fullUrl){
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
            cout << key << "\n";
            cout << value << "\n";
            key = "";
            value = "";
        }else{
            key += queryValue[i];
        }
    }

}

string canonicalRequest(string httpMethod , string canonicalURI , string canonicalQueryString , string canonicalHeaders)  {
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
    UriEncodeCanonicalQueryString("http://s3.amazonaws.com/examplebucket?prefix=somePrefix&marker=someMarker&max-keys=20");
    return 0;
}
