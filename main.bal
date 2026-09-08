import ballerina/crypto;
import ballerina/http;
import ballerina/log;
import ballerina/time;

configurable string secretKey = "super-secret-partner-key-123";

listener http:Listener ep = new(9090);

service /checksumtests on ep {
    resource function post api/webhook/payment(http:RequestContext ctx, http:Caller caller, http:Request req) returns error? {
        string payloadString = check req.getTextPayload();

        int currentTimestamp = time:utcNow()[0];
        string timestampStr = currentTimestamp.toString();
        string messageToSign = timestampStr + "." + payloadString;

        // calculate HMAC SHA-256 signature
        byte[] keyBytes = secretKey.toBytes();
        byte[] messageBytes = messageToSign.toBytes();
        byte[] hmacBytes = check crypto:hmacSha256(messageBytes, keyBytes);
        string signature = hmacBytes.toBase16();

        log:printInfo("Calculated Signature in wso2 Integrator " + signature);

        //Creating a http client pointing to the untouched springboot backend
        http:Client backendClient = check new("http://localhost:8080");

        //building an outbound request enriching it with the necessary headers
        http:Request outboundReq = new;
        outboundReq.setTextPayload(payloadString, contentType="application/json");
        outboundReq.setHeader("X-Signature", signature);
        outboundReq.setHeader("X-Timestamp", timestampStr);


        //forward the enriched springboot request to the springboot backend
        http:Response|error backendRes = backendClient->post("/api/webhook/payment", outboundReq);

        if backendRes is http:Response {
            //Return the backend's response back to the original client
            check caller->respond(backendRes);
        } else {
            log:printError("Failed to reach the springboot application", 'error=backendRes);
            check caller->respond({"error": "Internal Integration Gateway error"});
        }
    }
}