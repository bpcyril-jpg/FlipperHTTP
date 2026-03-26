#include "http.hpp"
#include "certs.hpp"
#include "common.hpp"
#include <ArduinoHttpClient.h>

#ifndef BOARD_BW16
HTTP::HTTP(UART *uart, WiFiClientSecure *client)
#else
HTTP::HTTP(UART *uart, WiFiSSLClient *client)
#endif
{
    this->uart = uart;
    this->client = client;

#ifndef BOARD_BW16
    this->client->setCACert(root_ca);
#else
    this->client->setRootCA((unsigned char *)root_ca);
#endif
}

String HTTP::request(
    const char *method,
    String url,
    String payload,
    const char *headerKeys[],
    const char *headerValues[],
    int headerSize)
#ifdef BOARD_BW16
{
    String response = "";                              // Initialize response string
    this->client->setRootCA((unsigned char *)root_ca); // Set root CA for SSL
    int index = url.indexOf('/');                      // Find the first occurrence of '/'
    String host = url.substring(0, index);             // Extract host
    String path = url.substring(index);                // Extract path

    char host_server[64];                                    // Buffer for host server
    strncpy(host_server, host.c_str(), sizeof(host_server)); // Copy host to buffer

    if (this->client->connect(host_server, 443)) // Connect to the server
    {
        // Make a HTTP request:
        this->client->print(method);
        this->client->print(" ");
        this->client->print(path);
        this->client->println(" HTTP/1.1");
        this->client->print("Host: ");
        this->client->println(host_server);

        // Add custom headers if provided
        for (int i = 0; i < headerSize; i++)
        {
            this->client->print(headerKeys[i]);
            this->client->print(": ");
            this->client->println(headerValues[i]);
        }

        // Add payload if provided
        if (payload != "")
        {
            this->client->print("Content-Length: ");
            this->client->println(payload.length());
            this->client->println("Content-Type: application/json");
        }

        this->client->println("Connection: close");
        this->client->println();

        // Send the payload in the request body
        if (payload != "")
        {
            this->client->println(payload);
        }

        // read everything that’s in the buffer, then stop
        while (this->client->available())
            response += this->client->readStringUntil('\n') + "\n";
        this->client->stop();
    }
    else
    {
        this->uart->println(F("[ERROR] Unable to connect to the server."));
    }

    // Clear serial buffer to avoid any residual data
    this->uart->clearBuffer();

    return response;
}
#else
{
    HTTPClient http;
    String response = "";

    http.collectHeaders(headerKeys, headerSize);

    if (http.begin(*this->client, url))
    {
        for (int i = 0; i < headerSize; i++)
        {
            http.addHeader(headerKeys[i], headerValues[i]);
        }

        if (payload == "")
        {
            payload = "{}";
        }

        int statusCode = http.sendRequest(method, payload);
        char headerResponse[512];

        if (statusCode > 0)
        {
            snprintf(headerResponse, sizeof(headerResponse), "[%s/SUCCESS]{\"Status-Code\":%d,\"Content-Length\":%d}", method, statusCode, http.getSize());
            this->uart->println(headerResponse);
            response = http.getString();
            http.end();
            return response;
        }
        else
        {
            if (statusCode != -1) // HTTPC_ERROR_CONNECTION_FAILED
            {
                snprintf(headerResponse, sizeof(headerResponse), "[ERROR] %s Request Failed, error: %s", method, http.errorToString(statusCode).c_str());
                this->uart->println(headerResponse);
            }
            else // certification failed?
            {
                // send request without SSL
                http.end();
                this->client->setInsecure();
                if (http.begin(*this->client, url))
                {
                    for (int i = 0; i < headerSize; i++)
                    {
                        http.addHeader(headerKeys[i], headerValues[i]);
                    }
                    int newCode = http.sendRequest(method, payload);
                    if (newCode > 0)
                    {
                        snprintf(headerResponse, sizeof(headerResponse), "[%s/SUCCESS]{\"Status-Code\":%d,\"Content-Length\":%d}", method, newCode, http.getSize());
                        this->uart->println(headerResponse);
                        response = http.getString();
                        http.end();
                        this->client->setCACert(root_ca);
                        return response;
                    }
                    else
                    {
                        this->client->setCACert(root_ca);
                        snprintf(headerResponse, sizeof(headerResponse), "[ERROR] %s Request Failed, error: %s", method, http.errorToString(newCode).c_str());
                        this->uart->println(headerResponse);
                    }
                }
            }
        }
        http.end();
    }
    else
    {
        this->uart->println(F("[ERROR] Unable to connect to the server."));
    }

    // Clear serial buffer to avoid any residual data
    this->uart->clearBuffer();

    return response;
}
#endif

bool HTTP::stream(const char *method, String url, String payload, const char *headerKeys[], const char *headerValues[], int headerSize)
#ifdef BOARD_BW16
{
    // Not implemented for BW16
    this->uart->print(F("[ERROR] streamBytes not implemented for BW16."));
    this->uart->print(method);
    this->uart->print(url);
    this->uart->print(payload);
    for (int i = 0; i < headerSize; i++)
    {
        this->uart->print(headerKeys[i]);
        this->uart->print(headerValues[i]);
    }
    this->uart->println();
    return false;
}
#else
{
    HTTPClient http;

    http.collectHeaders(headerKeys, headerSize);

    if (http.begin(*this->client, url))
    {
        for (int i = 0; i < headerSize; i++)
        {
            http.addHeader(headerKeys[i], headerValues[i]);
        }

        if (payload == "")
        {
            payload = "{}";
        }

        int httpCode = http.sendRequest(method, payload);
        int len = http.getSize(); // Get the response content length
        char headerResponse[256];
        if (httpCode > 0)
        {
            snprintf(headerResponse, sizeof(headerResponse), "[%s/SUCCESS]{\"Status-Code\":%d,\"Content-Length\":%d}", method, httpCode, len);
            this->uart->println(headerResponse);
            uint8_t buff[512] = {0}; // Buffer for reading data

            WiFiClient *stream = http.getStreamPtr();

            size_t freeHeap = commonGetFreeHeap(); // Check available heap memory before starting
            const size_t minHeapThreshold = 1024;  // Minimum heap space to avoid overflow
            if (freeHeap < minHeapThreshold)
            {
                this->uart->println(F("[ERROR] Not enough memory to start processing the response."));
                http.end();
                return false;
            }

            // Start timeout timer
            unsigned long timeoutStart = millis();
            const unsigned long timeoutInterval = 2000; // 2 seconds

            // Stream data while connected and available
            while (http.connected() && (len > 0 || len == -1))
            {
                size_t size = stream->available();
                if (size)
                {
                    // Reset the timeout when new data comes in
                    timeoutStart = millis();

                    int c = stream->readBytes(buff, ((size > sizeof(buff)) ? sizeof(buff) : size));
                    this->uart->write(buff, c); // Write data to serial
                    if (len > 0)
                    {
                        len -= c;
                    }
                }
                else
                {
                    // Check if timeout has been reached
                    if (millis() - timeoutStart > timeoutInterval)
                    {
                        break;
                    }
                }
                delay(1); // Yield control to the system
            }
            freeHeap = commonGetFreeHeap(); // Check available heap memory after processing
            if (freeHeap < minHeapThreshold)
            {
                this->uart->println(F("[ERROR] Not enough memory to continue processing the response."));
                http.end();
                return false;
            }

            http.end();
            // Flush the serial buffer to ensure all data is sent
            this->uart->flush();
            this->uart->println();
            if (strcmp(method, "GET") == 0)
            {
                this->uart->println(F("[GET/END]"));
            }
            else
            {
                this->uart->println(F("[POST/END]"));
            }
            return true;
        }
        else
        {
            if (httpCode != -1) // HTTPC_ERROR_CONNECTION_FAILED
            {
                snprintf(headerResponse, sizeof(headerResponse), "[ERROR] %s Request Failed, error: %s", method, http.errorToString(httpCode).c_str());
                this->uart->println(headerResponse);
            }
            else // certification failed?
            {
                // Send request without SSL
                http.end();
                this->client->setInsecure();
                if (http.begin(*this->client, url))
                {
                    for (int i = 0; i < headerSize; i++)
                    {
                        http.addHeader(headerKeys[i], headerValues[i]);
                    }
                    int newCode = http.sendRequest(method, payload);
                    int len = http.getSize(); // Get the response content length
                    if (newCode > 0)
                    {
                        snprintf(headerResponse, sizeof(headerResponse), "[%s/SUCCESS]{\"Status-Code\":%d,\"Content-Length\":%d}", method, newCode, len);
                        this->uart->println(headerResponse);
                        uint8_t buff[512] = {0}; // Buffer for reading data

                        WiFiClient *stream = http.getStreamPtr();

                        // Check available heap memory before starting
                        size_t freeHeap = commonGetFreeHeap();
                        if (freeHeap < 1024)
                        {
                            this->uart->println(F("[ERROR] Not enough memory to start processing the response."));
                            http.end();
                            this->client->setCACert(root_ca);
                            return false;
                        }

                        // Start timeout timer
                        unsigned long timeoutStart = millis();
                        const unsigned long timeoutInterval = 2000; // 2 seconds

                        // Stream data while connected and available
                        while (http.connected() && (len > 0 || len == -1))
                        {
                            size_t size = stream->available();
                            if (size)
                            {
                                // Reset the timeout when new data arrives
                                timeoutStart = millis();

                                int c = stream->readBytes(buff, ((size > sizeof(buff)) ? sizeof(buff) : size));
                                this->uart->write(buff, c); // Write data to serial
                                if (len > 0)
                                {
                                    len -= c;
                                }
                            }
                            else
                            {
                                // Check if timeout has been reached
                                if (millis() - timeoutStart > timeoutInterval)
                                {
                                    break;
                                }
                            }
                            delay(1); // Yield control to the system
                        }

                        freeHeap = commonGetFreeHeap(); // Check available heap memory after processing
                        if (freeHeap < 1024)
                        {
                            this->uart->println(F("[ERROR] Not enough memory to continue processing the response."));
                            http.end();
                            this->client->setCACert(root_ca);
                            return false;
                        }

                        http.end();
                        // Flush the serial buffer to ensure all data is sent
                        this->uart->flush();
                        this->uart->println();
                        if (strcmp(method, "GET") == 0)
                        {
                            this->uart->println(F("[GET/END]"));
                        }
                        else
                        {
                            this->uart->println(F("[POST/END]"));
                        }
                        this->client->setCACert(root_ca);
                        return true;
                    }
                    else
                    {
                        this->client->setCACert(root_ca);
                        snprintf(headerResponse, sizeof(headerResponse), "[ERROR] %s Request Failed, error: %s", method, http.errorToString(newCode).c_str());
                        this->uart->println(headerResponse);
                    }
                }
                this->client->setCACert(root_ca);
            }
        }
        http.end();
    }
    else
    {
        this->uart->println(F("[ERROR] Unable to connect to the server."));
    }
    return false;
}
#endif