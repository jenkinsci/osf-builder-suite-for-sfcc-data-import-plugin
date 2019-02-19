package org.jenkinsci.plugins.osfbuildersuiteforsfcc.dataimport;

import hudson.AbortException;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.http.HttpStatus;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.FileEntity;
import org.apache.http.impl.client.CloseableHttpClient;

import java.io.File;
import java.io.IOException;
import java.net.URLEncoder;
import java.util.Map;

class WebDAV {
    static void cleanupLeftoverData(
            Map<String, String> authResponseMap,
            CloseableHttpClient httpClient,
            String hostname,
            String path) throws IOException {

        RequestBuilder requestBuilder = RequestBuilder.create("DELETE");
        requestBuilder.setHeader("Authorization", String.format(
                "%s %s",
                authResponseMap.get("token_type"),
                authResponseMap.get("access_token")
        ));

        requestBuilder.setUri(String.format(
                "https://%s/on/demandware.servlet/webdav/Sites/Impex/src/instance/%s",
                hostname,
                URLEncoder.encode(path, "UTF-8")
        ));

        CloseableHttpResponse httpResponse;

        try {
            httpResponse = httpClient.execute(requestBuilder.build());
        } catch (IOException e) {
            AbortException abortException = new AbortException(String.format(
                    "\nException thrown while making HTTP request!\n%s",
                    ExceptionUtils.getStackTrace(e)
            ));
            abortException.initCause(e);
            throw abortException;
        }

        try {
            httpResponse.close();
        } catch (IOException e) {
            AbortException abortException = new AbortException(String.format(
                    "\nException thrown while making HTTP request!\n%s",
                    ExceptionUtils.getStackTrace(e)
            ));
            abortException.initCause(e);
            throw abortException;
        }

        StatusLine httpStatusLine = httpResponse.getStatusLine();

        if (httpStatusLine.getStatusCode() != HttpStatus.SC_NOT_FOUND) {
            if (httpStatusLine.getStatusCode() == HttpStatus.SC_UNAUTHORIZED) {
                throw new AbortException("\nInvalid username or password!");
            } else if (httpStatusLine.getStatusCode() != HttpStatus.SC_NO_CONTENT) {
                throw new AbortException(String.format(
                        "\n%s - %s!", httpStatusLine.getStatusCode(), httpStatusLine.getReasonPhrase()
                ));
            }
        }
    }

    static void uploadData(
            Map<String, String> authResponseMap,
            CloseableHttpClient httpClient,
            String hostname,
            File dataZip,
            String archiveName) throws IOException {

        RequestBuilder requestBuilder = RequestBuilder.create("PUT");
        requestBuilder.setHeader("Authorization", String.format(
                "%s %s",
                authResponseMap.get("token_type"),
                authResponseMap.get("access_token")
        ));

        requestBuilder.setEntity(new FileEntity(dataZip, ContentType.APPLICATION_OCTET_STREAM));
        requestBuilder.setUri(String.format(
                "https://%s/on/demandware.servlet/webdav/Sites/Impex/src/instance/%s.zip",
                hostname,
                URLEncoder.encode(archiveName, "UTF-8")
        ));

        CloseableHttpResponse httpResponse;

        try {
            httpResponse = httpClient.execute(requestBuilder.build());
        } catch (IOException e) {
            AbortException abortException = new AbortException(String.format(
                    "\nException thrown while making HTTP request!\n%s",
                    ExceptionUtils.getStackTrace(e)
            ));
            abortException.initCause(e);
            throw abortException;
        }

        try {
            httpResponse.close();
        } catch (IOException e) {
            AbortException abortException = new AbortException(String.format(
                    "\nException thrown while making HTTP request!\n%s",
                    ExceptionUtils.getStackTrace(e)
            ));
            abortException.initCause(e);
            throw abortException;
        }

        StatusLine httpStatusLine = httpResponse.getStatusLine();

        if (httpStatusLine.getStatusCode() != HttpStatus.SC_CREATED) {
            if (httpStatusLine.getStatusCode() == HttpStatus.SC_UNAUTHORIZED) {
                throw new AbortException("\nInvalid username or password!");
            } else {
                throw new AbortException(String.format(
                        "\n%s - %s!", httpStatusLine.getStatusCode(), httpStatusLine.getReasonPhrase()
                ));
            }
        }
    }
}