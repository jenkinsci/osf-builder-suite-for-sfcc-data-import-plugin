package org.jenkinsci.plugins.osfbuildersuiteforsfcc.dataimport;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import hudson.AbortException;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.http.Consts;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.StatusLine;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.jenkinsci.plugins.osfbuildersuiteforsfcc.credentials.BusinessManagerAuthCredentials;
import org.jenkinsci.plugins.osfbuildersuiteforsfcc.credentials.OpenCommerceAPICredentials;

import java.io.IOException;
import java.net.URLEncoder;
import java.util.*;
import java.util.stream.Stream;

class OpenCommerceAPI {
    static Map<String, String> auth(
            CloseableHttpClient httpClient,
            String hostname,
            BusinessManagerAuthCredentials bmCredentials,
            OpenCommerceAPICredentials ocCredentials) throws IOException {

        List<NameValuePair> httpPostParams = new ArrayList<>();
        httpPostParams.add(new BasicNameValuePair(
                "grant_type", "urn:demandware:params:oauth:grant-type:client-id:dwsid:dwsecuretoken"
        ));

        RequestBuilder requestBuilder = RequestBuilder.create("POST");
        requestBuilder.setHeader("Authorization", String.format(
                "Basic %s",
                Base64.getEncoder().encodeToString(
                        String.format(
                                "%s:%s:%s",
                                bmCredentials.getUsername(),
                                bmCredentials.getPassword().getPlainText(),
                                ocCredentials.getClientPassword().getPlainText()
                        ).getBytes(Consts.UTF_8)
                )
        ));

        requestBuilder.setEntity(new UrlEncodedFormEntity(httpPostParams, Consts.UTF_8));
        requestBuilder.setUri(String.format(
                "https://%s/dw/oauth2/access_token?client_id=%s",
                hostname,
                URLEncoder.encode(ocCredentials.getClientId(), "UTF-8")
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

        String httpEntityString;

        try {
            httpEntityString = EntityUtils.toString(httpResponse.getEntity(), "UTF-8");
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

        if (httpStatusLine.getStatusCode() != HttpStatus.SC_OK) {
            throw new AbortException(String.format(
                    "\nFailed to authenticate with OCAPI! %s - %s!\nResponse=%s",
                    httpStatusLine.getStatusCode(),
                    httpStatusLine.getReasonPhrase(),
                    httpEntityString
            ));
        }

        JsonElement jsonElement;

        try {
            JsonParser jsonParser = new JsonParser();
            jsonElement = jsonParser.parse(httpEntityString);
        } catch (JsonParseException e) {
            AbortException abortException = new AbortException(String.format(
                    "\nException thrown while parsing OCAPI JSON response!\nResponse=%s\n%s",
                    httpEntityString,
                    ExceptionUtils.getStackTrace(e)
            ));
            abortException.initCause(e);
            throw abortException;
        }

        if (!jsonElement.isJsonObject()) {
            throw new AbortException(String.format(
                    "\nFailed to parse OCAPI JSON response!\nResponse=%s",
                    httpEntityString
            ));
        }

        JsonObject jsonObject = jsonElement.getAsJsonObject();
        boolean isValidJson = Stream.of("access_token", "token_type").allMatch(jsonObject::has);

        if (!isValidJson) {
            throw new AbortException(String.format(
                    "\nFailed to parse OCAPI JSON response!\nResponse=%s",
                    httpEntityString
            ));
        }

        Map<String, String> authResponseMap = new HashMap<>();
        authResponseMap.put("token_type", jsonObject.get("token_type").getAsString());
        authResponseMap.put("access_token", jsonObject.get("access_token").getAsString());
        return authResponseMap;
    }

    static Map<String, String> executeSiteArchiveImportJob(
            Map<String, String> authResponseMap,
            CloseableHttpClient httpClient,
            String hostname,
            String ocVersion,
            String archiveName,
            OpenCommerceAPICredentials ocCredentials) throws IOException {

        RequestBuilder requestBuilder = RequestBuilder.create("POST");
        requestBuilder.setHeader("Authorization", String.format(
                "%s %s",
                authResponseMap.get("token_type"),
                authResponseMap.get("access_token")
        ));

        JsonObject requestJson = new JsonObject();
        requestJson.addProperty("file_name", String.format("%s.zip", archiveName));
        requestJson.addProperty("mode", "merge");
        requestBuilder.setEntity(new StringEntity(requestJson.toString(), ContentType.APPLICATION_JSON));

        requestBuilder.setUri(String.format(
                "https://%s/s/-/dw/data/%s/jobs/sfcc-site-archive-import/executions?client_id=%s",
                hostname,
                URLEncoder.encode(ocVersion, "UTF-8"),
                URLEncoder.encode(ocCredentials.getClientId(), "UTF-8")
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

        String httpEntityString;

        try {
            httpEntityString = EntityUtils.toString(httpResponse.getEntity(), "UTF-8");
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

        JsonElement jsonElement;

        try {
            JsonParser jsonParser = new JsonParser();
            jsonElement = jsonParser.parse(httpEntityString);
        } catch (JsonParseException e) {
            AbortException abortException = new AbortException(String.format(
                    "\nException thrown while parsing OCAPI JSON response!\nResponse=%s\n%s",
                    httpEntityString,
                    ExceptionUtils.getStackTrace(e)
            ));
            abortException.initCause(e);
            throw abortException;
        }

        StatusLine httpStatusLine = httpResponse.getStatusLine();

        if (!Arrays.asList(HttpStatus.SC_OK, HttpStatus.SC_ACCEPTED).contains(httpStatusLine.getStatusCode())) {
            throw new AbortException(String.format(
                    "\nFailed to execute OCAPI data import job! %s - %s!\nResponse=%s",
                    httpStatusLine.getStatusCode(),
                    httpStatusLine.getReasonPhrase(),
                    httpEntityString
            ));
        }

        if (!jsonElement.isJsonObject()) {
            throw new AbortException(String.format(
                    "\nFailed to parse OCAPI execute data import job JSON response!\nResponse=%s",
                    httpEntityString
            ));
        }

        JsonObject jsonObject = jsonElement.getAsJsonObject();
        boolean isValidJson = Stream.of("execution_status", "id").allMatch(jsonObject::has);

        if (!isValidJson) {
            throw new AbortException(String.format(
                    "\nFailed to parse OCAPI execute data import job JSON response!\nResponse=%s",
                    httpEntityString
            ));
        }

        Map<String, String> executeJobResponseMap = new HashMap<>();
        executeJobResponseMap.put("execution_status", jsonObject.get("execution_status").getAsString());
        executeJobResponseMap.put("id", jsonObject.get("id").getAsString());
        return executeJobResponseMap;
    }

    static Map<String, String> checkSiteArchiveImportJob(
            Map<String, String> authResponseMap,
            CloseableHttpClient httpClient,
            String hostname,
            String ocVersion,
            String archiveName,
            String jobId,
            OpenCommerceAPICredentials ocCredentials) throws IOException {

        RequestBuilder requestBuilder = RequestBuilder.create("GET");
        requestBuilder.setHeader("Authorization", String.format(
                "%s %s",
                authResponseMap.get("token_type"),
                authResponseMap.get("access_token")
        ));

        requestBuilder.setUri(String.format(
                "https://%s/s/-/dw/data/%s/jobs/sfcc-site-archive-import/executions/%s?client_id=%s",
                hostname,
                URLEncoder.encode(ocVersion, "UTF-8"),
                URLEncoder.encode(jobId, "UTF-8"),
                URLEncoder.encode(ocCredentials.getClientId(), "UTF-8")
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

        String httpEntityString;

        try {
            httpEntityString = EntityUtils.toString(httpResponse.getEntity(), "UTF-8");
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

        JsonElement jsonElement;

        try {
            JsonParser jsonParser = new JsonParser();
            jsonElement = jsonParser.parse(httpEntityString);
        } catch (JsonParseException e) {
            AbortException abortException = new AbortException(String.format(
                    "\nException thrown while parsing OCAPI JSON response!\nResponse=%s\n%s",
                    httpEntityString,
                    ExceptionUtils.getStackTrace(e)
            ));
            abortException.initCause(e);
            throw abortException;
        }

        StatusLine httpStatusLine = httpResponse.getStatusLine();

        if (httpStatusLine.getStatusCode() != HttpStatus.SC_OK) {
            throw new AbortException(String.format(
                    "\nFailed to get OCAPI data import job status! %s - %s!\nResponse=%s",
                    httpStatusLine.getStatusCode(),
                    httpStatusLine.getReasonPhrase(),
                    httpEntityString
            ));
        }

        if (!jsonElement.isJsonObject()) {
            throw new AbortException(String.format(
                    "\nFailed to parse OCAPI get data import job JSON response!\nResponse=%s",
                    httpEntityString
            ));
        }

        JsonObject jsonObject = jsonElement.getAsJsonObject();
        if (!jsonObject.has("execution_status")) {
            throw new AbortException(String.format(
                    "\nFailed to parse OCAPI get data import job JSON response!\nResponse=%s",
                    httpEntityString
            ));
        }

        JsonElement jsonExecutionStatus = jsonObject.get("execution_status");
        String executionStatus = jsonExecutionStatus.getAsString();

        if (StringUtils.equalsIgnoreCase(executionStatus, "finished")) {
            if (!jsonObject.has("exit_status")) {
                throw new AbortException(String.format(
                        "\nFailed to parse OCAPI get data import job JSON response!\nResponse=%s",
                        httpEntityString
                ));
            }

            JsonElement exitStatusElement = jsonObject.get("exit_status");

            if (!exitStatusElement.isJsonObject()) {
                throw new AbortException(String.format(
                        "\nFailed to parse OCAPI get data import job JSON response!\nResponse=%s",
                        httpEntityString
                ));
            }

            JsonObject exitStatusObject = exitStatusElement.getAsJsonObject();

            JsonElement exitStatusStatusElement = exitStatusObject.get("status");
            String exitStatusStatus = exitStatusStatusElement.getAsString();

            if (!StringUtils.equalsIgnoreCase(exitStatusStatus, "ok")) {
                throw new AbortException(String.format(
                        "\nFailed to import %s.zip!\nResponse=%s",
                        archiveName,
                        httpEntityString
                ));
            }
        }

        Map<String, String> checkJobResponseMap = new HashMap<>();
        checkJobResponseMap.put("execution_status", jsonObject.get("execution_status").getAsString());
        return checkJobResponseMap;
    }
}
