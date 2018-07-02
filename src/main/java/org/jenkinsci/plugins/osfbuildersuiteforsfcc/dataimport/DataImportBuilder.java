package org.jenkinsci.plugins.osfbuildersuiteforsfcc.dataimport;

import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.common.StandardCredentials;
import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.cloudbees.plugins.credentials.domains.URIRequirementBuilder;
import com.google.gson.*;
import hudson.*;
import hudson.model.*;
import hudson.model.queue.Tasks;
import hudson.remoting.VirtualChannel;
import hudson.security.ACL;
import hudson.tasks.Builder;
import hudson.tasks.BuildStepDescriptor;
import hudson.util.ListBoxModel;
import jenkins.MasterToSlaveFileCallable;
import jenkins.tasks.SimpleBuildStep;
import net.sf.json.JSONObject;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.http.*;
import org.apache.http.Header;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.NTCredentials;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.GzipDecompressingEntity;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.config.ConnectionConfig;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.FileEntity;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.*;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.SSLContexts;
import org.apache.http.util.EntityUtils;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.codehaus.plexus.util.MatchPattern;
import org.jenkinsci.Symbol;
import org.jenkinsci.plugins.osfbuildersuiteforsfcc.credentials.OpenCommerceAPICredentials;
import org.jenkinsci.plugins.osfbuildersuiteforsfcc.credentials.TwoFactorAuthCredentials;
import org.jenkinsci.plugins.osfbuildersuiteforsfcc.credentials.BusinessManagerAuthCredentials;
import org.jenkinsci.plugins.osfbuildersuiteforsfcc.dataimport.model.DataImportAction;
import org.jenkinsci.plugins.osfbuildersuiteforsfcc.dataimport.model.DataImportEnvAction;
import org.jenkinsci.plugins.osfbuildersuiteforsfcc.dataimport.repeatable.ExcludePattern;
import org.jenkinsci.plugins.tokenmacro.MacroEvaluationException;
import org.jenkinsci.plugins.tokenmacro.TokenMacro;
import org.kohsuke.stapler.*;
import org.zeroturnaround.zip.ZipUtil;

import javax.annotation.Nonnull;
import javax.net.ssl.SSLContext;
import java.io.*;
import java.net.URLEncoder;
import java.nio.file.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;


@SuppressWarnings("unused")
public class DataImportBuilder extends Builder implements SimpleBuildStep {

    private String hostname;
    private String bmCredentialsId;
    private String tfCredentialsId;
    private String ocCredentialsId;
    private String ocVersion;
    private String archiveName;
    private String sourcePath;
    private List<ExcludePattern> excludePatterns;
    private String importStrategy;
    private String tempDirectory;

    @DataBoundConstructor
    public DataImportBuilder(
            String hostname,
            String bmCredentialsId,
            String tfCredentialsId,
            String ocCredentialsId,
            String ocVersion,
            String archiveName,
            String sourcePath,
            List<ExcludePattern> excludePatterns,
            String importStrategy,
            String tempDirectory) {

        this.hostname = hostname;
        this.bmCredentialsId = bmCredentialsId;
        this.tfCredentialsId = tfCredentialsId;
        this.ocCredentialsId = ocCredentialsId;
        this.ocVersion = ocVersion;
        this.archiveName = archiveName;
        this.sourcePath = sourcePath;
        this.excludePatterns = excludePatterns;
        this.importStrategy = importStrategy;
        this.tempDirectory = tempDirectory;
    }

    @SuppressWarnings("unused")
    public String getHostname() {
        return hostname;
    }

    @SuppressWarnings("unused")
    @DataBoundSetter
    public void setHostname(String hostname) {
        this.hostname = hostname;
    }

    @SuppressWarnings("unused")
    public String getBmCredentialsId() {
        return bmCredentialsId;
    }

    @SuppressWarnings("unused")
    @DataBoundSetter
    public void setBmCredentialsId(String bmCredentialsId) {
        this.bmCredentialsId = StringUtils.trim(bmCredentialsId);
    }

    @SuppressWarnings("unused")
    public String getTfCredentialsId() {
        return tfCredentialsId;
    }

    @SuppressWarnings("unused")
    @DataBoundSetter
    public void setTfCredentialsId(String tfCredentialsId) {
        this.tfCredentialsId = StringUtils.trim(tfCredentialsId);
    }

    @SuppressWarnings("unused")
    public String getOcCredentialsId() {
        return ocCredentialsId;
    }

    @SuppressWarnings("unused")
    @DataBoundSetter
    public void setOcCredentialsId(String ocCredentialsId) {
        this.ocCredentialsId = ocCredentialsId;
    }

    @SuppressWarnings("unused")
    public String getOcVersion() {
        return ocVersion;
    }

    @SuppressWarnings("unused")
    @DataBoundSetter
    public void setOcVersion(String ocVersion) {
        this.ocVersion = ocVersion;
    }

    @SuppressWarnings("unused")
    public String getArchiveName() {
        return archiveName;
    }

    @SuppressWarnings("unused")
    @DataBoundSetter
    public void setArchiveName(String archiveName) {
        this.archiveName = archiveName;
    }

    @SuppressWarnings("unused")
    public String getSourcePath() {
        return sourcePath;
    }

    @SuppressWarnings("unused")
    @DataBoundSetter
    public void setSourcePath(String sourcePath) {
        this.sourcePath = sourcePath;
    }

    @SuppressWarnings("unused")
    public List<ExcludePattern> getExcludePatterns() {
        return excludePatterns;
    }

    @SuppressWarnings("unused")
    @DataBoundSetter
    public void setExcludePatterns(List<ExcludePattern> excludePatterns) {
        this.excludePatterns = excludePatterns;
    }

    @SuppressWarnings("unused")
    public String getImportStrategy() {
        return importStrategy;
    }

    @SuppressWarnings("unused")
    @DataBoundSetter
    public void setImportStrategy(String importStrategy) {
        this.importStrategy = importStrategy;
    }

    @SuppressWarnings("unused")
    public String getTempDirectory() {
        return tempDirectory;
    }

    @SuppressWarnings("unused")
    @DataBoundSetter
    public void setTempDirectory(String tempDirectory) {
        this.tempDirectory = tempDirectory;
    }

    @Override
    public void perform(
            @Nonnull Run<?, ?> build,
            @Nonnull FilePath workspace,
            @Nonnull Launcher launcher,
            @Nonnull TaskListener listener) throws InterruptedException, IOException {

        PrintStream logger = listener.getLogger();

        logger.println();
        logger.println(String.format("--[B: %s]--", getDescriptor().getDisplayName()));
        logger.println();

        String expandedHostname;
        try {
            expandedHostname = TokenMacro.expandAll(build, workspace, listener, hostname);
        } catch (MacroEvaluationException e) {
            AbortException abortException = new AbortException("Exception thrown while expanding the hostname!");
            abortException.initCause(e);
            throw abortException;
        }

        BusinessManagerAuthCredentials bmCredentials = null;
        if (StringUtils.isNotEmpty(bmCredentialsId)) {
            bmCredentials = com.cloudbees.plugins.credentials.CredentialsProvider.findCredentialById(
                    bmCredentialsId,
                    BusinessManagerAuthCredentials.class,
                    build, URIRequirementBuilder.create().build()
            );
        }

        if (bmCredentials != null) {
            com.cloudbees.plugins.credentials.CredentialsProvider.track(build, bmCredentials);
        }

        TwoFactorAuthCredentials tfCredentials = null;
        if (StringUtils.isNotEmpty(tfCredentialsId)) {
            tfCredentials = com.cloudbees.plugins.credentials.CredentialsProvider.findCredentialById(
                    tfCredentialsId,
                    TwoFactorAuthCredentials.class,
                    build, URIRequirementBuilder.create().build()
            );
        }

        if (tfCredentials != null) {
            com.cloudbees.plugins.credentials.CredentialsProvider.track(build, tfCredentials);
        }

        OpenCommerceAPICredentials ocCredentials = null;
        if (StringUtils.isNotEmpty(ocCredentialsId)) {
            ocCredentials = com.cloudbees.plugins.credentials.CredentialsProvider.findCredentialById(
                    ocCredentialsId,
                    OpenCommerceAPICredentials.class,
                    build, URIRequirementBuilder.create().build()
            );
        }

        if (ocCredentials != null) {
            com.cloudbees.plugins.credentials.CredentialsProvider.track(build, ocCredentials);
        }

        String expandedArchiveName;
        try {
            expandedArchiveName = TokenMacro.expandAll(build, workspace, listener, archiveName);
        } catch (MacroEvaluationException e) {
            AbortException abortException = new AbortException("Exception thrown while expanding the archive name!");
            abortException.initCause(e);
            throw abortException;
        }

        List<String> previousDataFingerprints = new ArrayList<>();
        Run<?, ?> previousBuild = build.getPreviousBuild();
        if (previousBuild != null) {
            previousBuild.getActions(DataImportAction.class).forEach(
                    (dataImportAction) -> previousDataFingerprints.addAll(dataImportAction.getDataFingerprints())
            );
        }

        DataImportResult dataImportResult = workspace.act(new DataImportCallable(
                workspace,
                listener,
                expandedHostname,
                bmCredentialsId,
                bmCredentials,
                tfCredentialsId,
                tfCredentials,
                ocCredentialsId,
                ocCredentials,
                ocVersion,
                expandedArchiveName,
                sourcePath,
                excludePatterns,
                importStrategy,
                tempDirectory,
                getDescriptor().getHttpProxyHost(),
                getDescriptor().getHttpProxyPort(),
                getDescriptor().getHttpProxyUsername(),
                getDescriptor().getHttpProxyPassword(),
                getDescriptor().getDisableSSLValidation(),
                previousDataFingerprints
        ));

        build.addAction(new DataImportAction(dataImportResult.getDataFingerprints()));
        build.addAction(new DataImportEnvAction(
                build.getActions(DataImportEnvAction.class).size(),
                dataImportResult.getStatus()
        ));

        logger.println();
        logger.println(String.format("--[E: %s]--", getDescriptor().getDisplayName()));
        logger.println();
    }

    @Override
    public DescriptorImpl getDescriptor() {
        return (DescriptorImpl) super.getDescriptor();
    }

    @Extension
    @Symbol("osfBuilderSuiteForSFCCDataImport")
    public static final class DescriptorImpl extends BuildStepDescriptor<Builder> {
        private String httpProxyHost;
        private String httpProxyPort;
        private String httpProxyUsername;
        private String httpProxyPassword;
        private Boolean disableSSLValidation;

        public DescriptorImpl() {
            load();
        }

        public String getDisplayName() {
            return "OSF Builder Suite For Salesforce Commerce Cloud :: Data Import";
        }

        public boolean isApplicable(Class<? extends AbstractProject> jobType) {
            return true;
        }

        @SuppressWarnings("unused")
        public ListBoxModel doFillBmCredentialsIdItems(
                @AncestorInPath Item context,
                @QueryParameter String credentialsId) {

            if (context == null || !context.hasPermission(Item.CONFIGURE)) {
                return new ListBoxModel();
            }

            return new StandardListBoxModel().includeEmptyValue().includeMatchingAs(
                    context instanceof hudson.model.Queue.Task
                            ? Tasks.getAuthenticationOf((hudson.model.Queue.Task) context)
                            : ACL.SYSTEM,
                    context,
                    StandardCredentials.class,
                    URIRequirementBuilder.create().build(),
                    CredentialsMatchers.instanceOf(BusinessManagerAuthCredentials.class)
            );
        }

        @SuppressWarnings("unused")
        public ListBoxModel doFillTfCredentialsIdItems(
                @AncestorInPath Item context,
                @QueryParameter String credentialsId) {

            if (context == null || !context.hasPermission(Item.CONFIGURE)) {
                return new ListBoxModel();
            }

            return new StandardListBoxModel().includeEmptyValue().includeMatchingAs(
                    context instanceof hudson.model.Queue.Task
                            ? Tasks.getAuthenticationOf((hudson.model.Queue.Task) context)
                            : ACL.SYSTEM,
                    context,
                    StandardCredentials.class,
                    URIRequirementBuilder.create().build(),
                    CredentialsMatchers.instanceOf(TwoFactorAuthCredentials.class)
            );
        }

        @SuppressWarnings("unused")
        public ListBoxModel doFillOcCredentialsIdItems(
                @AncestorInPath Item context,
                @QueryParameter String credentialsId) {

            if (context == null || !context.hasPermission(Item.CONFIGURE)) {
                return new ListBoxModel();
            }

            return new StandardListBoxModel().includeEmptyValue().includeMatchingAs(
                    context instanceof hudson.model.Queue.Task
                            ? Tasks.getAuthenticationOf((hudson.model.Queue.Task) context)
                            : ACL.SYSTEM,
                    context,
                    StandardCredentials.class,
                    URIRequirementBuilder.create().build(),
                    CredentialsMatchers.instanceOf(OpenCommerceAPICredentials.class)
            );
        }

        @SuppressWarnings("unused")
        public ListBoxModel doFillImportStrategyItems(
                @AncestorInPath Item context,
                @QueryParameter String credentialsId) {

            return new ListBoxModel(
                    new ListBoxModel.Option("Full", "FULL"),
                    new ListBoxModel.Option("Delta", "DELTA")
            );
        }

        @SuppressWarnings("WeakerAccess")
        public String getHttpProxyHost() {
            return httpProxyHost;
        }

        @SuppressWarnings({"WeakerAccess", "unused"})
        public void setHttpProxyHost(String httpProxyHost) {
            this.httpProxyHost = httpProxyHost;
        }

        @SuppressWarnings("WeakerAccess")
        public String getHttpProxyPort() {
            return httpProxyPort;
        }

        @SuppressWarnings({"WeakerAccess", "unused"})
        public void setHttpProxyPort(String httpProxyPort) {
            this.httpProxyPort = httpProxyPort;
        }

        @SuppressWarnings("WeakerAccess")
        public String getHttpProxyUsername() {
            return httpProxyUsername;
        }

        @SuppressWarnings({"WeakerAccess", "unused"})
        public void setHttpProxyUsername(String httpProxyUsername) {
            this.httpProxyUsername = httpProxyUsername;
        }

        @SuppressWarnings("WeakerAccess")
        public String getHttpProxyPassword() {
            return httpProxyPassword;
        }

        @SuppressWarnings({"WeakerAccess", "unused"})
        public void setHttpProxyPassword(String httpProxyPassword) {
            this.httpProxyPassword = httpProxyPassword;
        }

        @SuppressWarnings("WeakerAccess")
        public Boolean getDisableSSLValidation() {
            return disableSSLValidation;
        }

        @SuppressWarnings({"WeakerAccess", "unused"})
        public void setDisableSSLValidation(Boolean disableSSLValidation) {
            this.disableSSLValidation = disableSSLValidation;
        }

        @Override
        public boolean configure(StaplerRequest req, JSONObject formData) throws FormException {
            httpProxyHost = formData.getString("httpProxyHost");
            httpProxyPort = formData.getString("httpProxyPort");
            httpProxyUsername = formData.getString("httpProxyUsername");
            httpProxyPassword = formData.getString("httpProxyPassword");
            disableSSLValidation = formData.getBoolean("disableSSLValidation");

            save();

            return super.configure(req, formData);
        }
    }

    private static class DataImportCallable extends MasterToSlaveFileCallable<DataImportResult> {

        private static final long serialVersionUID = 1L;

        private final FilePath workspace;
        private final TaskListener listener;
        private final String hostname;
        private final String bmCredentialsId;
        private final BusinessManagerAuthCredentials bmCredentials;
        private final String tfCredentialsId;
        private final TwoFactorAuthCredentials tfCredentials;
        private final String ocCredentialsId;
        private final OpenCommerceAPICredentials ocCredentials;
        private final String ocVersion;
        private final String archiveName;
        private final String sourcePath;
        private final List<ExcludePattern> excludePatterns;
        private final String importStrategy;
        private final String tempDirectory;
        private final String httpProxyHost;
        private final String httpProxyPort;
        private final String httpProxyUsername;
        private final String httpProxyPassword;
        private final Boolean disableSSLValidation;
        private final List<String> previousDataFingerprints;

        @SuppressWarnings("WeakerAccess")
        public DataImportCallable(
                FilePath workspace,
                TaskListener listener,
                String hostname,
                String bmCredentialsId,
                BusinessManagerAuthCredentials bmCredentials,
                String tfCredentialsId,
                TwoFactorAuthCredentials tfCredentials,
                String ocCredentialsId,
                OpenCommerceAPICredentials ocCredentials,
                String ocVersion,
                String archiveName,
                String sourcePath,
                List<ExcludePattern> excludePatterns,
                String importStrategy,
                String tempDirectory,
                String httpProxyHost,
                String httpProxyPort,
                String httpProxyUsername,
                String httpProxyPassword,
                Boolean disableSSLValidation,
                List<String> previousDataFingerprints) {

            this.workspace = workspace;
            this.listener = listener;
            this.hostname = hostname;
            this.bmCredentialsId = bmCredentialsId;
            this.bmCredentials = bmCredentials;
            this.tfCredentialsId = tfCredentialsId;
            this.tfCredentials = tfCredentials;
            this.ocCredentialsId = ocCredentialsId;
            this.ocCredentials = ocCredentials;
            this.ocVersion = ocVersion;
            this.archiveName = archiveName;
            this.sourcePath = sourcePath;
            this.excludePatterns = excludePatterns;
            this.importStrategy = importStrategy;
            this.tempDirectory = tempDirectory;
            this.httpProxyHost = httpProxyHost;
            this.httpProxyPort = httpProxyPort;
            this.httpProxyUsername = httpProxyUsername;
            this.httpProxyPassword = httpProxyPassword;
            this.disableSSLValidation = disableSSLValidation;
            this.previousDataFingerprints = previousDataFingerprints;
        }

        @SuppressWarnings("ConstantConditions")
        @Override
        public DataImportResult invoke(File dir, VirtualChannel channel) throws IOException, InterruptedException {
            PrintStream logger = listener.getLogger();

            if (StringUtils.isEmpty(hostname)) {
                logger.println();
                throw new AbortException(
                        "Missing value for \"Instance Hostname\"!" + " " +
                                "What are we going to do with all the data if we don't have where to push it?"
                );
            }

            if (StringUtils.isEmpty(bmCredentialsId)) {
                logger.println();
                throw new AbortException(
                        "Missing \"Business Manager Credentials\"!" + " " +
                                "We can't push the data without proper credentials, can't we?"
                );
            }

            if (bmCredentials == null) {
                logger.println();
                throw new AbortException(
                        "Failed to load \"Business Manager Credentials\"!" + " " +
                                "Something's wrong but not sure who's blame it is..."
                );
            }

            if (StringUtils.isNotEmpty(tfCredentialsId)) {
                if (tfCredentials == null) {
                    logger.println();
                    throw new AbortException(
                            "Failed to load \"Two Factor Auth Credentials\"!" + " " +
                                    "Something's wrong but not sure who's blame it is..."
                    );
                } else if (StringUtils.isEmpty(StringUtils.trim(tfCredentials.getServerCertificate()))) {
                    logger.println();
                    throw new AbortException(
                            "Failed to load \"Two Factor Auth Credentials\"!" + " " +
                                    "Missing value for \"Server Certificate\"!"
                    );
                } else if (StringUtils.isEmpty(StringUtils.trim(tfCredentials.getClientCertificate()))) {
                    logger.println();
                    throw new AbortException(
                            "Failed to load \"Two Factor Auth Credentials\"!" + " " +
                                    "Missing value for \"Client Certificate\"!"
                    );
                } else if (StringUtils.isEmpty(StringUtils.trim(tfCredentials.getClientPrivateKey()))) {
                    logger.println();
                    throw new AbortException(
                            "Failed to load \"Two Factor Auth Credentials\"!" + " " +
                                    "Missing value for \"Client Private Key\"!"
                    );
                }
            }

            if (StringUtils.isEmpty(ocCredentialsId)) {
                logger.println();
                throw new AbortException(
                        "Missing \"Open Commerce API Credentials\"!" + " " +
                                "We can't import the data without proper credentials, can't we?"
                );
            }

            if (ocCredentials == null) {
                logger.println();
                throw new AbortException(
                        "Failed to load \"Open Commerce API Credentials\"!" + " " +
                                "Something's wrong but not sure who's blame it is..."
                );
            }

            if (StringUtils.isEmpty(ocVersion)) {
                logger.println();
                throw new AbortException(
                        "Missing \"Open Commerce API Version\"!" + " " +
                                "We can't use Open Commerce API without specifying a version, can't we?"
                );
            }

            if (StringUtils.isEmpty(archiveName)) {
                logger.println();
                throw new AbortException(
                        "Missing \"Archive Name\"!" + " " +
                                "We need a name for the data archive we're about to push!"
                );
            }

            Pattern validationArchiveNamePattern = Pattern.compile("^[a-z0-9_.]+$", Pattern.CASE_INSENSITIVE);
            Matcher validationArchiveNameMatcher = validationArchiveNamePattern.matcher(archiveName);

            if (!validationArchiveNameMatcher.matches()) {
                logger.println();
                throw new AbortException(
                        String.format("Invalid value \"%s\" for data archive name!", archiveName) + " " +
                                "Only alphanumeric, \"_\" and \".\" characters are allowed."
                );
            }

            if (StringUtils.isEmpty(sourcePath)) {
                logger.println();
                throw new AbortException(
                        "No \"Source\" defined!" + " " +
                                "We don't want to have an empty data archive, do we?"
                );
            }

            if (StringUtils.isEmpty(tempDirectory)) {
                logger.println();
                throw new AbortException(
                        "Missing \"Temp Directory\"!" + " " +
                                "We need a temporary place to store the data archive before we can push it!"
                );
            }

            @SuppressWarnings("UnnecessaryLocalVariable")
            File wDirectory = dir;
            File tDirectory = new File(wDirectory, tempDirectory);

            Path wDirectoryPath = wDirectory.toPath().normalize();
            Path tDirectoryPath = tDirectory.toPath().normalize();

            if (!tDirectoryPath.startsWith(wDirectoryPath)) {
                logger.println();
                throw new AbortException(
                        "Invalid value for \"Temp Directory\"! The path needs to be inside the workspace!"
                );
            }


            /* Setting up the temporary directory */
            logger.println("[+] Setting up the temporary directory");

            if (!tDirectory.exists()) {
                if (!tDirectory.mkdirs()) {
                    logger.println();
                    throw new AbortException(String.format("Failed to create %s!", tDirectory.getAbsolutePath()));
                }
            }

            File[] tDirectoryFiles = tDirectory.listFiles();
            if (tDirectoryFiles != null) {
                for (File tDirectoryFile : tDirectoryFiles) {
                    if (tDirectoryFile.isDirectory()) {
                        try {
                            FileUtils.deleteDirectory(tDirectoryFile);
                        } catch (IOException e) {
                            logger.println();
                            AbortException abortException = new AbortException(String.format(
                                    "Exception thrown while deleting \"%s\"!\n%s",
                                    tDirectoryFile.getAbsolutePath(),
                                    ExceptionUtils.getStackTrace(e)
                            ));
                            abortException.initCause(e);
                            throw abortException;
                        }
                    } else {
                        if (!tDirectoryFile.delete()) {
                            logger.println();
                            throw new AbortException(String.format(
                                    "Failed to delete \"%s\"!", tDirectoryFile.getAbsolutePath()
                            ));
                        }
                    }
                }
            }

            logger.println(" + Ok");
            /* Setting up the temporary directory */


            /* Creating ZIP archive of data to be imported */
            logger.println();
            logger.println(String.format("[+] Creating ZIP archive of data to be imported (%s.zip)", archiveName));

            Path pSourcePath = Paths.get(wDirectory.getAbsolutePath(), sourcePath).normalize();
            if (!pSourcePath.startsWith(wDirectoryPath)) {
                logger.println();
                throw new AbortException(
                        "Invalid value for \"Source Path\"! The path needs to be inside the workspace!"
                );
            }

            File dataSrc = pSourcePath.toFile();
            if (!dataSrc.exists()) {
                logger.println();
                throw new AbortException(
                        "Invalid value for \"Source Path\"!" + " " +
                                String.format("\"%s\" does not exist!", sourcePath)
                );
            }

            if (!dataSrc.isDirectory()) {
                logger.println();
                throw new AbortException(
                        "Invalid value for \"Source Path\"!" + " " +
                                String.format("\"%s\" is not a directory!", sourcePath)
                );
            }

            File dataZip = new File(tDirectory, String.format("%s.zip", archiveName));
            if (dataZip.exists()) {
                logger.println();
                throw new AbortException(
                        "Failed to create ZIP archive of data to be imported!" + " " +
                                String.format("\"%s.zip\" already exists!", dataZip)
                );
            }

            List<MatchPattern> excludePatternsList = new ArrayList<>();
            if (excludePatterns != null) {
                excludePatternsList.addAll(excludePatterns.stream()
                        .map(ExcludePattern::getExcludePattern)
                        .filter(StringUtils::isNotEmpty)
                        .map((p) -> MatchPattern.fromString("%ant[" + File.separator + p + "]"))
                        .collect(Collectors.toList())
                );
            }

            List<String> currentDataFingerprints = new ArrayList<>();

            ZipUtil.pack(dataSrc, dataZip, (path) -> {
                Boolean excludeFile = excludePatternsList.stream().anyMatch(
                        (pattern) -> pattern.matchPath(File.separator + path, true)
                );

                if (excludeFile) {
                    return null;
                }

                File currentFile = new File(dataSrc, path);
                if (!currentFile.isDirectory()) {
                    try (InputStream inputStream = new FileInputStream(currentFile)) {
                        String dataFingerprint = String.format(
                                "%s:%s:%s",
                                DigestUtils.sha1Hex(inputStream),
                                dataSrc.getName(),
                                path
                        );

                        currentDataFingerprints.add(dataFingerprint);

                        if (StringUtils.equals(importStrategy, "DELTA")) {
                            if (previousDataFingerprints.contains(dataFingerprint)) {
                                return null;
                            }
                        }
                    } catch (IOException ignored) {

                    }
                }

                return archiveName + "/" + path;
            });

            logger.println(" + Ok");
            /* Creating ZIP archive of data to be imported */


            /* Checking if data import is needed */
            logger.println();
            logger.println("[+] Checking if data import is needed");

            List<String> dataZipFiles = new ArrayList<>();
            ZipUtil.iterate(dataZip, (zipEntry) -> dataZipFiles.add(zipEntry.getName()));

            if (dataZipFiles.isEmpty()) {
                if (StringUtils.equals(importStrategy, "DELTA")) {
                    logger.println(
                            " + Ok (data has not been changed since previous build so we'll skip the import this time)"
                    );
                } else {
                    logger.println(
                            " + Ok (nothing to import so we'll skip the import this time)"
                    );
                }

                return new DataImportResult(currentDataFingerprints, "SKIPPED");
            } else {
                if (StringUtils.equals(importStrategy, "DELTA")) {
                    dataZipFiles.forEach((dataZipFile) -> logger.println(String.format(" - %s", dataZipFile)));
                    logger.println(
                            " + Ok (proceeding with DELTA import)"
                    );
                } else {
                    logger.println(
                            " + Ok (proceeding with FULL import)"
                    );
                }
            }
            /* Checking if data import is needed */


            /* Setup HTTP Client */
            HttpClientBuilder httpClientBuilder = HttpClients.custom();
            httpClientBuilder.setUserAgent("Jenkins (OSF Builder Suite For Salesforce Commerce Cloud :: Data Import)");
            httpClientBuilder.setDefaultCookieStore(new BasicCookieStore());

            httpClientBuilder.addInterceptorFirst((HttpRequestInterceptor) (request, context) -> {
                if (!request.containsHeader("Accept-Encoding")) {
                    request.addHeader("Accept-Encoding", "gzip");
                }
            });

            httpClientBuilder.addInterceptorFirst((HttpResponseInterceptor) (response, context) -> {
                HttpEntity entity = response.getEntity();
                if (entity != null) {
                    Header header = entity.getContentEncoding();
                    if (header != null) {
                        for (HeaderElement headerElement : header.getElements()) {
                            if (headerElement.getName().equalsIgnoreCase("gzip")) {
                                response.setEntity(new GzipDecompressingEntity(response.getEntity()));
                                return;
                            }
                        }
                    }
                }
            });

            httpClientBuilder.setDefaultConnectionConfig(ConnectionConfig.custom()
                    .setBufferSize(5242880 /* 5 MegaBytes */)
                    .setFragmentSizeHint(5242880 /* 5 MegaBytes */)
                    .build()
            );

            httpClientBuilder.setDefaultRequestConfig(RequestConfig.custom()
                    .setSocketTimeout(300000 /* 5 minutes */)
                    .setConnectTimeout(300000 /* 5 minutes */)
                    .setConnectionRequestTimeout(300000 /* 5 minutes */)
                    .build()
            );

            org.apache.http.client.CredentialsProvider httpCredentialsProvider = new BasicCredentialsProvider();

            // Proxy Auth
            if (StringUtils.isNotEmpty(httpProxyHost) && StringUtils.isNotEmpty(httpProxyPort)) {
                Integer httpProxyPortInteger;

                try {
                    httpProxyPortInteger = Integer.valueOf(httpProxyPort);
                } catch (NumberFormatException e) {
                    logger.println();
                    throw new AbortException(
                            String.format("Invalid value \"%s\" for HTTP proxy port!", httpProxyPort) + " " +
                                    "Please enter a valid port number."
                    );
                }

                if (httpProxyPortInteger <= 0 || httpProxyPortInteger > 65535) {
                    logger.println();
                    throw new AbortException(
                            String.format("Invalid value \"%s\" for HTTP proxy port!", httpProxyPort) + " " +
                                    "Please enter a valid port number."
                    );
                }

                HttpHost httpClientProxy = new HttpHost(httpProxyHost, httpProxyPortInteger);
                httpClientBuilder.setProxy(httpClientProxy);

                if (StringUtils.isNotEmpty(httpProxyUsername) && StringUtils.isNotEmpty(httpProxyPassword)) {
                    if (httpProxyUsername.contains("\\")) {
                        String domain = httpProxyUsername.substring(0, httpProxyUsername.indexOf("\\"));
                        String user = httpProxyUsername.substring(httpProxyUsername.indexOf("\\") + 1);

                        httpCredentialsProvider.setCredentials(
                                new AuthScope(httpProxyHost, httpProxyPortInteger),
                                new NTCredentials(user, httpProxyPassword, "", domain)
                        );
                    } else {
                        httpCredentialsProvider.setCredentials(
                                new AuthScope(httpProxyHost, httpProxyPortInteger),
                                new UsernamePasswordCredentials(httpProxyUsername, httpProxyPassword)
                        );
                    }
                }
            }

            httpClientBuilder.setDefaultCredentialsProvider(httpCredentialsProvider);

            // WebDAV Auth
            String bmAuthHeaderValue = String.format("Basic %s", Base64.getEncoder().encodeToString(String.format(
                    "%s:%s",
                    bmCredentials.getUsername(),
                    bmCredentials.getPassword().getPlainText()
            ).getBytes(Consts.UTF_8)));

            // OCAPI Auth
            String ocAuthHeaderValue = String.format("Basic %s", Base64.getEncoder().encodeToString(String.format(
                    "%s:%s:%s",
                    bmCredentials.getUsername(),
                    bmCredentials.getPassword().getPlainText(),
                    ocCredentials.getClientPassword()
            ).getBytes(Consts.UTF_8)));

            SSLContextBuilder sslContextBuilder = SSLContexts.custom();

            if (tfCredentials != null) {
                Provider bouncyCastleProvider = new BouncyCastleProvider();

                // Server Certificate
                Reader serverCertificateReader = new StringReader(tfCredentials.getServerCertificate());
                PEMParser serverCertificateParser = new PEMParser(serverCertificateReader);

                JcaX509CertificateConverter serverCertificateConverter = new JcaX509CertificateConverter();
                serverCertificateConverter.setProvider(bouncyCastleProvider);

                X509Certificate serverCertificate;

                try {
                    serverCertificate = serverCertificateConverter.getCertificate(
                            (X509CertificateHolder) serverCertificateParser.readObject()
                    );
                } catch (CertificateException | IOException e) {
                    logger.println();
                    AbortException abortException = new AbortException(String.format(
                            "Exception thrown while loading two factor auth server certificate!\n%s",
                            ExceptionUtils.getStackTrace(e)
                    ));
                    abortException.initCause(e);
                    throw abortException;
                }

                try {
                    serverCertificate.checkValidity();
                } catch (CertificateExpiredException e) {
                    logger.println();
                    AbortException abortException = new AbortException(String.format(
                            "The server certificate used for two factor auth is expired!\n%s",
                            ExceptionUtils.getStackTrace(e)
                    ));
                    abortException.initCause(e);
                    throw abortException;
                } catch (CertificateNotYetValidException e) {
                    logger.println();
                    AbortException abortException = new AbortException(String.format(
                            "The server certificate used for two factor auth is not yet valid!\n%s",
                            ExceptionUtils.getStackTrace(e)
                    ));
                    abortException.initCause(e);
                    throw abortException;
                }

                // Client Certificate
                Reader clientCertificateReader = new StringReader(tfCredentials.getClientCertificate());
                PEMParser clientCertificateParser = new PEMParser(clientCertificateReader);

                JcaX509CertificateConverter clientCertificateConverter = new JcaX509CertificateConverter();
                clientCertificateConverter.setProvider(bouncyCastleProvider);

                X509Certificate clientCertificate;

                try {
                    clientCertificate = clientCertificateConverter.getCertificate(
                            (X509CertificateHolder) clientCertificateParser.readObject()
                    );
                } catch (CertificateException | IOException e) {
                    logger.println();
                    AbortException abortException = new AbortException(String.format(
                            "Exception thrown while loading two factor auth client certificate!\n%s",
                            ExceptionUtils.getStackTrace(e)
                    ));
                    abortException.initCause(e);
                    throw abortException;
                }

                try {
                    clientCertificate.checkValidity();
                } catch (CertificateExpiredException e) {
                    logger.println();
                    AbortException abortException = new AbortException(String.format(
                            "The client certificate used for two factor auth is expired!\n%s",
                            ExceptionUtils.getStackTrace(e)
                    ));
                    abortException.initCause(e);
                    throw abortException;
                } catch (CertificateNotYetValidException e) {
                    logger.println();
                    AbortException abortException = new AbortException(String.format(
                            "The client certificate used for two factor auth is not yet valid!\n%s",
                            ExceptionUtils.getStackTrace(e)
                    ));
                    abortException.initCause(e);
                    throw abortException;
                }

                // Client Private Key
                Reader clientPrivateKeyReader = new StringReader(tfCredentials.getClientPrivateKey());
                PEMParser clientPrivateKeyParser = new PEMParser(clientPrivateKeyReader);

                Object clientPrivateKeyObject;

                try {
                    clientPrivateKeyObject = clientPrivateKeyParser.readObject();
                } catch (IOException e) {
                    logger.println();
                    AbortException abortException = new AbortException(String.format(
                            "Exception thrown while loading two factor auth client private key!\n%s",
                            ExceptionUtils.getStackTrace(e)
                    ));
                    abortException.initCause(e);
                    throw abortException;
                }

                PrivateKeyInfo clientPrivateKeyInfo;

                if (clientPrivateKeyObject instanceof PrivateKeyInfo) {
                    clientPrivateKeyInfo = (PrivateKeyInfo) clientPrivateKeyObject;
                } else if (clientPrivateKeyObject instanceof PEMKeyPair) {
                    clientPrivateKeyInfo = ((PEMKeyPair) clientPrivateKeyObject).getPrivateKeyInfo();
                } else {
                    logger.println();
                    throw new AbortException("Failed to load two factor auth client private key!");
                }

                // Trust Store
                KeyStore customTrustStore;

                try {
                    customTrustStore = KeyStore.getInstance(KeyStore.getDefaultType());
                } catch (KeyStoreException e) {
                    logger.println();
                    AbortException abortException = new AbortException(String.format(
                            "Exception thrown while setting up the custom trust store!\n%s",
                            ExceptionUtils.getStackTrace(e)
                    ));
                    abortException.initCause(e);
                    throw abortException;
                }

                try {
                    customTrustStore.load(null, null);
                } catch (IOException | NoSuchAlgorithmException | CertificateException e) {
                    logger.println();
                    AbortException abortException = new AbortException(String.format(
                            "Exception thrown while setting up the custom trust store!\n%s",
                            ExceptionUtils.getStackTrace(e)
                    ));
                    abortException.initCause(e);
                    throw abortException;
                }

                try {
                    customTrustStore.setCertificateEntry(hostname, serverCertificate);
                } catch (KeyStoreException e) {
                    logger.println();
                    AbortException abortException = new AbortException(String.format(
                            "Exception thrown while setting up the custom trust store!\n%s",
                            ExceptionUtils.getStackTrace(e)
                    ));
                    abortException.initCause(e);
                    throw abortException;
                }

                try {
                    sslContextBuilder.loadTrustMaterial(customTrustStore, null);
                } catch (NoSuchAlgorithmException | KeyStoreException e) {
                    logger.println();
                    AbortException abortException = new AbortException(String.format(
                            "Exception thrown while setting up the custom trust store!\n%s",
                            ExceptionUtils.getStackTrace(e)
                    ));
                    abortException.initCause(e);
                    throw abortException;
                }

                // Key Store
                KeyFactory customKeyStoreKeyFactory;

                try {
                    customKeyStoreKeyFactory = KeyFactory.getInstance("RSA");
                } catch (NoSuchAlgorithmException e) {
                    logger.println();
                    AbortException abortException = new AbortException(String.format(
                            "Exception thrown while setting up the custom key store!\n%s",
                            ExceptionUtils.getStackTrace(e)
                    ));
                    abortException.initCause(e);
                    throw abortException;
                }

                PrivateKey customKeyStorePrivateKey;

                try {
                    customKeyStorePrivateKey = customKeyStoreKeyFactory.generatePrivate(
                            new PKCS8EncodedKeySpec(clientPrivateKeyInfo.getEncoded())
                    );
                } catch (InvalidKeySpecException | IOException e) {
                    logger.println();
                    AbortException abortException = new AbortException(String.format(
                            "Exception thrown while setting up the custom key store!\n%s",
                            ExceptionUtils.getStackTrace(e)
                    ));
                    abortException.initCause(e);
                    throw abortException;
                }

                KeyStore customKeyStore;

                try {
                    customKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
                } catch (KeyStoreException e) {
                    logger.println();
                    AbortException abortException = new AbortException(String.format(
                            "Exception thrown while setting up the custom key store!\n%s",
                            ExceptionUtils.getStackTrace(e)
                    ));
                    abortException.initCause(e);
                    throw abortException;
                }

                try {
                    customKeyStore.load(null, null);
                } catch (IOException | NoSuchAlgorithmException | CertificateException e) {
                    logger.println();
                    AbortException abortException = new AbortException(String.format(
                            "Exception thrown while setting up the custom key store!\n%s",
                            ExceptionUtils.getStackTrace(e)
                    ));
                    abortException.initCause(e);
                    throw abortException;
                }

                char[] keyStorePassword = RandomStringUtils.randomAscii(32).toCharArray();

                try {
                    customKeyStore.setKeyEntry(
                            hostname, customKeyStorePrivateKey, keyStorePassword,
                            new X509Certificate[]{clientCertificate, serverCertificate}
                    );
                } catch (KeyStoreException e) {
                    logger.println();
                    AbortException abortException = new AbortException(String.format(
                            "Exception thrown while setting up the custom key store!\n%s",
                            ExceptionUtils.getStackTrace(e)
                    ));
                    abortException.initCause(e);
                    throw abortException;
                }

                try {
                    sslContextBuilder.loadKeyMaterial(customKeyStore, keyStorePassword);
                } catch (NoSuchAlgorithmException | KeyStoreException | UnrecoverableKeyException e) {
                    logger.println();
                    AbortException abortException = new AbortException(String.format(
                            "Exception thrown while setting up the custom key store!\n%s",
                            ExceptionUtils.getStackTrace(e)
                    ));
                    abortException.initCause(e);
                    throw abortException;
                }
            }

            if (disableSSLValidation != null && disableSSLValidation) {
                try {
                    sslContextBuilder.loadTrustMaterial(null, (TrustStrategy) (arg0, arg1) -> true);
                } catch (NoSuchAlgorithmException | KeyStoreException e) {
                    logger.println();
                    AbortException abortException = new AbortException(String.format(
                            "Exception thrown while setting up the custom key store!\n%s",
                            ExceptionUtils.getStackTrace(e)
                    ));
                    abortException.initCause(e);
                    throw abortException;
                }
            }

            SSLContext customSSLContext;

            try {
                customSSLContext = sslContextBuilder.build();
            } catch (NoSuchAlgorithmException | KeyManagementException e) {
                logger.println();
                AbortException abortException = new AbortException(String.format(
                        "Exception thrown while creating custom SSL context!\n%s",
                        ExceptionUtils.getStackTrace(e)
                ));
                abortException.initCause(e);
                throw abortException;
            }

            if (disableSSLValidation != null && disableSSLValidation) {
                httpClientBuilder.setSSLSocketFactory(
                        new SSLConnectionSocketFactory(
                                customSSLContext, NoopHostnameVerifier.INSTANCE
                        )
                );
            } else {
                httpClientBuilder.setSSLSocketFactory(
                        new SSLConnectionSocketFactory(
                                customSSLContext, SSLConnectionSocketFactory.getDefaultHostnameVerifier()
                        )
                );
            }

            CloseableHttpClient httpClient = httpClientBuilder.build();
            /* Setup HTTP Client */


            /* Cleaning up leftover data from previous data import */
            logger.println();
            logger.println("[+] Cleaning up leftover data from previous data import");

            for (String rmPath : Arrays.asList(archiveName, String.format("%s.zip", archiveName))) {
                RequestBuilder rmRequestBuilder = RequestBuilder.create("DELETE");
                rmRequestBuilder.setHeader("Authorization", bmAuthHeaderValue);
                rmRequestBuilder.setUri(String.format(
                        "https://%s/on/demandware.servlet/webdav/Sites/Impex/src/instance/%s",
                        hostname, rmPath
                ));

                CloseableHttpResponse rmHttpResponse;

                try {
                    rmHttpResponse = httpClient.execute(rmRequestBuilder.build());
                } catch (IOException e) {
                    logger.println();
                    AbortException abortException = new AbortException(String.format(
                            "Exception thrown while making HTTP request!\n%s",
                            ExceptionUtils.getStackTrace(e)
                    ));
                    abortException.initCause(e);
                    throw abortException;
                }

                try {
                    rmHttpResponse.close();
                } catch (IOException e) {
                    logger.println();
                    AbortException abortException = new AbortException(String.format(
                            "Exception thrown while making HTTP request!\n%s",
                            ExceptionUtils.getStackTrace(e)
                    ));
                    abortException.initCause(e);
                    throw abortException;
                }

                StatusLine rmHttpStatusLine = rmHttpResponse.getStatusLine();

                if (rmHttpStatusLine.getStatusCode() != HttpStatus.SC_NOT_FOUND) {
                    if (rmHttpStatusLine.getStatusCode() == HttpStatus.SC_UNAUTHORIZED) {
                        logger.println();
                        throw new AbortException("Invalid username or password!");
                    } else if (rmHttpStatusLine.getStatusCode() == HttpStatus.SC_NO_CONTENT) {
                        logger.println(String.format(" - %s", rmPath));
                    } else {
                        logger.println();
                        throw new AbortException(String.format(
                                "%s - %s!", rmHttpStatusLine.getStatusCode(), rmHttpStatusLine.getReasonPhrase()
                        ));
                    }
                }
            }

            logger.println(" + Ok");
            /* Cleaning up leftover data from previous data import */


            /* Uploading data */
            logger.println();
            logger.println(String.format("[+] Uploading data (%s.zip)", archiveName));

            RequestBuilder upRequestBuilder = RequestBuilder.create("PUT");
            upRequestBuilder.setHeader("Authorization", bmAuthHeaderValue);
            upRequestBuilder.setEntity(new FileEntity(dataZip, ContentType.APPLICATION_OCTET_STREAM));
            upRequestBuilder.setUri(String.format(
                    "https://%s/on/demandware.servlet/webdav/Sites/Impex/src/instance/%s.zip",
                    hostname, archiveName
            ));

            CloseableHttpResponse upHttpResponse;

            try {
                upHttpResponse = httpClient.execute(upRequestBuilder.build());
            } catch (IOException e) {
                logger.println();
                AbortException abortException = new AbortException(String.format(
                        "Exception thrown while making HTTP request!\n%s",
                        ExceptionUtils.getStackTrace(e)
                ));
                abortException.initCause(e);
                throw abortException;
            }

            try {
                upHttpResponse.close();
            } catch (IOException e) {
                logger.println();
                AbortException abortException = new AbortException(String.format(
                        "Exception thrown while making HTTP request!\n%s",
                        ExceptionUtils.getStackTrace(e)
                ));
                abortException.initCause(e);
                throw abortException;
            }

            StatusLine upHttpStatusLine = upHttpResponse.getStatusLine();

            if (upHttpStatusLine.getStatusCode() != HttpStatus.SC_CREATED) {
                if (upHttpStatusLine.getStatusCode() == HttpStatus.SC_UNAUTHORIZED) {
                    logger.println();
                    throw new AbortException("Invalid username or password!");
                } else {
                    logger.println();
                    throw new AbortException(String.format(
                            "%s - %s!", upHttpStatusLine.getStatusCode(), upHttpStatusLine.getReasonPhrase()
                    ));
                }
            }

            logger.println(" + Ok");
            /* Uploading data */


            /* Importing data */
            logger.println();
            logger.println(String.format("[+] Importing data (%s.zip)", archiveName));

            List<NameValuePair> oaHttpPostParams = new ArrayList<>();
            oaHttpPostParams.add(new BasicNameValuePair(
                    "grant_type", "urn:demandware:params:oauth:grant-type:client-id:dwsid:dwsecuretoken"
            ));

            RequestBuilder oaRequestBuilder = RequestBuilder.create("POST");
            oaRequestBuilder.setHeader("Authorization", ocAuthHeaderValue);
            oaRequestBuilder.setEntity(new UrlEncodedFormEntity(oaHttpPostParams, Consts.UTF_8));
            oaRequestBuilder.setUri(String.format(
                    "https://%s/dw/oauth2/access_token?client_id=%s",
                    hostname, URLEncoder.encode(ocCredentials.getClientId(), "UTF-8")
            ));

            CloseableHttpResponse oaHttpResponse;

            try {
                oaHttpResponse = httpClient.execute(oaRequestBuilder.build());
            } catch (IOException e) {
                logger.println();
                AbortException abortException = new AbortException(String.format(
                        "Exception thrown while making HTTP request!\n%s",
                        ExceptionUtils.getStackTrace(e)
                ));
                abortException.initCause(e);
                throw abortException;
            }

            String oaHttpEntityString;

            try {
                oaHttpEntityString = EntityUtils.toString(oaHttpResponse.getEntity(), "UTF-8");
            } catch (IOException e) {
                logger.println();
                AbortException abortException = new AbortException(String.format(
                        "Exception thrown while making HTTP request!\n%s",
                        ExceptionUtils.getStackTrace(e)
                ));
                abortException.initCause(e);
                throw abortException;
            }

            try {
                oaHttpResponse.close();
            } catch (IOException e) {
                logger.println();
                AbortException abortException = new AbortException(String.format(
                        "Exception thrown while making HTTP request!\n%s",
                        ExceptionUtils.getStackTrace(e)
                ));
                abortException.initCause(e);
                throw abortException;
            }

            JsonElement oaJsonElement;

            try {
                JsonParser oaJsonParser = new JsonParser();
                oaJsonElement = oaJsonParser.parse(oaHttpEntityString);
            } catch (JsonParseException e) {
                logger.println();
                AbortException abortException = new AbortException(String.format(
                        "Exception thrown while parsing OCAPI JSON response!\nResponse=%s\n%s",
                        oaHttpEntityString,
                        ExceptionUtils.getStackTrace(e)
                ));
                abortException.initCause(e);
                throw abortException;
            }

            StatusLine oaHttpStatusLine = oaHttpResponse.getStatusLine();

            if (oaHttpStatusLine.getStatusCode() != HttpStatus.SC_OK) {
                logger.println();
                throw new AbortException(String.format(
                        "Failed to authenticate with OCAPI! %s - %s!\nResponse=%s",
                        oaHttpStatusLine.getStatusCode(),
                        oaHttpStatusLine.getReasonPhrase(),
                        oaHttpEntityString
                ));
            }

            if (!oaJsonElement.isJsonObject()) {
                logger.println();
                throw new AbortException(String.format(
                        "Failed to parse OCAPI JSON response!\nResponse=%s",
                        oaHttpEntityString
                ));
            }

            JsonObject oaJsonObject = oaJsonElement.getAsJsonObject();
            Boolean oaValidJson = Stream.of("access_token", "token_type").allMatch(oaJsonObject::has);

            if (!oaValidJson) {
                logger.println();
                throw new AbortException(String.format(
                        "Failed to parse OCAPI JSON response!\nResponse=%s",
                        oaHttpEntityString
                ));
            }

            JsonElement oaJsonTokenType = oaJsonObject.get("token_type");
            JsonElement oaJsonAccessToken = oaJsonObject.get("access_token");

            RequestBuilder rjRequestBuilder = RequestBuilder.create("POST");
            rjRequestBuilder.setHeader("Authorization", String.format(
                    "%s %s",
                    oaJsonTokenType.getAsString(),
                    oaJsonAccessToken.getAsString()
            ));

            JsonObject rjRequestJson = new JsonObject();
            rjRequestJson.addProperty("file_name", String.format("%s.zip", archiveName));
            rjRequestJson.addProperty("mode", "merge");
            rjRequestBuilder.setEntity(new StringEntity(rjRequestJson.toString(), ContentType.APPLICATION_JSON));

            rjRequestBuilder.setUri(String.format(
                    "https://%s/s/-/dw/data/%s/jobs/sfcc-site-archive-import/executions?client_id=%s",
                    hostname,
                    URLEncoder.encode(ocVersion, "UTF-8"),
                    URLEncoder.encode(ocCredentials.getClientId(), "UTF-8")
            ));

            CloseableHttpResponse rjHttpResponse;

            try {
                rjHttpResponse = httpClient.execute(rjRequestBuilder.build());
            } catch (IOException e) {
                logger.println();
                AbortException abortException = new AbortException(String.format(
                        "Exception thrown while making HTTP request!\n%s",
                        ExceptionUtils.getStackTrace(e)
                ));
                abortException.initCause(e);
                throw abortException;
            }

            String rjHttpEntityString;

            try {
                rjHttpEntityString = EntityUtils.toString(rjHttpResponse.getEntity(), "UTF-8");
            } catch (IOException e) {
                logger.println();
                AbortException abortException = new AbortException(String.format(
                        "Exception thrown while making HTTP request!\n%s",
                        ExceptionUtils.getStackTrace(e)
                ));
                abortException.initCause(e);
                throw abortException;
            }

            try {
                rjHttpResponse.close();
            } catch (IOException e) {
                logger.println();
                AbortException abortException = new AbortException(String.format(
                        "Exception thrown while making HTTP request!\n%s",
                        ExceptionUtils.getStackTrace(e)
                ));
                abortException.initCause(e);
                throw abortException;
            }

            JsonElement rjJsonElement;

            try {
                JsonParser rjJsonParser = new JsonParser();
                rjJsonElement = rjJsonParser.parse(rjHttpEntityString);
            } catch (JsonParseException e) {
                logger.println();
                AbortException abortException = new AbortException(String.format(
                        "Exception thrown while parsing OCAPI JSON response!\nResponse=%s\n%s",
                        rjHttpEntityString,
                        ExceptionUtils.getStackTrace(e)
                ));
                abortException.initCause(e);
                throw abortException;
            }

            StatusLine rjHttpStatusLine = rjHttpResponse.getStatusLine();

            if (!Arrays.asList(HttpStatus.SC_OK, HttpStatus.SC_ACCEPTED).contains(rjHttpStatusLine.getStatusCode())) {
                logger.println();
                throw new AbortException(String.format(
                        "Failed to execute OCAPI data import job! %s - %s!\nResponse=%s",
                        rjHttpStatusLine.getStatusCode(),
                        rjHttpStatusLine.getReasonPhrase(),
                        rjHttpEntityString
                ));
            }

            if (!rjJsonElement.isJsonObject()) {
                logger.println();
                throw new AbortException(String.format(
                        "Failed to parse OCAPI execute data import job JSON response!\nResponse=%s",
                        rjHttpEntityString
                ));
            }

            JsonObject rjJsonObject = rjJsonElement.getAsJsonObject();
            if (!rjJsonObject.has("id")) {
                logger.println();
                throw new AbortException(String.format(
                        "Failed to parse OCAPI execute data import job JSON response!\nResponse=%s",
                        rjHttpEntityString
                ));
            }

            JsonElement rjJsonExecutionStatus = rjJsonObject.get("execution_status");
            String rjExecutionStatus = rjJsonExecutionStatus.getAsString();

            logger.println(String.format(" - %s", rjExecutionStatus));

            JsonElement rjJsonJobId = rjJsonObject.get("id");
            String rjJobId = rjJsonJobId.getAsString();

            Boolean keepRunning = true;
            while (keepRunning) {
                TimeUnit.MINUTES.sleep(1);

                List<NameValuePair> jaHttpPostParams = new ArrayList<>();
                jaHttpPostParams.add(new BasicNameValuePair(
                        "grant_type", "urn:demandware:params:oauth:grant-type:client-id:dwsid:dwsecuretoken"
                ));

                RequestBuilder jaRequestBuilder = RequestBuilder.create("POST");
                jaRequestBuilder.setHeader("Authorization", ocAuthHeaderValue);
                jaRequestBuilder.setEntity(new UrlEncodedFormEntity(jaHttpPostParams, Consts.UTF_8));
                jaRequestBuilder.setUri(String.format(
                        "https://%s/dw/oauth2/access_token?client_id=%s",
                        hostname, URLEncoder.encode(ocCredentials.getClientId(), "UTF-8")
                ));

                CloseableHttpResponse jaHttpResponse;

                try {
                    jaHttpResponse = httpClient.execute(jaRequestBuilder.build());
                } catch (IOException e) {
                    logger.println();
                    AbortException abortException = new AbortException(String.format(
                            "Exception thrown while making HTTP request!\n%s",
                            ExceptionUtils.getStackTrace(e)
                    ));
                    abortException.initCause(e);
                    throw abortException;
                }

                String jaHttpEntityString;

                try {
                    jaHttpEntityString = EntityUtils.toString(jaHttpResponse.getEntity(), "UTF-8");
                } catch (IOException e) {
                    logger.println();
                    AbortException abortException = new AbortException(String.format(
                            "Exception thrown while making HTTP request!\n%s",
                            ExceptionUtils.getStackTrace(e)
                    ));
                    abortException.initCause(e);
                    throw abortException;
                }

                try {
                    jaHttpResponse.close();
                } catch (IOException e) {
                    logger.println();
                    AbortException abortException = new AbortException(String.format(
                            "Exception thrown while making HTTP request!\n%s",
                            ExceptionUtils.getStackTrace(e)
                    ));
                    abortException.initCause(e);
                    throw abortException;
                }

                JsonElement jaJsonElement;

                try {
                    JsonParser jaJsonParser = new JsonParser();
                    jaJsonElement = jaJsonParser.parse(jaHttpEntityString);
                } catch (JsonParseException e) {
                    logger.println();
                    AbortException abortException = new AbortException(String.format(
                            "Exception thrown while parsing OCAPI JSON response!\nResponse=%s\n%s",
                            jaHttpEntityString,
                            ExceptionUtils.getStackTrace(e)
                    ));
                    abortException.initCause(e);
                    throw abortException;
                }

                StatusLine jaHttpStatusLine = jaHttpResponse.getStatusLine();

                if (jaHttpStatusLine.getStatusCode() != HttpStatus.SC_OK) {
                    logger.println();
                    throw new AbortException(String.format(
                            "Failed to authenticate with OCAPI! %s - %s!\nResponse=%s",
                            jaHttpStatusLine.getStatusCode(),
                            jaHttpStatusLine.getReasonPhrase(),
                            jaHttpEntityString
                    ));
                }

                if (!jaJsonElement.isJsonObject()) {
                    logger.println();
                    throw new AbortException(String.format(
                            "Failed to parse OCAPI JSON response!\nResponse=%s",
                            jaHttpEntityString
                    ));
                }

                JsonObject jaJsonObject = jaJsonElement.getAsJsonObject();
                Boolean jaValidJson = Stream.of("access_token", "token_type").allMatch(jaJsonObject::has);

                if (!jaValidJson) {
                    logger.println();
                    throw new AbortException(String.format(
                            "Failed to parse OCAPI JSON response!\nResponse=%s",
                            jaHttpEntityString
                    ));
                }

                JsonElement jaJsonTokenType = jaJsonObject.get("token_type");
                JsonElement jaJsonAccessToken = jaJsonObject.get("access_token");

                RequestBuilder jsRequestBuilder = RequestBuilder.create("GET");
                jsRequestBuilder.setHeader("Authorization", String.format(
                        "%s %s",
                        jaJsonTokenType.getAsString(),
                        jaJsonAccessToken.getAsString()
                ));

                jsRequestBuilder.setUri(String.format(
                        "https://%s/s/-/dw/data/%s/jobs/sfcc-site-archive-import/executions/%s?client_id=%s",
                        hostname,
                        URLEncoder.encode(ocVersion, "UTF-8"),
                        URLEncoder.encode(rjJobId, "UTF-8"),
                        URLEncoder.encode(ocCredentials.getClientId(), "UTF-8")
                ));

                CloseableHttpResponse jsHttpResponse;

                try {
                    jsHttpResponse = httpClient.execute(jsRequestBuilder.build());
                } catch (IOException e) {
                    logger.println();
                    AbortException abortException = new AbortException(String.format(
                            "Exception thrown while making HTTP request!\n%s",
                            ExceptionUtils.getStackTrace(e)
                    ));
                    abortException.initCause(e);
                    throw abortException;
                }

                String jsHttpEntityString;

                try {
                    jsHttpEntityString = EntityUtils.toString(jsHttpResponse.getEntity(), "UTF-8");
                } catch (IOException e) {
                    logger.println();
                    AbortException abortException = new AbortException(String.format(
                            "Exception thrown while making HTTP request!\n%s",
                            ExceptionUtils.getStackTrace(e)
                    ));
                    abortException.initCause(e);
                    throw abortException;
                }

                try {
                    jsHttpResponse.close();
                } catch (IOException e) {
                    logger.println();
                    AbortException abortException = new AbortException(String.format(
                            "Exception thrown while making HTTP request!\n%s",
                            ExceptionUtils.getStackTrace(e)
                    ));
                    abortException.initCause(e);
                    throw abortException;
                }

                JsonElement jsJsonElement;

                try {
                    JsonParser jsJsonParser = new JsonParser();
                    jsJsonElement = jsJsonParser.parse(jsHttpEntityString);
                } catch (JsonParseException e) {
                    logger.println();
                    AbortException abortException = new AbortException(String.format(
                            "Exception thrown while parsing OCAPI JSON response!\nResponse=%s\n%s",
                            jsHttpEntityString,
                            ExceptionUtils.getStackTrace(e)
                    ));
                    abortException.initCause(e);
                    throw abortException;
                }

                StatusLine jsHttpStatusLine = jsHttpResponse.getStatusLine();

                if (jsHttpStatusLine.getStatusCode() != HttpStatus.SC_OK) {
                    logger.println();
                    throw new AbortException(String.format(
                            "Failed to get OCAPI data import job status! %s - %s!\nResponse=%s",
                            jsHttpStatusLine.getStatusCode(),
                            jsHttpStatusLine.getReasonPhrase(),
                            jsHttpEntityString
                    ));
                }

                if (!jsJsonElement.isJsonObject()) {
                    logger.println();
                    throw new AbortException(String.format(
                            "Failed to parse OCAPI get data import job JSON response!\nResponse=%s",
                            jsHttpEntityString
                    ));
                }

                JsonObject jsJsonObject = jsJsonElement.getAsJsonObject();
                if (!jsJsonObject.has("execution_status")) {
                    logger.println();
                    throw new AbortException(String.format(
                            "Failed to parse OCAPI get data import job JSON response!\nResponse=%s",
                            jsHttpEntityString
                    ));
                }

                JsonElement jsJsonExecutionStatus = jsJsonObject.get("execution_status");
                String jsExecutionStatus = jsJsonExecutionStatus.getAsString();

                logger.println(String.format(" - %s", jsExecutionStatus));

                if (StringUtils.equalsIgnoreCase(jsExecutionStatus, "finished")) {
                    keepRunning = false;

                    if (!jsJsonObject.has("exit_status")) {
                        logger.println();
                        throw new AbortException(String.format(
                                "Failed to parse OCAPI get data import job JSON response!\nResponse=%s",
                                jsHttpEntityString
                        ));
                    }

                    JsonElement exitStatusElement = jsJsonObject.get("exit_status");

                    if (!exitStatusElement.isJsonObject()) {
                        logger.println();
                        throw new AbortException(String.format(
                                "Failed to parse OCAPI get data import job JSON response!\nResponse=%s",
                                jsHttpEntityString
                        ));
                    }

                    JsonObject exitStatusObject = exitStatusElement.getAsJsonObject();

                    JsonElement exitStatusStatusElement = exitStatusObject.get("status");
                    String exitStatusStatus = exitStatusStatusElement.getAsString();

                    if (!StringUtils.equalsIgnoreCase(exitStatusStatus, "ok")) {
                        logger.println();
                        throw new AbortException(String.format(
                                "Failed to import %s.zip!\nResponse=%s",
                                archiveName,
                                jsHttpEntityString
                        ));
                    }
                }
            }

            logger.println(" + Ok");
            /* Importing data */


            /* Cleaning up leftover data from current data import */
            logger.println();
            logger.println("[+] Cleaning up leftover data from current data import");

            for (String rmPath : Arrays.asList(archiveName, String.format("%s.zip", archiveName))) {
                RequestBuilder rmRequestBuilder = RequestBuilder.create("DELETE");
                rmRequestBuilder.setHeader("Authorization", bmAuthHeaderValue);
                rmRequestBuilder.setUri(String.format(
                        "https://%s/on/demandware.servlet/webdav/Sites/Impex/src/instance/%s",
                        hostname, rmPath
                ));

                CloseableHttpResponse rmHttpResponse;

                try {
                    rmHttpResponse = httpClient.execute(rmRequestBuilder.build());
                } catch (IOException e) {
                    logger.println();
                    AbortException abortException = new AbortException(String.format(
                            "Exception thrown while making HTTP request!\n%s",
                            ExceptionUtils.getStackTrace(e)
                    ));
                    abortException.initCause(e);
                    throw abortException;
                }

                try {
                    rmHttpResponse.close();
                } catch (IOException e) {
                    logger.println();
                    AbortException abortException = new AbortException(String.format(
                            "Exception thrown while making HTTP request!\n%s",
                            ExceptionUtils.getStackTrace(e)
                    ));
                    abortException.initCause(e);
                    throw abortException;
                }

                StatusLine rmHttpStatusLine = rmHttpResponse.getStatusLine();

                if (rmHttpStatusLine.getStatusCode() != HttpStatus.SC_NOT_FOUND) {
                    if (rmHttpStatusLine.getStatusCode() == HttpStatus.SC_UNAUTHORIZED) {
                        logger.println();
                        throw new AbortException("Invalid username or password!");
                    } else if (rmHttpStatusLine.getStatusCode() == HttpStatus.SC_NO_CONTENT) {
                        logger.println(String.format(" - %s", rmPath));
                    } else {
                        logger.println();
                        throw new AbortException(String.format(
                                "%s - %s!", rmHttpStatusLine.getStatusCode(), rmHttpStatusLine.getReasonPhrase()
                        ));
                    }
                }
            }

            logger.println(" + Ok");
            /* Cleaning up leftover data from current data import */


            /* Close HTTP Client */
            try {
                httpClient.close();
            } catch (IOException e) {
                logger.println();
                AbortException abortException = new AbortException(String.format(
                        "Exception thrown while closing HTTP client!\n%s",
                        ExceptionUtils.getStackTrace(e)
                ));
                abortException.initCause(e);
                throw abortException;
            }
            /* Close HTTP Client */


            return new DataImportResult(currentDataFingerprints, "IMPORTED");
        }
    }

    private static class DataImportResult implements Serializable {
        private final List<String> dataFingerprints;
        private final String status;

        @SuppressWarnings("WeakerAccess")
        public DataImportResult(List<String> dataFingerprints, String status) {
            this.dataFingerprints = dataFingerprints;
            this.status = status;
        }

        @SuppressWarnings("WeakerAccess")
        public List<String> getDataFingerprints() {
            return dataFingerprints;
        }

        @SuppressWarnings("WeakerAccess")
        public String getStatus() {
            return status;
        }

        private static final long serialVersionUID = 1L;
    }
}
