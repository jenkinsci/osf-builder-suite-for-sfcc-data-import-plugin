package org.jenkinsci.plugins.osfbuildersuiteforsfcc.dataimport;

import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardCredentials;
import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.cloudbees.plugins.credentials.domains.URIRequirementBuilder;
import hudson.AbortException;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.AbstractProject;
import hudson.model.Item;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.model.queue.Tasks;
import hudson.remoting.VirtualChannel;
import hudson.security.ACL;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.Builder;
import hudson.util.ListBoxModel;
import jenkins.MasterToSlaveFileCallable;
import jenkins.model.Jenkins;
import jenkins.tasks.SimpleBuildStep;
import net.sf.json.JSONObject;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.codehaus.plexus.util.MatchPattern;
import org.jenkinsci.Symbol;
import org.jenkinsci.plugins.osfbuildersuiteforsfcc.credentials.HTTPProxyCredentials;
import org.jenkinsci.plugins.osfbuildersuiteforsfcc.credentials.OpenCommerceAPICredentials;
import org.jenkinsci.plugins.osfbuildersuiteforsfcc.credentials.TwoFactorAuthCredentials;
import org.jenkinsci.plugins.osfbuildersuiteforsfcc.dataimport.model.DataImportAction;
import org.jenkinsci.plugins.osfbuildersuiteforsfcc.dataimport.model.DataImportEnvAction;
import org.jenkinsci.plugins.osfbuildersuiteforsfcc.dataimport.repeatable.ExcludePattern;
import org.jenkinsci.plugins.osfbuildersuiteforsfcc.dataimport.repeatable.IncludePattern;
import org.jenkinsci.plugins.tokenmacro.MacroEvaluationException;
import org.jenkinsci.plugins.tokenmacro.TokenMacro;
import org.kohsuke.stapler.*;
import org.zeroturnaround.zip.ZipUtil;

import javax.annotation.Nonnull;
import java.io.*;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;


@SuppressWarnings("unused")
public class DataImportBuilder extends Builder implements SimpleBuildStep {

    private String hostname;
    private String tfCredentialsId;
    private String ocCredentialsId;
    private String ocVersion;
    private String archiveName;
    private String sourcePath;
    private List<IncludePattern> includePatterns;
    private List<ExcludePattern> excludePatterns;
    private String importStrategy;
    private String tempDirectory;

    @DataBoundConstructor
    public DataImportBuilder(
            String hostname,
            String tfCredentialsId,
            String ocCredentialsId,
            String ocVersion,
            String archiveName,
            String sourcePath,
            List<IncludePattern> includePatterns,
            List<ExcludePattern> excludePatterns,
            String importStrategy,
            String tempDirectory) {

        this.hostname = hostname;
        this.tfCredentialsId = tfCredentialsId;
        this.ocCredentialsId = ocCredentialsId;
        this.ocVersion = ocVersion;
        this.archiveName = archiveName;
        this.sourcePath = sourcePath;
        this.includePatterns = includePatterns;
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
    public List<IncludePattern> getIncludePatterns() {
        return includePatterns;
    }

    @SuppressWarnings("unused")
    @DataBoundSetter
    public void setIncludePatterns(List<IncludePattern> includePatterns) {
        this.includePatterns = includePatterns;
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

        HTTPProxyCredentials httpProxyCredentials = null;
        if (StringUtils.isNotEmpty(getDescriptor().getHttpProxyCredentialsId())) {
            httpProxyCredentials = com.cloudbees.plugins.credentials.CredentialsProvider.findCredentialById(
                    getDescriptor().getHttpProxyCredentialsId(),
                    HTTPProxyCredentials.class,
                    build,
                    URIRequirementBuilder.create().build()
            );
        }

        List<String> previousDataFingerprints = new ArrayList<>();
        Run<?, ?> previousBuild = build.getPreviousBuild();
        if (previousBuild != null) {
            previousBuild.getActions(DataImportAction.class).forEach((dataImportAction) -> {
                List<String> dataFingerprints = dataImportAction.getDataFingerprints();
                if (dataFingerprints != null && !dataFingerprints.isEmpty()) {
                    previousDataFingerprints.addAll(dataFingerprints);
                }
            });
        }

        DataImportResult dataImportResult = workspace.act(new DataImportCallable(
                listener,
                expandedHostname,
                tfCredentialsId,
                tfCredentials,
                ocCredentialsId,
                ocCredentials,
                ocVersion,
                expandedArchiveName,
                sourcePath,
                includePatterns,
                excludePatterns,
                importStrategy,
                tempDirectory,
                httpProxyCredentials,
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
        private String httpProxyCredentialsId;
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
        public ListBoxModel doFillTfCredentialsIdItems(
                @AncestorInPath Item item,
                @QueryParameter String credentialsId) {

            StandardListBoxModel result = new StandardListBoxModel();

            if (item == null) {
                if (!Jenkins.get().hasPermission(Jenkins.ADMINISTER)) {
                    return result.includeCurrentValue(credentialsId);
                }
            } else {
                if (!item.hasPermission(Item.EXTENDED_READ)
                        && !item.hasPermission(CredentialsProvider.USE_ITEM)) {
                    return result.includeCurrentValue(credentialsId);
                }
            }

            return result
                    .includeEmptyValue()
                    .includeMatchingAs(
                            item instanceof hudson.model.Queue.Task
                                    ? Tasks.getAuthenticationOf((hudson.model.Queue.Task) item)
                                    : ACL.SYSTEM,
                            item,
                            StandardCredentials.class,
                            URIRequirementBuilder.create().build(),
                            CredentialsMatchers.instanceOf(TwoFactorAuthCredentials.class)
                    )
                    .includeCurrentValue(credentialsId);
        }

        @SuppressWarnings("unused")
        public ListBoxModel doFillOcCredentialsIdItems(
                @AncestorInPath Item item,
                @QueryParameter String credentialsId) {

            StandardListBoxModel result = new StandardListBoxModel();

            if (item == null) {
                if (!Jenkins.get().hasPermission(Jenkins.ADMINISTER)) {
                    return result.includeCurrentValue(credentialsId);
                }
            } else {
                if (!item.hasPermission(Item.EXTENDED_READ)
                        && !item.hasPermission(CredentialsProvider.USE_ITEM)) {
                    return result.includeCurrentValue(credentialsId);
                }
            }

            return result
                    .includeEmptyValue()
                    .includeMatchingAs(
                            item instanceof hudson.model.Queue.Task
                                    ? Tasks.getAuthenticationOf((hudson.model.Queue.Task) item)
                                    : ACL.SYSTEM,
                            item,
                            StandardCredentials.class,
                            URIRequirementBuilder.create().build(),
                            CredentialsMatchers.instanceOf(OpenCommerceAPICredentials.class)
                    )
                    .includeCurrentValue(credentialsId);
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

        @SuppressWarnings("unused")
        public ListBoxModel doFillHttpProxyCredentialsIdItems(
                @AncestorInPath Item item,
                @QueryParameter String credentialsId) {

            StandardListBoxModel result = new StandardListBoxModel();

            if (item == null) {
                if (!Jenkins.get().hasPermission(Jenkins.ADMINISTER)) {
                    return result.includeCurrentValue(credentialsId);
                }
            } else {
                if (!item.hasPermission(Item.EXTENDED_READ)
                        && !item.hasPermission(CredentialsProvider.USE_ITEM)) {
                    return result.includeCurrentValue(credentialsId);
                }
            }

            return result
                    .includeEmptyValue()
                    .includeMatchingAs(
                            item instanceof hudson.model.Queue.Task
                                    ? Tasks.getAuthenticationOf((hudson.model.Queue.Task) item)
                                    : ACL.SYSTEM,
                            item,
                            StandardCredentials.class,
                            URIRequirementBuilder.create().build(),
                            CredentialsMatchers.instanceOf(HTTPProxyCredentials.class)
                    )
                    .includeCurrentValue(credentialsId);
        }

        @SuppressWarnings("WeakerAccess")
        public String getHttpProxyCredentialsId() {
            return httpProxyCredentialsId;
        }

        @SuppressWarnings("unused")
        public void setHttpProxyCredentialsId(String httpProxyCredentialsId) {
            this.httpProxyCredentialsId = httpProxyCredentialsId;
        }

        @SuppressWarnings("WeakerAccess")
        public Boolean getDisableSSLValidation() {
            return disableSSLValidation;
        }

        @SuppressWarnings("unused")
        public void setDisableSSLValidation(Boolean disableSSLValidation) {
            this.disableSSLValidation = disableSSLValidation;
        }

        @Override
        public boolean configure(StaplerRequest req, JSONObject formData) throws FormException {
            httpProxyCredentialsId = formData.getString("httpProxyCredentialsId");
            disableSSLValidation = formData.getBoolean("disableSSLValidation");

            save();

            return super.configure(req, formData);
        }
    }

    private static class DataImportCallable extends MasterToSlaveFileCallable<DataImportResult> {

        private static final long serialVersionUID = 1L;

        private final TaskListener listener;
        private final String hostname;
        private final String tfCredentialsId;
        private final TwoFactorAuthCredentials tfCredentials;
        private final String ocCredentialsId;
        private final OpenCommerceAPICredentials ocCredentials;
        private final String ocVersion;
        private final String archiveName;
        private final String sourcePath;
        private final List<IncludePattern> includePatterns;
        private final List<ExcludePattern> excludePatterns;
        private final String importStrategy;
        private final String tempDirectory;
        private final HTTPProxyCredentials httpProxyCredentials;
        private final Boolean disableSSLValidation;
        private final List<String> previousDataFingerprints;

        @SuppressWarnings("WeakerAccess")
        public DataImportCallable(
                TaskListener listener,
                String hostname,
                String tfCredentialsId,
                TwoFactorAuthCredentials tfCredentials,
                String ocCredentialsId,
                OpenCommerceAPICredentials ocCredentials,
                String ocVersion,
                String archiveName,
                String sourcePath,
                List<IncludePattern> includePatterns,
                List<ExcludePattern> excludePatterns,
                String importStrategy,
                String tempDirectory,
                HTTPProxyCredentials httpProxyCredentials,
                Boolean disableSSLValidation,
                List<String> previousDataFingerprints) {

            this.listener = listener;
            this.hostname = hostname;
            this.tfCredentialsId = tfCredentialsId;
            this.tfCredentials = tfCredentials;
            this.ocCredentialsId = ocCredentialsId;
            this.ocCredentials = ocCredentials;
            this.ocVersion = ocVersion;
            this.archiveName = archiveName;
            this.sourcePath = sourcePath;
            this.includePatterns = includePatterns;
            this.excludePatterns = excludePatterns;
            this.importStrategy = importStrategy;
            this.tempDirectory = tempDirectory;
            this.httpProxyCredentials = httpProxyCredentials;
            this.disableSSLValidation = disableSSLValidation;
            this.previousDataFingerprints = previousDataFingerprints;
        }

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

            List<MatchPattern> includePatternsList = new ArrayList<>();
            if (includePatterns != null) {
                includePatternsList.addAll(includePatterns.stream()
                        .map(IncludePattern::getIncludePattern)
                        .filter(StringUtils::isNotEmpty)
                        .map((p) -> MatchPattern.fromString("%ant[" + File.separator + p + "]"))
                        .collect(Collectors.toList())
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
            List<String> currentDataZipFiles = new ArrayList<>();

            ZipUtil.pack(dataSrc, dataZip, (path) -> {
                boolean includeFile = true;
                if (!includePatternsList.isEmpty()) {
                    includeFile = includePatternsList.stream().anyMatch(
                            (pattern) -> pattern.matchPath(File.separator + path, true)
                    );
                }

                if (!includeFile) {
                    return null;
                }

                boolean excludeFile = false;
                if (!excludePatternsList.isEmpty()) {
                    excludeFile = excludePatternsList.stream().anyMatch(
                            (pattern) -> pattern.matchPath(File.separator + path, true)
                    );
                }

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

                        currentDataZipFiles.add(path);
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

            if (currentDataZipFiles.isEmpty()) {
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
                    currentDataZipFiles.forEach((dataZipFile) -> logger.println(String.format(" - %s", dataZipFile)));
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

            OpenCommerceAPI openCommerceAPI = new OpenCommerceAPI(
                    hostname,
                    httpProxyCredentials,
                    disableSSLValidation,
                    tfCredentials,
                    ocCredentials,
                    ocVersion
            );

            /* Cleaning up leftover data from previous data import */
            logger.println();
            logger.println("[+] Cleaning up leftover data from previous data import");

            for (String rmPath : Arrays.asList(archiveName, String.format("%s.zip", archiveName))) {
                openCommerceAPI.cleanupLeftoverData(rmPath);
                logger.println(String.format(" - %s", rmPath));
            }

            logger.println(" + Ok");
            /* Cleaning up leftover data from previous data import */


            /* Uploading data */
            logger.println();
            logger.println(String.format("[+] Uploading data (%s.zip)", archiveName));

            openCommerceAPI.uploadData(dataZip, archiveName);

            logger.println(" + Ok");
            /* Uploading data */


            /* Importing data */
            logger.println();
            logger.println(String.format("[+] Importing data (%s.zip)", archiveName));

            OpenCommerceAPI.JobExecutionResult impJobResult = openCommerceAPI.executeSiteArchiveImportJob(archiveName);
            logger.println(String.format(" - %s", impJobResult.getStatus()));

            String currentExecutionStatus = impJobResult.getStatus();
            while (!StringUtils.equalsIgnoreCase(currentExecutionStatus, "finished")) {
                TimeUnit.MINUTES.sleep(1);
                OpenCommerceAPI.JobExecutionResult chkJobResult = openCommerceAPI.checkSiteArchiveImportJob(
                        archiveName,
                        impJobResult.getId()
                );

                currentExecutionStatus = chkJobResult.getStatus();
                logger.println(String.format(" - %s", currentExecutionStatus));
            }

            logger.println(" + Ok");
            /* Importing data */


            /* Cleaning up leftover data from current data import */
            logger.println();
            logger.println("[+] Cleaning up leftover data from current data import");

            for (String rmPath : Arrays.asList(archiveName, String.format("%s.zip", archiveName))) {
                openCommerceAPI.cleanupLeftoverData(rmPath);
                logger.println(String.format(" - %s", rmPath));
            }

            logger.println(" + Ok");
            /* Cleaning up leftover data from current data import */

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
