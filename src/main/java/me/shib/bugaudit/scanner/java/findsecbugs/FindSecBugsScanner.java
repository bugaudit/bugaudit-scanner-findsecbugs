package me.shib.bugaudit.scanner.java.findsecbugs;

import me.shib.bugaudit.commons.BugAuditContent;
import me.shib.bugaudit.commons.BugAuditException;
import me.shib.bugaudit.scanner.Bug;
import me.shib.bugaudit.scanner.BugAuditScanResult;
import me.shib.bugaudit.scanner.BugAuditScanner;
import me.shib.bugaudit.scanner.Lang;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class FindSecBugsScanner extends BugAuditScanner {

    private static transient final Lang scannerLang = Lang.Java;
    private static transient final String tool = "FindSecBugs";
    private static transient final String thresholdLevel = "FINDSECBUGS_CONFIDENCE_LEVEL";
    private static transient final int java_Maven = 1;
    private static transient final int java_Gradle = 2;

    private BugAuditScanResult result;

    public FindSecBugsScanner() throws BugAuditException {
        super();
        this.getBugAuditScanResult().addKey("SAST-Warning");
        this.result = getBugAuditScanResult();
    }

    protected String readFromFile(File file) throws IOException {
        StringBuilder contentBuilder = new StringBuilder();
        BufferedReader br = new BufferedReader(new FileReader(file));
        String line;
        while ((line = br.readLine()) != null) {
            contentBuilder.append(line).append("\n");
        }
        br.close();
        return contentBuilder.toString();
    }

    protected void writeToFile(String content, File file) throws FileNotFoundException {
        PrintWriter pw = new PrintWriter(file);
        pw.append(content);
        pw.close();
    }

    private void modifyXMLsForEnvironment(int buildType) throws FileNotFoundException, IOException {
        String fileName = "";
        if (buildType == java_Maven)
            fileName = "pom.xml";
        else
            fileName = "build.gradle";

        //The corresponding two files is used to tell spotbugs to report only security bugs and not others!
        File excludeFile = new File(getScanDirectory() + File.separator + "spotbugs-security-exclude.xml");
        String excludeFileContents = "<FindBugsFilter>\n" +
                "</FindBugsFilter>";

        if (!excludeFile.exists())
            writeToFile(excludeFileContents, excludeFile);
        else
            System.out.println("Exclude file already present!");

        File includeFile = new File(getScanDirectory() + File.separator + "spotbugs-security-include.xml");
        System.out.println(includeFile.getAbsolutePath());
        String includeFileContents = "<FindBugsFilter>\n" +
                "    <Match>\n" +
                "        <Bug category=\"SECURITY\"/>\n" +
                "    </Match>\n" +
                "</FindBugsFilter>";

        if (!includeFile.exists())
            writeToFile(includeFileContents, includeFile);
        else
            System.out.println("Include file already present!");

        //Used to append spotbugs maven plugin to pom.xml file
        File buildFile = new File(getScanDirectory() + File.separator + fileName);

        System.out.println(buildFile.getAbsolutePath());
        if (buildFile.exists()) {
            List<String> lines = Files.readAllLines(buildFile.toPath(), StandardCharsets.UTF_8);

            String confidenceLevel = System.getenv(thresholdLevel);
            if (confidenceLevel == null || confidenceLevel.equals(""))
                confidenceLevel = "Low";
            else
                confidenceLevel = confidenceLevel.substring(0, 1).toUpperCase() + confidenceLevel.substring(1).toLowerCase();

            if (fileName == "pom.xml") {
                int position = 0;

                for (String str : lines) {
                    if (str.trim().contains("<plugins>")) {
                        position = lines.indexOf(str);
                        break;
                    }
                }

                String pluginStr = "<plugin>\n" +
                        "            <groupId>com.github.spotbugs</groupId>\n" +
                        "            <artifactId>spotbugs-maven-plugin</artifactId>\n" +
                        "            <version>3.1.12</version>\n" +
                        "            <configuration>\n" +
                        "                <effort>Max</effort>\n" +
                        "                <threshold>" + confidenceLevel + "</threshold>\n" +
                        "                <failOnError>true</failOnError>\n" +
                        "                <maxHeap>2048</maxHeap>\n" +
                        "                <includeFilterFile>spotbugs-security-include.xml</includeFilterFile>\n" +
                        "                <excludeFilterFile>spotbugs-security-exclude.xml</excludeFilterFile>\n" +
                        "                <plugins>\n" +
                        "                    <plugin>\n" +
                        "                        <groupId>com.h3xstream.findsecbugs</groupId>\n" +
                        "                        <artifactId>findsecbugs-plugin</artifactId>\n" +
                        "                        <version>LATEST</version> <!-- Auto-update to the latest stable -->\n" +
                        "                    </plugin>\n" +
                        "                </plugins>\n" +
                        "            </configuration>\n" +
                        "        </plugin>";

                lines.add(position + 1, pluginStr);
                Files.write(Paths.get(getScanDirectory() + File.separator + "pom.xml"), lines, StandardCharsets.UTF_8);
            } else {
                int position = 0;

                String pluginStr = "\n\nallprojects {\n" +
                        "    \tapply plugin: 'findbugs'\n" +
                        "    dependencies {\n" +
                        "    \n" +
                        "    \tfindbugs 'com.google.code.findbugs:findbugs:3.0.1'\n" +
                        "    \tfindbugs configurations.findbugsPlugins.dependencies\n" +
                        "    \tfindbugsPlugins 'com.h3xstream.findsecbugs:findsecbugs-plugin:1.9.0'\n" +
                        "    }\n" +
                        "    \n" +
                        "    task findbugs(type: FindBugs) {\n" +
                        "\n" +
                        "      classes = fileTree(project.rootDir.absolutePath).include(\"**/*.class\");\n" +
                        "      source = fileTree(project.rootDir.absolutePath).include(\"**/*.java\");\n" +
                        "      classpath = files()\n" +
                        "      pluginClasspath = project.configurations.findbugsPlugins\n" +
                        "\n" +
                        "      findbugs {\n" +
                        "       toolVersion = \"3.1.12\"\n" +
                        "       sourceSets = [sourceSets.main]\n" +
                        "       maxHeapSize = '2048m'  \n" +
                        "       ignoreFailures = true\n" +
                        "       reportsDir = file(\"$project.buildDir\")\n" +
                        "       effort = \"max\"\n" +
                        "       reportLevel = \"" + confidenceLevel.toLowerCase() + "\"\n" +
                        "       includeFilter = file(\"$rootProject.projectDir/spotbugs-security-include.xml\")\n" +
                        "       excludeFilter = file(\"$rootProject.projectDir/spotbugs-security-exclude.xml\")\n" +
                        "      }\n" +
                        "\n" +
                        "      tasks.withType(FindBugs) {\n" +
                        "            reports {\n" +
                        "                    xml.enabled = true\n" +
                        "                    html.enabled = false\n" +
                        "            }\n" +
                        "        }\n" +
                        "    }\n" +
                        "  }";

                Files.write(Paths.get(getScanDirectory() + File.separator + fileName), pluginStr.getBytes(), StandardOpenOption.APPEND);
            }
        } else
            throw new FileNotFoundException(fileName + "not found!");
    }

    private List<String> getModulePaths() throws IOException {
        List<String> modulePaths = new ArrayList<>();
        File file = new File(getScanDirectory() + File.separator + "pom.xml");
        String contents = readFromFile(file);
        Pattern pattern = Pattern.compile("<module>(.*)</module>");
        Matcher matcher = pattern.matcher(contents);
        if (matcher.find()) {
            while (matcher.find()) {
                String module = matcher.group(1);
                String path = getScanDirectory() + File.separator + module + "/target/spotbugsXml.xml";

                modulePaths.add(path);
            }
        } else {
            String path = getScanDirectory() + File.separator + "target/spotbugsXml.xml";
            modulePaths.add(path);
        }

        return modulePaths;
    }

    private Integer getSeverity(int priority, int rank) {
        Integer[][] severityMatrix = {
                {1, 2, 2},
                {2, 2, 3},
                {3, 3, 4},
                {3, 4, 4}
        };

        int index1 = 0;
        if (rank >= 5 && rank <= 9)
            index1 = 1;
        else if (rank >= 10 && rank <= 14)
            index1 = 2;
        else if (rank >= 15 && rank <= 20)
            index1 = 3;
        int index2 = priority - 1;
        return severityMatrix[index1][index2];
    }

    private List<FindSecBugsWarning> getXMLValuesForBug(String modulePath) throws ParserConfigurationException, IOException, SAXException {
        File bugXML = new File(modulePath);
        List<FindSecBugsWarning> bugsList = new ArrayList<FindSecBugsWarning>();

        if (!bugXML.exists())
            return bugsList;

        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();

        Document doc = dBuilder.parse(bugXML);
        doc.getDocumentElement().normalize();

        NodeList nList = doc.getElementsByTagName("Project");

        Node nNode = nList.item(0);
        Element nElement = (Element) nNode;

        nList = doc.getElementsByTagName("BugInstance");
        for (int temp = 0; temp < nList.getLength(); temp++) {
            nNode = nList.item(temp);

            if (nNode.getNodeType() == Node.ELEMENT_NODE) {
                Element eElement = (Element) nNode;

                FindSecBugsWarning findBugs = new FindSecBugsWarning();   //Class object which contains the details of a bug!

                if (nElement.hasAttribute("projectName"))
                    findBugs.setModuleName(nElement.getAttribute("projectName"));

                if (eElement.hasAttribute("type"))
                    findBugs.setBugType(nElement.getAttribute("type"));

                if (eElement.hasAttribute("instanceHash"))
                    findBugs.setInstanceHash(nElement.getAttribute("instanceHash"));

                if (eElement.hasAttribute("LongMessage"))
                    findBugs.setMessage(eElement.getElementsByTagName("LongMessage").item(0).getTextContent());

                NodeList nList1 = eElement.getElementsByTagName("SourceLine");
                Node nNode1 = nList1.item(2);
                Element eElement1 = (Element) nNode1;

                if (eElement1 == null)
                    continue;

                if (eElement1.hasAttribute("classname"))
                    findBugs.setClassName(eElement1.getAttribute("classname"));

                if (eElement1.hasAttribute("sourcepath"))
                    findBugs.setFilePath(eElement1.getAttribute("sourcepath"));

                String lineStart = "", lineEnd = "";
                if (eElement1.hasAttribute("start"))
                    lineStart = eElement1.getAttribute("start");

                if (eElement1.hasAttribute("end"))
                    lineEnd = eElement1.getAttribute("end");

                findBugs.setLineNumber(lineStart + "-" + lineEnd);
                findBugs.setPriority(eElement.getAttribute("priority"));

                Integer priority = Integer.parseInt(findBugs.getPriority());
                Integer rank = Integer.parseInt(eElement.getAttribute("rank"));
                findBugs.setSeverity(getSeverity(priority, rank)); //Get severity using risk matrix

                bugsList.add(findBugs);
            }
        }

        return bugsList;
    }

    private String getDescription(FindSecBugsWarning warning) {
        String scanDirRelPath = getScanDirectory().getAbsolutePath().
                replaceFirst(new File(System.getProperty("user.dir")).getAbsolutePath(), "");
        StringBuilder description = new StringBuilder();
        description.append("The following insecure code was found **[was found](");
        description.append(this.getBugAuditScanResult().getRepo().getWebUrl());
        description.append("/tree/").append(this.getBugAuditScanResult().getRepo().getCommit());
        description.append("/").append(scanDirRelPath).append("/").append(warning.getFilePath()).append("):**\n");
        description.append(" * **Line:** ").append(warning.getLineNumber()).append("\n");
        description.append(" * **Type:** ").append(warning.getBugType()).append("\n");
        description.append(" * **Message:** ").append(warning.getMessage()).append("\n");
        description.append(" * **Confidence:** ").append(warning.getPriority());
        return description.toString();
    }

    private void addKeys(Bug bug, FindSecBugsWarning warning) throws BugAuditException {
        bug.addKey(warning.getFilePath());
        bug.addKey(getBugAuditScanResult().getRepo() + "-" + warning.getInstanceHash());
    }

    private void processFindSecBugsResult(int buildType) throws IOException, SAXException, ParserConfigurationException, BugAuditException, InterruptedException {
        if (buildType == java_Maven) {
            List<String> modulePaths = getModulePaths();    //Find the modules from parent pom.xml file

            for (String module : modulePaths) {

                List<FindSecBugsWarning> bugsList = getXMLValuesForBug(module);    //Get Bug details from XML

                for (FindSecBugsWarning issue : bugsList) {
                    String title = "FindSecBugs (" + issue.getBugType() + ") found in " + issue.getFilePath() + getBugAuditScanResult().getRepo();//Example: FindSecBugs (OBJECT_DESERIALIZATION) found in org/owasp/webgoat/plugin/InsecureDeserializationTask.javabugaudit/bugaudit-cli
                    Bug bug = new Bug(title, issue.getSeverity());   //Create new bug using title and severity!
                    bug.setDescription(new BugAuditContent(this.getDescription(issue)));
                    bug.addType(issue.getBugType().replace(" ", "-"));
                    addKeys(bug, issue);    //Add hash so that the bug doesn't duplicate
                    result.addBug(bug); //The add bug function will create a bug in freshrelease using the details from env variables and from bug object values!
                }
            }
        } else if (buildType == java_Gradle) {
            String buildDirString = runCommand("gradle properties");
            Pattern pattern = Pattern.compile("buildDir: *(.*)"); //Example: <module>Billing</module>
            Matcher matcher = pattern.matcher(buildDirString);

            String buildDir = "";
            if (matcher.find())
                buildDir = matcher.group(1);

            List<FindSecBugsWarning> bugsList = getXMLValuesForBug(buildDir + "/findbugs.xml");

            for (FindSecBugsWarning issue : bugsList) {
                String title = "FindSecBugs (" + issue.getBugType() + ") found in " + issue.getFilePath() + getBugAuditScanResult().getRepo();//Example: FindSecBugs (OBJECT_DESERIALIZATION) found in org/owasp/webgoat/plugin/InsecureDeserializationTask.javabugaudit/bugaudit-cli
                Bug bug = new Bug(title, issue.getSeverity());   //Create new bug using title and severity!
                bug.setDescription(new BugAuditContent(this.getDescription(issue)));
                bug.addType(issue.getBugType().replace(" ", "-"));
                addKeys(bug, issue);    //Add hash so that the bug doesn't duplicate
                result.addBug(bug); //The add bug function will create a bug in freshrelease using the details from env variables and from bug object values!
            }
        }
    }

    private void runFindSecBugs(int buildType) throws BugAuditException, InterruptedException, SAXException, ParserConfigurationException, IOException {
        System.out.println("Running FindSecBugs!\n");

        if (buildType == java_Maven) {
            modifyXMLsForEnvironment(java_Maven);//Need to add two additional XML's to find only security bugs and also have to add the plugin in pom.xml file
            String buildScript = getBuildScript();
            String command = "", extraArgument;
            if (buildScript == null)
                extraArgument = "";
            else {
                Pattern pattern = Pattern.compile("mvn clean install(.*)");
                Matcher matcher = pattern.matcher(buildScript);

                if (matcher.find()) {
                    extraArgument = matcher.group(1);
                } else {
                    extraArgument = "";
                }
            }

            command = "mvn spotbugs:spotbugs" + extraArgument;

            String spotBugsResponse = runCommand(command);  //The command should run from root pom.xml file location

            if (!spotBugsResponse.contains("BUILD SUCCESS")) //If spotbugs build failed,throw BugAuditException!
                throw new BugAuditException("FindSecBugs failed!");
        } else if (buildType == java_Gradle) {
            modifyXMLsForEnvironment(java_Gradle);

            String command = "gradle findbugs";
            String findBugsResponse = runCommand(command);

            if (!findBugsResponse.contains("BUILD SUCCESSFUL"))
                throw new BugAuditException("FindSecBugs failed!");

        }

    }

    @Override
    protected boolean isLangSupported(Lang lang) {
        return lang == scannerLang;
    }

    @Override
    public String getTool() {
        return tool;
    }

    @Override
    public void scan() throws Exception {

        int buildType;
        if (new File(getScanDirectory() + File.separator + "pom.xml").exists())
            buildType = java_Maven;
        else
            buildType = java_Gradle;

        if (!isParserOnly()) {
            runFindSecBugs(buildType);   //Run the plugin and get XML result stored in target/SpotbugsXml.xml file
        }
        processFindSecBugsResult(buildType); //Process the XML file and convert them to bugs
    }
}
