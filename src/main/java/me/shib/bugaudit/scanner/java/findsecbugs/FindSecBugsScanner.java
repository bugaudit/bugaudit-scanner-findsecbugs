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
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class FindSecBugsScanner extends BugAuditScanner {

    private static transient final Lang lang = Lang.Java;
    private static transient final String tool = "FindSecBugs";
    private static transient final String findSecBugsThresholdLevel = "BUGAUDIT_FINDSECBUGS_CONFIDENCE_LEVEL";

    private BugAuditScanResult result;

    public FindSecBugsScanner() throws BugAuditException {
        super();
        this.getBugAuditScanResult().addKey("SAST-Warning");
        this.result = getBugAuditScanResult();
    }

    private void modifyXMLsForEnvironment() throws IOException {
        File excludeFile = new File(getScanDirectory() + File.separator + "spotbugs-security-exclude.xml");
        String excludeFileContents = "<FindBugsFilter>\n" +
                "</FindBugsFilter>";
        if (!excludeFile.exists())
            writeToFile(excludeFileContents, excludeFile);
        else
            System.out.println("Include file already present!");
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
        File pomFile = new File(getScanDirectory() + File.separator + "pom.xml");
        System.out.println(pomFile.getAbsolutePath());
        if (pomFile.exists()) {
            List<String> lines = Files.readAllLines(pomFile.toPath(), StandardCharsets.UTF_8);
            int position = 0;
            for (String str : lines) {
                if (str.trim().contains("<plugins>")) {
                    position = lines.indexOf(str);
                    break;
                }
            }
            String confidenceLevel = System.getenv(findSecBugsThresholdLevel);
            if (confidenceLevel == null || confidenceLevel.isEmpty()) {
                confidenceLevel = "Low";
            } else {
                confidenceLevel = confidenceLevel.substring(0, 1).toUpperCase() +
                        confidenceLevel.toLowerCase().substring(1).toLowerCase();
            }
            System.out.println("Setting FindSecBugs confidence threshold level: " + confidenceLevel);
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
        } else
            throw new FileNotFoundException("Pom XML Not found!");
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
        List<FindSecBugsWarning> bugsList = new ArrayList<>();
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
                FindSecBugsWarning warning = new FindSecBugsWarning();
                warning.moduleName = nElement.getAttribute("projectName");
                warning.bugType = eElement.getAttribute("type");
                warning.instanceHash = eElement.getAttribute("instanceHash");
                warning.message = eElement.getElementsByTagName("LongMessage").item(0).getTextContent();
                NodeList nList1 = eElement.getElementsByTagName("SourceLine");
                Node nNode1 = nList1.item(2);
                Element eElement1 = (Element) nNode1;
                if (eElement1 == null)
                    continue;
                warning.className = eElement1.getAttribute("classname");
                warning.filePath = eElement1.getAttribute("sourcepath");
                String lineStart = eElement1.getAttribute("start");
                String lineEnd = eElement1.getAttribute("end");
                warning.lineNumber = lineStart + "-" + lineEnd;
                warning.priority = eElement.getAttribute("priority");

                int priority = Integer.parseInt(warning.priority);
                int rank = Integer.parseInt(eElement.getAttribute("rank"));
                warning.severity = getSeverity(priority, rank); //Get severity using risk matrix
                bugsList.add(warning);
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
        description.append("/").append(scanDirRelPath).append("/").append(warning.filePath).append("):**\n");
        description.append(" * **Line:** ").append(warning.lineNumber).append("\n");
        description.append(" * **Type:** ").append(warning.bugType).append("\n");
        description.append(" * **Message:** ").append(warning.message).append("\n");
        description.append(" * **Confidence:** ").append(warning.priority);
        return description.toString();
    }

    private void addKeys(Bug bug, FindSecBugsWarning warning) throws BugAuditException {
        bug.addKey(warning.filePath);
        bug.addKey(getBugAuditScanResult().getRepo() + "-" + warning.instanceHash);
    }

    private void processFindSecBugsResult() throws IOException, SAXException, ParserConfigurationException, BugAuditException {
        List<String> modulePaths = getModulePaths();
        for (String module : modulePaths) {
            List<FindSecBugsWarning> bugsList = getXMLValuesForBug(module);
            for (FindSecBugsWarning issue : bugsList) {
                String title = "Security warning (" + issue.bugType + ") found in " + issue.filePath + " of " +
                        getBugAuditScanResult().getRepo();
                Bug bug = new Bug(title, issue.severity);
                bug.setDescription(new BugAuditContent(this.getDescription(issue)));
                bug.addType(issue.bugType.replace(" ", "-"));
                addKeys(bug, issue);
                result.addBug(bug);
            }
        }
    }

    private void runFindSecBugs() throws BugAuditException, InterruptedException, IOException {
        modifyXMLsForEnvironment();
        String buildScript = getBuildScript();
        String extraArgument;
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
        String command = "mvn spotbugs:spotbugs" + extraArgument;
        String spotBugsResponse = runCommand(command);
        if (!spotBugsResponse.contains("BUILD SUCCESS"))
            throw new BugAuditException("SpotBugs failed!");
    }

    @Override
    protected Lang getLang() {
        return lang;
    }

    @Override
    public String getTool() {
        return tool;
    }

    @Override
    public void scan() throws Exception {
        if (!isParserOnly()) {
            runFindSecBugs();
        }
        processFindSecBugsResult();
    }
}
