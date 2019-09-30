package me.shib.bugaudit.scanner.java.findsecbugs;

import com.sun.org.apache.xerces.internal.impl.xpath.regex.Match;
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

    private static transient final Lang lang = Lang.Java;
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
        String fileName="";
        if(buildType == java_Maven)
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
            }
            else
            {
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
                        "       reportLevel = \""+ confidenceLevel.toLowerCase() + "\"\n" +
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
                        "    }\n"   +
                        "  }";

                Files.write(Paths.get(getScanDirectory() + File.separator + fileName), pluginStr.getBytes(), StandardOpenOption.APPEND);
            }
        }
        else
                throw new FileNotFoundException(fileName + "not found!");
    }

    private List<String> getModulePaths() throws IOException {
        // A root pom.xml file is present with all the modules (projects) that has to be built. This function will get all the projects name using regex.
        List<String> modulePaths = new ArrayList<String>(); //modulePaths contain all the modules of the project that we have to run findsecbugs for

        File file = new File(getScanDirectory() + File.separator + "pom.xml");
        String contents = readFromFile(file);

        Pattern pattern = Pattern.compile("<module>(.*)</module>"); //Example: <module>Billing</module>
        Matcher matcher = pattern.matcher(contents);

        if (matcher.find()) {
            while (matcher.find()) {
                String module = matcher.group(1);
                String path = getScanDirectory() + File.separator + module + "/target/spotbugsXml.xml";

                modulePaths.add(path);
            }
        } else {      //Some projects do not have any modules and we just build from parent pom.xml file.
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

        int index1 = 0, index2 = 0;
        if (rank > 1 && rank <= 4)
            index1 = 0;
        else if (rank >= 5 && rank <= 9)
            index1 = 1;
        else if (rank >= 10 && rank <= 14)
            index1 = 2;
        else if (rank >= 15 && rank <= 20)
            index1 = 3;

        index2 = priority - 1;

        return severityMatrix[index1][index2];
    }

    /*Example of XML Contents:
    <Project projectName="insecure-deserialization">...</Project>
    <BugInstance instanceOccurrenceNum="0" instanceHash="be849f1dc19e86fbed90c49263a4ce1d" cweid="502" rank="10" abbrev="SECOBDES" category="SECURITY" priority="1" type="OBJECT_DESERIALIZATION" instanceOccurrenceMax="0">
    <ShortMessage>Object deserialization is used in {1}</ShortMessage>
    <LongMessage> Object deserialization is used in org.owasp.webgoat.plugin.InsecureDeserializationTask.completed(String) </LongMessage>
    <Class classname="org.owasp.webgoat.plugin.InsecureDeserializationTask" primary="true">
    <SourceLine classname="org.owasp.webgoat.plugin.InsecureDeserializationTask" start="51" end="88" sourcepath="org/owasp/webgoat/plugin/InsecureDeserializationTask.java" sourcefile="InsecureDeserializationTask.java">
    <Message>At InsecureDeserializationTask.java:[lines 51-88]</Message>
    </SourceLine> <Message> In class org.owasp.webgoat.plugin.InsecureDeserializationTask </Message> </Class>
    <Method isStatic="false" classname="org.owasp.webgoat.plugin.InsecureDeserializationTask" signature="(Ljava/lang/String;)Lorg/owasp/webgoat/assignments/AttackResult;" name="completed" primary="true"> <SourceLine endBytecode="502" classname="org.owasp.webgoat.plugin.InsecureDeserializationTask" start="64" end="88" sourcepath="org/owasp/webgoat/plugin/InsecureDeserializationTask.java" sourcefile="InsecureDeserializationTask.java" startBytecode="0"/>
    <Message> In method org.owasp.webgoat.plugin.InsecureDeserializationTask.completed(String) </Message></Method>
    <SourceLine endBytecode="65" classname="org.owasp.webgoat.plugin.InsecureDeserializationTask" start="74" end="74" sourcepath="org/owasp/webgoat/plugin/InsecureDeserializationTask.java" sourcefile="InsecureDeserializationTask.java" startBytecode="65" primary="true">
    <Message>At InsecureDeserializationTask.java:[line 74]</Message> </SourceLine> </BugInstance>*/

    private List<FindSecBugs> getXMLValuesForBug(String modulePath) throws ParserConfigurationException, IOException, SAXException {
        File bugXML = new File(modulePath);
        List<FindSecBugs> bugsList = new ArrayList<FindSecBugs>();

        if(!bugXML.exists())
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

                FindSecBugs findBugs = new FindSecBugs();   //Class object which contains the details of a bug!

                if(nElement.hasAttribute("projectName"))
                    findBugs.moduleName = nElement.getAttribute("projectName");

                if(eElement.hasAttribute("type"))
                    findBugs.bugType = eElement.getAttribute("type");

                if(eElement.hasAttribute("instanceHash"))
                    findBugs.instanceHash = eElement.getAttribute("instanceHash");

                if(eElement.hasAttribute("LongMessage"))
                    findBugs.message = eElement.getElementsByTagName("LongMessage").item(0).getTextContent();

                NodeList nList1 = eElement.getElementsByTagName("SourceLine");
                Node nNode1 = nList1.item(2);
                Element eElement1 = (Element) nNode1;

                if(eElement1 == null)
                    continue;

                if(eElement1.hasAttribute("classname"))
                    findBugs.className = eElement1.getAttribute("classname");

                if(eElement1.hasAttribute("sourcepath"))
                    findBugs.filePath = eElement1.getAttribute("sourcepath");

                String lineStart="",lineEnd="";
                if(eElement1.hasAttribute("start"))
                    lineStart = eElement1.getAttribute("start");

                if(eElement1.hasAttribute("end"))
                    lineEnd = eElement1.getAttribute("end");

                findBugs.lineNumber = lineStart + "-" + lineEnd;
                findBugs.priority = eElement.getAttribute("priority");

                Integer priority = Integer.parseInt(findBugs.priority);
                Integer rank = Integer.parseInt(eElement.getAttribute("rank"));
                findBugs.severity = getSeverity(priority, rank); //Get severity using risk matrix

                bugsList.add(findBugs);
            }
        }

        return bugsList;
    }

    public String getDescription(FindSecBugs findBugs) {
        StringBuilder description = new StringBuilder();

        description.append("The following insecure code bugs were found in ").append("**[").append(findBugs.filePath).append("](").append(this.getBugAuditScanResult().getRepo().getWebUrl()).append("/tree/").append(this.getBugAuditScanResult().getRepo().getCommit()).append("/").append(findBugs.filePath).append("):**\n");
        description.append(" * **Line:** ").append(findBugs.lineNumber).append("\n");
        description.append(" * **Type:** ");
        description.append(findBugs.bugType);
        description.append("\n");
        description.append(" * **Message:** ").append(findBugs.message).append("\n");
        description.append(" * **Confidence:** ").append(findBugs.priority);

        return description.toString();
    }

    private void addKeys(Bug bug, FindSecBugs findBugs) throws BugAuditException {
        bug.addKey(findBugs.filePath);
        bug.addKey(getBugAuditScanResult().getRepo() + "-" + findBugs.instanceHash);
    }

    private void processFindSecBugsResult(int buildType) throws IOException, SAXException, ParserConfigurationException, BugAuditException, InterruptedException {
        if(buildType == java_Maven) {
            List<String> modulePaths = getModulePaths();    //Find the modules from parent pom.xml file

            for (String module : modulePaths) {

                List<FindSecBugs> bugsList = getXMLValuesForBug(module);    //Get Bug details from XML

                for (FindSecBugs issue : bugsList) {
                    String title = "FindSecBugs (" + issue.bugType + ") found in " + issue.filePath + getBugAuditScanResult().getRepo();//Example: FindSecBugs (OBJECT_DESERIALIZATION) found in org/owasp/webgoat/plugin/InsecureDeserializationTask.javabugaudit/bugaudit-cli
                    Bug bug = new Bug(title, issue.severity);   //Create new bug using title and severity!
                    bug.setDescription(new BugAuditContent(this.getDescription(issue)));
                    bug.addType(issue.bugType.replace(" ", "-"));
                    addKeys(bug, issue);    //Add hash so that the bug doesn't duplicate
                    result.addBug(bug); //The add bug function will create a bug in freshrelease using the details from env variables and from bug object values!
                }
            }
        }
        else if(buildType == java_Gradle)
        {
              String buildDirString = runCommand("gradle properties");
              Pattern pattern = Pattern.compile("buildDir: *(.*)"); //Example: <module>Billing</module>
              Matcher matcher = pattern.matcher(buildDirString);

              String buildDir="";
              if(matcher.find())
                  buildDir = matcher.group(1);

              List<FindSecBugs> bugsList = getXMLValuesForBug(buildDir + "/findbugs.xml");

            for (FindSecBugs issue : bugsList) {
                String title = "FindSecBugs (" + issue.bugType + ") found in " + issue.filePath + getBugAuditScanResult().getRepo();//Example: FindSecBugs (OBJECT_DESERIALIZATION) found in org/owasp/webgoat/plugin/InsecureDeserializationTask.javabugaudit/bugaudit-cli
                Bug bug = new Bug(title, issue.severity);   //Create new bug using title and severity!
                bug.setDescription(new BugAuditContent(this.getDescription(issue)));
                bug.addType(issue.bugType.replace(" ", "-"));
                addKeys(bug, issue);    //Add hash so that the bug doesn't duplicate
                result.addBug(bug); //The add bug function will create a bug in freshrelease using the details from env variables and from bug object values!
            }
        }
    }

    private void runFindSecBugs(int buildType) throws BugAuditException, InterruptedException, SAXException, ParserConfigurationException, IOException {
        System.out.println("Running FindSecBugs!\n");

        if( buildType == java_Maven) {
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
        }
        else if(buildType == java_Gradle)
        {
            modifyXMLsForEnvironment(java_Gradle);

            String command = "gradle findbugs";
            String findBugsResponse = runCommand(command);

            if(!findBugsResponse.contains("BUILD SUCCESSFUL"))
                throw new BugAuditException("FindSecBugs failed!");

        }

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

        int buildType;
        if(new File(getScanDirectory() + File.separator + "pom.xml").exists())
            buildType = java_Maven;
        else
            buildType = java_Gradle;

        if (!isParserOnly()) {
            runFindSecBugs(buildType);   //Run the plugin and get XML result stored in target/SpotbugsXml.xml file
        }
        processFindSecBugsResult(buildType); //Process the XML file and convert them to bugs
    }
}
