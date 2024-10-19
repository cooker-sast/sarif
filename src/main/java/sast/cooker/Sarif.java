package sast.cooker;

import com.contrastsecurity.sarif.*;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class Sarif {
    //一个sarif 有多个 result
    //每个result 都有一个 list of snippets
    //一个sarif还要设置tool的相关信息，和所有用到的rule的信息
    public static class Result{
        public String message;
        public String ruleId;
        public String location;
        public int startLine;
        public int startColumn;
        public List<Snippet> snippets = new ArrayList<>();

        public String getRuleId() {
            return ruleId;
        }

        public int getStartColumn() {
            return startColumn;
        }

        public int getStartLine() {
            return startLine;
        }

        public List<Snippet> getSnippets() {
            return snippets;
        }

        public String getLocation() {
            return location;
        }

        public String getMessage() {
            return message;
        }

        public void setRuleId(String ruleId) {
            this.ruleId = ruleId;
        }

        public void setSnippets(List<Snippet> codeFlow) {
            this.snippets = codeFlow;
        }
        public void addSnippet(Snippet codeFlow) {
            this.snippets.add(codeFlow);
        }

        public void setLocation(String location) {
            this.location = location;
        }

        public void setMessage(String message) {
            this.message = message;
        }

        public void setStartColumn(int startColumn) {
            this.startColumn = startColumn;
        }

        public void setStartLine(int startLine) {
            this.startLine = startLine;
        }
    }
    public static class Snippet{
        public String message;
        public String code;
        public int startLine;
        public int startColumn;
        public String location;

        public String getLocation() {
            return location;
        }

        public int getStartLine() {
            return startLine;
        }

        public int getStartColumn() {
            return startColumn;
        }

        public String getMessage() {
            return message;
        }

        public String getCodeSnippet() {
            return code;
        }

        public void setStartColumn(int startColumn) {
            this.startColumn = startColumn;
        }

        public void setLocation(String location) {
            this.location = location;
        }

        public void setStartLine(int startLine) {
            this.startLine = startLine;
        }

        public void setMessage(String message) {
            this.message = message;
        }

        public void setCodeSnippet(String codeSnippet) {
            this.code = codeSnippet;
        }
    }
    public static class Rule{
        public String name;
        public String description;
        public String ruleId;

        public String getDescription() {
            return description;
        }

        public String getName() {
            return name;
        }

        public String getRuleId() {
            return ruleId;
        }

        public void setDescription(String description) {
            this.description = description;
        }

        public void setRuleId(String ruleId) {
            this.ruleId = ruleId;
        }

        public void setName(String name) {
            this.name = name;
        }
    }
    public List<Result> results = new ArrayList<>();
    public List<Rule> rules = new ArrayList<>();
    public String toolName = "cooker";
    public String toolUrl = "https://github.com/cooker-sast/cooker";
    public String toolVersion = "1.0.1";

    public List<Result> getResults() {
        return results;
    }

    public List<Rule> getRule0s() {
        return rules;
    }

    public String getToolName() {
        return toolName;
    }

    public String getToolUrl() {
        return toolUrl;
    }

    public String getToolVersion() {
        return toolVersion;
    }

    public void setResults(List<Result> results) {
        this.results = results;
    }

    public void setRules(List<Rule> rule0s) {
        this.rules = rule0s;
    }

    public void setToolName(String toolName) {
        this.toolName = toolName;
    }

    public void setToolUrl(String toolUrl) {
        this.toolUrl = toolUrl;
    }

    public void setToolVersion(String toolVersion) {
        this.toolVersion = toolVersion;
    }

    public void addRule(Rule rule) {
        rules.add(rule);
    }
    public void addResult(Result result0){
        this.results.add(result0);
    }

    public void generate(String path){
        SarifSchema210 sarif = null;
        try {
            sarif = new SarifSchema210().withVersion(SarifSchema210.Version._2_1_0).with$schema(new URI("http://json.schemastore.org/sarif-2.1.0-rtm.5"));
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
        List<Run> runs = new ArrayList<>();
        List<com.contrastsecurity.sarif.Result> results1 = new ArrayList<>();
        for (Result r : results) {
            com.contrastsecurity.sarif.Result sarifResult = new com.contrastsecurity.sarif.Result()
                    .withMessage(new Message().withText(r.message))
                    .withLevel(com.contrastsecurity.sarif.Result.Level.ERROR).withRuleId(r.ruleId).withLocations(List.of(
                            new Location().withPhysicalLocation(new PhysicalLocation().withArtifactLocation(new ArtifactLocation().withUri(r.location)).withRegion(
                                    new Region().withStartLine(r.startLine).withStartColumn(r.startColumn)
                            ))));
            CodeFlow codeflow = new CodeFlow();
            List<ThreadFlowLocation> threadFlowLocations = new ArrayList<>();
            List<ThreadFlow> threadFlows = new ArrayList<>();
            for (Snippet loc : r.snippets) {
                ThreadFlowLocation location = new ThreadFlowLocation().withLocation(new Location().withMessage(new Message().withText(loc.message)).withPhysicalLocation(
                        new PhysicalLocation().withArtifactLocation(new ArtifactLocation().withUri(loc.location))
                                .withRegion(new Region().withStartLine(loc.startLine)
                                        .withEndLine(loc.startLine)
                                        .withStartColumn(loc.startColumn)
                                        .withEndColumn(loc.startColumn)
                                        .withSnippet(new ArtifactContent().withText(loc.code))))).withNestingLevel(0);
                threadFlowLocations.add(location);
            }
            ThreadFlow threadFlow = new ThreadFlow().withLocations(threadFlowLocations);
            threadFlows.add(threadFlow);
            codeflow.setThreadFlows(threadFlows);
            sarifResult.setCodeFlows(List.of(codeflow));

            results1.add(sarifResult);
        }
        Set<ReportingDescriptor> rules = new HashSet<>();
        for (Rule r : this.rules){
            rules.add(new ReportingDescriptor()
                    .withName(r.name)
                    .withId(r.ruleId)
                    .withDefaultConfiguration(new ReportingConfiguration()
                            .withLevel(ReportingConfiguration.Level.NOTE)
                    ).withFullDescription(new MultiformatMessageString().withText(r.description))
            );
        }
        try {
            runs.add(new Run()
                    .withResults(results1)
                    .withTool(new Tool()
                            .withDriver(new ToolComponent()
                                    .withRules(rules)
                                    .withVersion(this.toolVersion)
                                    .withInformationUri(new URI(this.toolUrl)).withName(this.toolName))));
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
        sarif.setRuns(runs);
        File file;
        if (path.equals("")) {
            file = Path.of("result.sarif").toFile();
        }else {
            file = Path.of(path).toFile();
        }
        ObjectMapper mapper = new ObjectMapper();
        try {
            mapper.writerWithDefaultPrettyPrinter().writeValue(file, sarif);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}
