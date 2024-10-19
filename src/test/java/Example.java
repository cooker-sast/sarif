import sast.cooker.Sarif;

public class Example {
    public static void main(String[] args) {
        Sarif sarif = new Sarif();
        sarif.setToolName("semgrep");
        sarif.setToolVersion("1.0.0");
        sarif.setToolUrl("https://semgrep.dev/");

        Sarif.Rule rule1 = new Sarif.Rule();
        rule1.setName("taint analysis");
        rule1.setRuleId("taint");
        rule1.setDescription("taint analysis description");

        sarif.addRule(rule1);
        Sarif.Result result = new Sarif.Result();
        result.setLocation("/tmp/web/index.php");
        result.setMessage("example");
        result.setStartColumn(0);
        result.setStartLine(1);
        result.setRuleId("taint");
        for (int i = 0; i < 10; i ++){
            Sarif.Snippet snippet = new Sarif.Snippet();
            snippet.setCodeSnippet("code here " + i);
            snippet.setLocation("/tmp/web/index.php");
            snippet.setStartLine(i + 1);
            snippet.setStartColumn(0);
            snippet.setMessage("message" + i);
            result.addSnippet(snippet);
        }
        sarif.addResult(result);
        sarif.generate("1.sarif");
    }
}
