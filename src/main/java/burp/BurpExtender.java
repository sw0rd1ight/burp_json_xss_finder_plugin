package burp;

import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class BurpExtender implements IBurpExtender,IScannerCheck{

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private PrintWriter stderr;
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName("Json Xss Finder");
        callbacks.registerScannerCheck(this);

        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);

        stdout.println(System.getProperty("user.dir"));
        stdout.println("Load Json Xss Finder Plugin Success");



    }

    //todo getmatches and highlight
    private List<int[]> getMatches(byte[] response, byte[] match)
    {
        List<int[]> matches = new ArrayList<int[]>();

        int start = 0;
        while (start < response.length)
        {
            start = helpers.indexOf(response, match, true, start, response.length);
            if (start == -1)
                break;
            matches.add(new int[] { start, start + match.length });
            start += match.length;
        }

        return matches;
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {

        IResponseInfo iResponseInfo = helpers.analyzeResponse(baseRequestResponse.getResponse());
        IRequestInfo iRequestInfo = helpers.analyzeRequest(baseRequestResponse.getRequest());

        String stateMimeType = iResponseInfo.getStatedMimeType();
        int rBodyOffset = iResponseInfo.getBodyOffset();
        String resp = new String(baseRequestResponse.getResponse(), StandardCharsets.UTF_8);
        String rBody = resp.substring(rBodyOffset);

        if(stateMimeType.equals("HTML")&&Utils.IsJSON(rBody)){
            List<IScanIssue> issues = new ArrayList<>(1);
            issues.add(new CustomScanIssue(baseRequestResponse.getHttpService(),helpers.analyzeRequest(baseRequestResponse).getUrl(),
                    new IHttpRequestResponse[]{callbacks.applyMarkers(baseRequestResponse, null, null)},
                    "Json Xss","Content-type: text/html","High"));

            return issues;

        }



        return null;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null;
    }

    //todo
    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        return 0;
    }
}
