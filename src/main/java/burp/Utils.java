package burp;

public class Utils {

    public static boolean IsJSON(String rBody){
        if (rBody.startsWith("{")&&rBody.endsWith("}")){
            return true;
        }
        else return rBody.startsWith("[") && rBody.endsWith("]");
    }
}
