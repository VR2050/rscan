package im.uwrkaxlmjj.messenger.utils;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/* JADX INFO: loaded from: classes2.dex */
public class RegexUtils {
    private static final String urlStr = "(((https|http)?://)?([a-z0-9]+[.])|(www.))\\w+[.|\\/]([a-z0-9]{0,})?[[.]([a-z0-9]{0,})]+((/[\\S&&[^,;一-龥]]+)+)?([.][a-z0-9]{0,}+|/?)";
    private static Pattern ptUrl = Pattern.compile(urlStr);

    public static boolean firstLetterIsEnglishLetter(CharSequence chars) {
        if (chars == null || chars.length() <= 0) {
            return false;
        }
        return Pattern.compile("([a-zA-Z])").matcher(chars.charAt(0) + "").matches();
    }

    public static boolean hasLetterAndNumber(CharSequence str, boolean allowUnderLine) {
        boolean hasDigit = false;
        boolean hasLetter = false;
        for (int i = 0; i < str.length(); i++) {
            if (!hasDigit && Character.isDigit(str.charAt(i))) {
                hasDigit = true;
            }
            if (!hasLetter && Character.isLetter(str.charAt(i))) {
                hasLetter = true;
            }
            if (hasDigit && hasLetter) {
                break;
            }
        }
        boolean isMatches = Pattern.matches(allowUnderLine ? "^[a-zA-Z0-9_]+$" : "^[a-zA-Z0-9]+$", str);
        return hasDigit && hasLetter && isMatches;
    }

    public static boolean hasLink(String str) {
        if (str == null) {
            return false;
        }
        Matcher m = ptUrl.matcher(str);
        int count = 0;
        while (m.find()) {
            count++;
        }
        return count != 0;
    }
}
