package im.uwrkaxlmjj.phoneformat;

import java.util.ArrayList;

/* JADX INFO: loaded from: classes2.dex */
public class CallingCodeInfo {
    public ArrayList<String> countries = new ArrayList<>();
    public String callingCode = "";
    public ArrayList<String> trunkPrefixes = new ArrayList<>();
    public ArrayList<String> intlPrefixes = new ArrayList<>();
    public ArrayList<RuleSet> ruleSets = new ArrayList<>();

    String matchingAccessCode(String str) {
        for (String code : this.intlPrefixes) {
            if (str.startsWith(code)) {
                return code;
            }
        }
        return null;
    }

    String matchingTrunkCode(String str) {
        for (String code : this.trunkPrefixes) {
            if (str.startsWith(code)) {
                return code;
            }
        }
        return null;
    }

    String format(String orig) {
        String str = orig;
        String trunkPrefix = null;
        String intlPrefix = null;
        if (str.startsWith(this.callingCode)) {
            intlPrefix = this.callingCode;
            str = str.substring(intlPrefix.length());
        } else {
            String trunk = matchingTrunkCode(str);
            if (trunk != null) {
                trunkPrefix = trunk;
                str = str.substring(trunkPrefix.length());
            }
        }
        for (RuleSet set : this.ruleSets) {
            String phone = set.format(str, intlPrefix, trunkPrefix, true);
            if (phone != null) {
                return phone;
            }
        }
        for (RuleSet set2 : this.ruleSets) {
            String phone2 = set2.format(str, intlPrefix, trunkPrefix, false);
            if (phone2 != null) {
                return phone2;
            }
        }
        return (intlPrefix == null || str.length() == 0) ? orig : String.format("%s %s", intlPrefix, str);
    }

    String desensitization(String orig) {
        String str = orig;
        String trunkPrefix = null;
        String intlPrefix = null;
        if (str.startsWith(this.callingCode)) {
            intlPrefix = this.callingCode;
            str = str.substring(intlPrefix.length());
        } else {
            String trunk = matchingTrunkCode(str);
            if (trunk != null) {
                trunkPrefix = trunk;
                str = str.substring(trunkPrefix.length());
            }
        }
        for (RuleSet set : this.ruleSets) {
            String phone = set.desensitization(str, intlPrefix, trunkPrefix, true);
            if (phone != null) {
                return phone;
            }
        }
        for (RuleSet set2 : this.ruleSets) {
            String phone2 = set2.desensitization(str, intlPrefix, trunkPrefix, false);
            if (phone2 != null) {
                return phone2;
            }
        }
        return (intlPrefix == null || str.length() == 0) ? orig : String.format("%s %s", intlPrefix, str);
    }

    boolean isValidPhoneNumber(String orig) {
        String str = orig;
        String trunkPrefix = null;
        String intlPrefix = null;
        if (str.startsWith(this.callingCode)) {
            intlPrefix = this.callingCode;
            str = str.substring(intlPrefix.length());
        } else {
            String trunk = matchingTrunkCode(str);
            if (trunk != null) {
                trunkPrefix = trunk;
                str = str.substring(trunkPrefix.length());
            }
        }
        for (RuleSet set : this.ruleSets) {
            boolean valid = set.isValid(str, intlPrefix, trunkPrefix, true);
            if (valid) {
                return true;
            }
        }
        for (RuleSet set2 : this.ruleSets) {
            boolean valid2 = set2.isValid(str, intlPrefix, trunkPrefix, false);
            if (valid2) {
                return true;
            }
        }
        return false;
    }
}
