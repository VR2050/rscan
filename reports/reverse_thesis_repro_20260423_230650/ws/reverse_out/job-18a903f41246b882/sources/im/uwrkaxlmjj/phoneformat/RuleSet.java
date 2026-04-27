package im.uwrkaxlmjj.phoneformat;

import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/* JADX INFO: loaded from: classes2.dex */
public class RuleSet {
    public static Pattern pattern = Pattern.compile("[0-9]+");
    public boolean hasRuleWithIntlPrefix;
    public boolean hasRuleWithTrunkPrefix;
    public int matchLen;
    public ArrayList<PhoneRule> rules = new ArrayList<>();

    String format(String str, String intlPrefix, String trunkPrefix, boolean prefixRequired) {
        int length = str.length();
        int i = this.matchLen;
        if (length < i) {
            return null;
        }
        String begin = str.substring(0, i);
        int val = 0;
        Matcher matcher = pattern.matcher(begin);
        if (matcher.find()) {
            String num = matcher.group(0);
            val = Integer.parseInt(num);
        }
        for (PhoneRule rule : this.rules) {
            if (val >= rule.minVal && val <= rule.maxVal && str.length() <= rule.maxLen) {
                if (prefixRequired) {
                    if (((rule.flag12 & 3) == 0 && trunkPrefix == null && intlPrefix == null) || ((trunkPrefix != null && (rule.flag12 & 1) != 0) || (intlPrefix != null && (rule.flag12 & 2) != 0))) {
                        return rule.format(str, intlPrefix, trunkPrefix);
                    }
                } else if ((trunkPrefix == null && intlPrefix == null) || ((trunkPrefix != null && (rule.flag12 & 1) != 0) || (intlPrefix != null && (rule.flag12 & 2) != 0))) {
                    return rule.format(str, intlPrefix, trunkPrefix);
                }
            }
        }
        if (!prefixRequired) {
            if (intlPrefix != null) {
                for (PhoneRule rule2 : this.rules) {
                    if (val >= rule2.minVal && val <= rule2.maxVal && str.length() <= rule2.maxLen && (trunkPrefix == null || (rule2.flag12 & 1) != 0)) {
                        return rule2.format(str, intlPrefix, trunkPrefix);
                    }
                }
            } else if (trunkPrefix != null) {
                for (PhoneRule rule3 : this.rules) {
                    if (val >= rule3.minVal && val <= rule3.maxVal && str.length() <= rule3.maxLen && (intlPrefix == null || (rule3.flag12 & 2) != 0)) {
                        return rule3.format(str, intlPrefix, trunkPrefix);
                    }
                }
            }
        }
        return null;
    }

    String desensitization(String str, String intlPrefix, String trunkPrefix, boolean prefixRequired) {
        int length = str.length();
        int i = this.matchLen;
        if (length < i) {
            return null;
        }
        String begin = str.substring(0, i);
        int val = 0;
        Matcher matcher = pattern.matcher(begin);
        if (matcher.find()) {
            String num = matcher.group(0);
            val = Integer.parseInt(num);
        }
        for (PhoneRule rule : this.rules) {
            if (val >= rule.minVal && val <= rule.maxVal && str.length() <= rule.maxLen) {
                if (prefixRequired) {
                    if (((rule.flag12 & 3) == 0 && trunkPrefix == null && intlPrefix == null) || ((trunkPrefix != null && (rule.flag12 & 1) != 0) || (intlPrefix != null && (rule.flag12 & 2) != 0))) {
                        return rule.desensitization(str, intlPrefix, trunkPrefix);
                    }
                } else if ((trunkPrefix == null && intlPrefix == null) || ((trunkPrefix != null && (rule.flag12 & 1) != 0) || (intlPrefix != null && (rule.flag12 & 2) != 0))) {
                    return rule.desensitization(str, intlPrefix, trunkPrefix);
                }
            }
        }
        if (!prefixRequired) {
            if (intlPrefix != null) {
                for (PhoneRule rule2 : this.rules) {
                    if (val >= rule2.minVal && val <= rule2.maxVal && str.length() <= rule2.maxLen && (trunkPrefix == null || (rule2.flag12 & 1) != 0)) {
                        return rule2.desensitization(str, intlPrefix, trunkPrefix);
                    }
                }
            } else if (trunkPrefix != null) {
                for (PhoneRule rule3 : this.rules) {
                    if (val >= rule3.minVal && val <= rule3.maxVal && str.length() <= rule3.maxLen && (intlPrefix == null || (rule3.flag12 & 2) != 0)) {
                        return rule3.desensitization(str, intlPrefix, trunkPrefix);
                    }
                }
            }
        }
        return null;
    }

    boolean isValid(String str, String intlPrefix, String trunkPrefix, boolean prefixRequired) {
        int length = str.length();
        int i = this.matchLen;
        if (length < i) {
            return false;
        }
        String begin = str.substring(0, i);
        int val = 0;
        Matcher matcher = pattern.matcher(begin);
        if (matcher.find()) {
            String num = matcher.group(0);
            val = Integer.parseInt(num);
        }
        for (PhoneRule rule : this.rules) {
            if (val >= rule.minVal && val <= rule.maxVal && str.length() == rule.maxLen) {
                if (prefixRequired) {
                    if (((rule.flag12 & 3) == 0 && trunkPrefix == null && intlPrefix == null) || ((trunkPrefix != null && (rule.flag12 & 1) != 0) || (intlPrefix != null && (rule.flag12 & 2) != 0))) {
                        return true;
                    }
                } else if ((trunkPrefix == null && intlPrefix == null) || ((trunkPrefix != null && (rule.flag12 & 1) != 0) || (intlPrefix != null && (rule.flag12 & 2) != 0))) {
                    return true;
                }
            }
        }
        if (!prefixRequired) {
            if (intlPrefix != null && !this.hasRuleWithIntlPrefix) {
                for (PhoneRule rule2 : this.rules) {
                    if (val >= rule2.minVal && val <= rule2.maxVal && str.length() == rule2.maxLen && (trunkPrefix == null || (rule2.flag12 & 1) != 0)) {
                        return true;
                    }
                }
            } else if (trunkPrefix != null && !this.hasRuleWithTrunkPrefix) {
                for (PhoneRule rule3 : this.rules) {
                    if (val >= rule3.minVal && val <= rule3.maxVal && str.length() == rule3.maxLen && (intlPrefix == null || (rule3.flag12 & 2) != 0)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }
}
