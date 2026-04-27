package im.uwrkaxlmjj.phoneformat;

/* JADX INFO: loaded from: classes2.dex */
public class PhoneRule {
    public int byte8;
    public String desensitizationFormat;
    public int flag12;
    public int flag13;
    public String format;
    public boolean hasIntlPrefix;
    public boolean hasTrunkPrefix;
    public int maxLen;
    public int maxVal;
    public int minVal;
    public int otherFlag;
    public int prefixLen;

    String format(String str, String intlPrefix, String trunkPrefix) {
        boolean hadC = false;
        boolean hadN = false;
        boolean hasOpen = false;
        int spot = 0;
        StringBuilder res = new StringBuilder(20);
        for (int i = 0; i < this.format.length(); i++) {
            char ch = this.format.charAt(i);
            if (ch == '#') {
                if (spot < str.length()) {
                    res.append(str.substring(spot, spot + 1));
                    spot++;
                } else if (hasOpen) {
                    res.append(" ");
                }
            } else {
                if (ch != '(') {
                    if (ch == 'c') {
                        hadC = true;
                        if (intlPrefix != null) {
                            res.append(intlPrefix);
                        }
                    } else if (ch == 'n') {
                        hadN = true;
                        if (trunkPrefix != null) {
                            res.append(trunkPrefix);
                        }
                    }
                } else if (spot < str.length()) {
                    hasOpen = true;
                }
                if ((ch != ' ' || i <= 0 || ((this.format.charAt(i - 1) != 'n' || trunkPrefix != null) && (this.format.charAt(i - 1) != 'c' || intlPrefix != null))) && (spot < str.length() || (hasOpen && ch == ')'))) {
                    res.append(this.format.substring(i, i + 1));
                    if (ch == ')') {
                        hasOpen = false;
                    }
                }
            }
        }
        if (intlPrefix != null && !hadC) {
            res.insert(0, String.format("%s ", intlPrefix));
        } else if (trunkPrefix != null && !hadN) {
            res.insert(0, trunkPrefix);
        }
        return res.toString();
    }

    /* JADX WARN: Removed duplicated region for block: B:38:0x00a6 A[PHI: r3 r6 r7
      0x00a6: PHI (r3v4 'hadC' boolean) = 
      (r3v2 'hadC' boolean)
      (r3v2 'hadC' boolean)
      (r3v2 'hadC' boolean)
      (r3v2 'hadC' boolean)
      (r3v2 'hadC' boolean)
      (r3v5 'hadC' boolean)
      (r3v5 'hadC' boolean)
      (r3v2 'hadC' boolean)
      (r3v2 'hadC' boolean)
     binds: [B:56:0x00e5, B:53:0x00d6, B:54:0x00d8, B:50:0x00cc, B:47:0x00c0, B:36:0x00a1, B:37:0x00a3, B:33:0x009a, B:34:0x009c] A[DONT_GENERATE, DONT_INLINE]
      0x00a6: PHI (r6v3 'hadN' boolean) = 
      (r6v1 'hadN' boolean)
      (r6v1 'hadN' boolean)
      (r6v1 'hadN' boolean)
      (r6v1 'hadN' boolean)
      (r6v1 'hadN' boolean)
      (r6v1 'hadN' boolean)
      (r6v1 'hadN' boolean)
      (r6v4 'hadN' boolean)
      (r6v4 'hadN' boolean)
     binds: [B:56:0x00e5, B:53:0x00d6, B:54:0x00d8, B:50:0x00cc, B:47:0x00c0, B:36:0x00a1, B:37:0x00a3, B:33:0x009a, B:34:0x009c] A[DONT_GENERATE, DONT_INLINE]
      0x00a6: PHI (r7v6 'hasOpen' boolean) = 
      (r7v4 'hasOpen' boolean)
      (r7v4 'hasOpen' boolean)
      (r7v4 'hasOpen' boolean)
      (r7v4 'hasOpen' boolean)
      (r7v4 'hasOpen' boolean)
      (r7v1 'hasOpen' boolean)
      (r7v1 'hasOpen' boolean)
      (r7v1 'hasOpen' boolean)
      (r7v1 'hasOpen' boolean)
     binds: [B:56:0x00e5, B:53:0x00d6, B:54:0x00d8, B:50:0x00cc, B:47:0x00c0, B:36:0x00a1, B:37:0x00a3, B:33:0x009a, B:34:0x009c] A[DONT_GENERATE, DONT_INLINE]] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    java.lang.String desensitization(java.lang.String r17, java.lang.String r18, java.lang.String r19) {
        /*
            Method dump skipped, instruction units count: 300
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.phoneformat.PhoneRule.desensitization(java.lang.String, java.lang.String, java.lang.String):java.lang.String");
    }

    private String handleDesensitizationSpecial(String str, int type) {
        if (str == null) {
            return "";
        }
        StringBuilder res = new StringBuilder(str.length());
        if (str.length() == 0) {
            return "";
        }
        if (str.length() == 1) {
            return str;
        }
        if (str.length() == 2) {
            return type == 1 ? "#*" : type == 2 ? "*#" : str;
        }
        if (str.length() == 3) {
            return type == 1 ? "#**" : type == 2 ? "**#" : "#*#";
        }
        if (str.length() == 4) {
            return type == 1 ? "#***" : type == 2 ? "***#" : "#**#";
        }
        if (str.length() == 5) {
            return type == 1 ? "##***" : type == 2 ? "***##" : "#***#";
        }
        if (str.length() == 6) {
            return type == 1 ? "##****" : type == 2 ? "****##" : "#****#";
        }
        if (str.length() == 7) {
            return type == 1 ? "###****" : type == 2 ? "****###" : "##****#";
        }
        if (type == 1) {
            res.append("####");
            for (int i = 4; i < str.length(); i++) {
                res.append("*");
            }
        } else if (type == 2) {
            for (int i2 = 0; i2 < str.length() - 4; i2++) {
                res.append("*");
            }
            res.append("####");
        } else {
            res.append("##");
            for (int i3 = 2; i3 < str.length() - 2; i3++) {
                res.append("*");
            }
        }
        return res.toString();
    }

    boolean hasIntlPrefix() {
        return (this.flag12 & 2) != 0;
    }

    boolean hasTrunkPrefix() {
        return (this.flag12 & 1) != 0;
    }
}
