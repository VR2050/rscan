package im.uwrkaxlmjj.phoneformat;

import im.uwrkaxlmjj.messenger.FileLog;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashMap;
import org.slf4j.Marker;

/* JADX INFO: loaded from: classes2.dex */
public class PhoneFormat {
    private static volatile PhoneFormat Instance = null;
    public ByteBuffer buffer;
    public HashMap<String, ArrayList<String>> callingCodeCountries;
    public HashMap<String, CallingCodeInfo> callingCodeData;
    public HashMap<String, Integer> callingCodeOffsets;
    public HashMap<String, String> countryCallingCode;
    public byte[] data;
    public String defaultCallingCode;
    public String defaultCountry;
    private boolean initialzed = false;

    public static PhoneFormat getInstance() {
        PhoneFormat localInstance = Instance;
        if (localInstance == null) {
            synchronized (PhoneFormat.class) {
                localInstance = Instance;
                if (localInstance == null) {
                    PhoneFormat phoneFormat = new PhoneFormat();
                    localInstance = phoneFormat;
                    Instance = phoneFormat;
                }
            }
        }
        return localInstance;
    }

    public static String strip(String str) {
        StringBuilder res = new StringBuilder(str);
        for (int i = res.length() - 1; i >= 0; i--) {
            if (!"0123456789+*#".contains(res.substring(i, i + 1))) {
                res.deleteCharAt(i);
            }
        }
        return res.toString();
    }

    public static String stripExceptNumbers(String str, boolean includePlus) {
        if (str == null) {
            return null;
        }
        StringBuilder res = new StringBuilder(str);
        String phoneChars = includePlus ? "0123456789" + Marker.ANY_NON_NULL_MARKER : "0123456789";
        for (int i = res.length() - 1; i >= 0; i--) {
            if (!phoneChars.contains(res.substring(i, i + 1))) {
                res.deleteCharAt(i);
            }
        }
        return res.toString();
    }

    public static String stripExceptNumbers(String str) {
        return stripExceptNumbers(str, false);
    }

    public PhoneFormat() {
        init(null);
    }

    public PhoneFormat(String countryCode) {
        init(countryCode);
    }

    /* JADX WARN: Removed duplicated region for block: B:57:0x00b9 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:68:0x00ad A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:73:? A[DONT_GENERATE, FINALLY_INSNS, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void init(java.lang.String r9) {
        /*
            r8 = this;
            r0 = 0
            r1 = 0
            android.content.Context r2 = im.uwrkaxlmjj.messenger.ApplicationLoader.applicationContext     // Catch: java.lang.Throwable -> L8c java.lang.Exception -> L8e
            android.content.res.AssetManager r2 = r2.getAssets()     // Catch: java.lang.Throwable -> L8c java.lang.Exception -> L8e
            java.lang.String r3 = "PhoneFormats.dat"
            java.io.InputStream r2 = r2.open(r3)     // Catch: java.lang.Throwable -> L8c java.lang.Exception -> L8e
            r0 = r2
            java.io.ByteArrayOutputStream r2 = new java.io.ByteArrayOutputStream     // Catch: java.lang.Throwable -> L8c java.lang.Exception -> L8e
            r2.<init>()     // Catch: java.lang.Throwable -> L8c java.lang.Exception -> L8e
            r1 = r2
            r2 = 1024(0x400, float:1.435E-42)
            byte[] r3 = new byte[r2]     // Catch: java.lang.Throwable -> L8c java.lang.Exception -> L8e
        L19:
            r4 = 0
            int r5 = r0.read(r3, r4, r2)     // Catch: java.lang.Throwable -> L8c java.lang.Exception -> L8e
            r6 = r5
            r7 = -1
            if (r5 == r7) goto L26
            r1.write(r3, r4, r6)     // Catch: java.lang.Throwable -> L8c java.lang.Exception -> L8e
            goto L19
        L26:
            byte[] r2 = r1.toByteArray()     // Catch: java.lang.Throwable -> L8c java.lang.Exception -> L8e
            r8.data = r2     // Catch: java.lang.Throwable -> L8c java.lang.Exception -> L8e
            java.nio.ByteBuffer r2 = java.nio.ByteBuffer.wrap(r2)     // Catch: java.lang.Throwable -> L8c java.lang.Exception -> L8e
            r8.buffer = r2     // Catch: java.lang.Throwable -> L8c java.lang.Exception -> L8e
            java.nio.ByteOrder r4 = java.nio.ByteOrder.LITTLE_ENDIAN     // Catch: java.lang.Throwable -> L8c java.lang.Exception -> L8e
            r2.order(r4)     // Catch: java.lang.Throwable -> L8c java.lang.Exception -> L8e
            r1.close()     // Catch: java.lang.Exception -> L3c
            goto L40
        L3c:
            r2 = move-exception
            im.uwrkaxlmjj.messenger.FileLog.e(r2)
        L40:
            if (r0 == 0) goto L4b
            r0.close()     // Catch: java.lang.Exception -> L46
            goto L4b
        L46:
            r2 = move-exception
            im.uwrkaxlmjj.messenger.FileLog.e(r2)
            goto L4c
        L4b:
        L4c:
            if (r9 == 0) goto L57
            int r2 = r9.length()
            if (r2 == 0) goto L57
            r8.defaultCountry = r9
            goto L65
        L57:
            java.util.Locale r2 = java.util.Locale.getDefault()
            java.lang.String r3 = r2.getCountry()
            java.lang.String r3 = r3.toLowerCase()
            r8.defaultCountry = r3
        L65:
            java.util.HashMap r2 = new java.util.HashMap
            r3 = 255(0xff, float:3.57E-43)
            r2.<init>(r3)
            r8.callingCodeOffsets = r2
            java.util.HashMap r2 = new java.util.HashMap
            r2.<init>(r3)
            r8.callingCodeCountries = r2
            java.util.HashMap r2 = new java.util.HashMap
            r4 = 10
            r2.<init>(r4)
            r8.callingCodeData = r2
            java.util.HashMap r2 = new java.util.HashMap
            r2.<init>(r3)
            r8.countryCallingCode = r2
            r8.parseDataHeader()
            r2 = 1
            r8.initialzed = r2
            return
        L8c:
            r2 = move-exception
            goto Lab
        L8e:
            r2 = move-exception
            r2.printStackTrace()     // Catch: java.lang.Throwable -> L8c
            if (r1 == 0) goto L9d
            r1.close()     // Catch: java.lang.Exception -> L98
            goto L9d
        L98:
            r3 = move-exception
            im.uwrkaxlmjj.messenger.FileLog.e(r3)
            goto L9e
        L9d:
        L9e:
            if (r0 == 0) goto La9
            r0.close()     // Catch: java.lang.Exception -> La4
            goto La9
        La4:
            r3 = move-exception
            im.uwrkaxlmjj.messenger.FileLog.e(r3)
            goto Laa
        La9:
        Laa:
            return
        Lab:
            if (r1 == 0) goto Lb6
            r1.close()     // Catch: java.lang.Exception -> Lb1
            goto Lb6
        Lb1:
            r3 = move-exception
            im.uwrkaxlmjj.messenger.FileLog.e(r3)
            goto Lb7
        Lb6:
        Lb7:
            if (r0 == 0) goto Lc2
            r0.close()     // Catch: java.lang.Exception -> Lbd
            goto Lc2
        Lbd:
            r3 = move-exception
            im.uwrkaxlmjj.messenger.FileLog.e(r3)
            goto Lc3
        Lc2:
        Lc3:
            throw r2
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.phoneformat.PhoneFormat.init(java.lang.String):void");
    }

    public String defaultCallingCode() {
        return callingCodeForCountryCode(this.defaultCountry);
    }

    public String callingCodeForCountryCode(String countryCode) {
        return this.countryCallingCode.get(countryCode.toLowerCase());
    }

    public ArrayList countriesForCallingCode(String callingCode) {
        if (callingCode.startsWith(Marker.ANY_NON_NULL_MARKER)) {
            callingCode = callingCode.substring(1);
        }
        return this.callingCodeCountries.get(callingCode);
    }

    public CallingCodeInfo findCallingCodeInfo(String str) {
        CallingCodeInfo res = null;
        for (int i = 0; i < 3 && i < str.length() && (res = callingCodeInfo(str.substring(0, i + 1))) == null; i++) {
        }
        return res;
    }

    public String format(String orig) {
        if (!this.initialzed) {
            return orig;
        }
        try {
            String str = strip(orig);
            if (str.startsWith(Marker.ANY_NON_NULL_MARKER)) {
                String rest = str.substring(1);
                CallingCodeInfo info = findCallingCodeInfo(rest);
                if (info != null) {
                    String phone = info.format(rest);
                    return Marker.ANY_NON_NULL_MARKER + phone;
                }
                return orig;
            }
            CallingCodeInfo info2 = callingCodeInfo(this.defaultCallingCode);
            if (info2 == null) {
                return orig;
            }
            String accessCode = info2.matchingAccessCode(str);
            if (accessCode != null) {
                String rest2 = str.substring(accessCode.length());
                String phone2 = rest2;
                CallingCodeInfo info22 = findCallingCodeInfo(rest2);
                if (info22 != null) {
                    phone2 = info22.format(rest2);
                }
                if (phone2.length() == 0) {
                    return accessCode;
                }
                return String.format("%s %s", accessCode, phone2);
            }
            return info2.format(str);
        } catch (Exception e) {
            FileLog.e(e);
            return orig;
        }
    }

    public String desensitization(String orig) {
        if (!this.initialzed) {
            return orig;
        }
        try {
            String str = strip(orig);
            if (str.startsWith(Marker.ANY_NON_NULL_MARKER)) {
                String rest = str.substring(1);
                CallingCodeInfo info = findCallingCodeInfo(rest);
                if (info != null) {
                    String phone = info.desensitization(rest);
                    return Marker.ANY_NON_NULL_MARKER + phone;
                }
                return orig;
            }
            CallingCodeInfo info2 = callingCodeInfo(this.defaultCallingCode);
            if (info2 == null) {
                return orig;
            }
            String accessCode = info2.matchingAccessCode(str);
            if (accessCode != null) {
                String rest2 = str.substring(accessCode.length());
                String phone2 = rest2;
                CallingCodeInfo info22 = findCallingCodeInfo(rest2);
                if (info22 != null) {
                    phone2 = info22.desensitization(rest2);
                }
                if (phone2.length() == 0) {
                    return accessCode;
                }
                return String.format("%s %s", accessCode, phone2);
            }
            return info2.desensitization(str);
        } catch (Exception e) {
            FileLog.e(e);
            return orig;
        }
    }

    public boolean isPhoneNumberValid(String phoneNumber) {
        CallingCodeInfo info2;
        if (!this.initialzed) {
            return true;
        }
        String str = strip(phoneNumber);
        if (str.startsWith(Marker.ANY_NON_NULL_MARKER)) {
            String rest = str.substring(1);
            CallingCodeInfo info = findCallingCodeInfo(rest);
            return info != null && info.isValidPhoneNumber(rest);
        }
        CallingCodeInfo info3 = callingCodeInfo(this.defaultCallingCode);
        if (info3 == null) {
            return false;
        }
        String accessCode = info3.matchingAccessCode(str);
        if (accessCode != null) {
            String rest2 = str.substring(accessCode.length());
            return (rest2.length() == 0 || (info2 = findCallingCodeInfo(rest2)) == null || !info2.isValidPhoneNumber(rest2)) ? false : true;
        }
        return info3.isValidPhoneNumber(str);
    }

    int value32(int offset) {
        if (offset + 4 <= this.data.length) {
            this.buffer.position(offset);
            return this.buffer.getInt();
        }
        return 0;
    }

    short value16(int offset) {
        if (offset + 2 <= this.data.length) {
            this.buffer.position(offset);
            return this.buffer.getShort();
        }
        return (short) 0;
    }

    public String valueString(int offset) {
        for (int a = offset; a < this.data.length; a++) {
            try {
                if (this.data[a] == 0) {
                    if (offset == a - offset) {
                        return "";
                    }
                    return new String(this.data, offset, a - offset);
                }
            } catch (Exception e) {
                e.printStackTrace();
                return "";
            }
        }
        return "";
    }

    public CallingCodeInfo callingCodeInfo(String callingCode) {
        Integer num;
        int start;
        int offset;
        int block1Len;
        boolean z;
        PhoneFormat phoneFormat = this;
        CallingCodeInfo res = phoneFormat.callingCodeData.get(callingCode);
        if (res == null && (num = phoneFormat.callingCodeOffsets.get(callingCode)) != null) {
            byte[] bytes = phoneFormat.data;
            int start2 = num.intValue();
            res = new CallingCodeInfo();
            res.callingCode = callingCode;
            res.countries = phoneFormat.callingCodeCountries.get(callingCode);
            phoneFormat.callingCodeData.put(callingCode, res);
            int block1Len2 = phoneFormat.value16(start2);
            int offset2 = start2 + 2 + 2;
            int block2Len = phoneFormat.value16(offset2);
            int offset3 = offset2 + 2 + 2;
            int setCnt = phoneFormat.value16(offset3);
            int offset4 = offset3 + 2 + 2;
            ArrayList<String> strs = new ArrayList<>(5);
            while (true) {
                String str = phoneFormat.valueString(offset4);
                if (str.length() == 0) {
                    break;
                }
                strs.add(str);
                offset4 += str.length() + 1;
            }
            res.trunkPrefixes = strs;
            int offset5 = offset4 + 1;
            ArrayList<String> strs2 = new ArrayList<>(5);
            while (true) {
                String str2 = phoneFormat.valueString(offset5);
                if (str2.length() == 0) {
                    break;
                }
                strs2.add(str2);
                offset5 += str2.length() + 1;
            }
            res.intlPrefixes = strs2;
            ArrayList<RuleSet> ruleSets = new ArrayList<>(setCnt);
            int offset6 = start2 + block1Len2;
            int s = 0;
            while (s < setCnt) {
                RuleSet ruleSet = new RuleSet();
                ruleSet.matchLen = phoneFormat.value16(offset6);
                int offset7 = offset6 + 2;
                int ruleCnt = phoneFormat.value16(offset7);
                offset6 = offset7 + 2;
                ArrayList<PhoneRule> rules = new ArrayList<>(ruleCnt);
                Integer num2 = num;
                int r = 0;
                while (r < ruleCnt) {
                    PhoneRule rule = new PhoneRule();
                    int setCnt2 = setCnt;
                    ArrayList<String> strs3 = strs2;
                    rule.minVal = phoneFormat.value32(offset6);
                    int offset8 = offset6 + 4;
                    rule.maxVal = phoneFormat.value32(offset8);
                    int offset9 = offset8 + 4;
                    int offset10 = offset9 + 1;
                    rule.byte8 = bytes[offset9];
                    int offset11 = offset10 + 1;
                    rule.maxLen = bytes[offset10];
                    int offset12 = offset11 + 1;
                    rule.otherFlag = bytes[offset11];
                    int offset13 = offset12 + 1;
                    rule.prefixLen = bytes[offset12];
                    int offset14 = offset13 + 1;
                    rule.flag12 = bytes[offset13];
                    int offset15 = offset14 + 1;
                    rule.flag13 = bytes[offset14];
                    int strOffset = phoneFormat.value16(offset15);
                    int offset16 = offset15 + 2;
                    byte[] bytes2 = bytes;
                    rule.format = phoneFormat.valueString(start2 + block1Len2 + block2Len + strOffset);
                    int openPos = rule.format.indexOf("[[");
                    if (openPos == -1) {
                        start = start2;
                        offset = offset16;
                        block1Len = block1Len2;
                    } else {
                        start = start2;
                        int closePos = rule.format.indexOf("]]");
                        offset = offset16;
                        block1Len = block1Len2;
                        rule.format = String.format("%s%s", rule.format.substring(0, openPos), rule.format.substring(closePos + 2));
                    }
                    rules.add(rule);
                    if (!rule.hasIntlPrefix) {
                        z = true;
                    } else {
                        z = true;
                        ruleSet.hasRuleWithIntlPrefix = true;
                    }
                    if (rule.hasTrunkPrefix) {
                        ruleSet.hasRuleWithTrunkPrefix = z;
                    }
                    r++;
                    phoneFormat = this;
                    offset6 = offset;
                    setCnt = setCnt2;
                    start2 = start;
                    strs2 = strs3;
                    bytes = bytes2;
                    block1Len2 = block1Len;
                }
                ruleSet.rules = rules;
                ruleSets.add(ruleSet);
                s++;
                phoneFormat = this;
                num = num2;
                bytes = bytes;
            }
            res.ruleSets = ruleSets;
        }
        return res;
    }

    public void parseDataHeader() {
        int count = value32(0);
        int base = (count * 12) + 4;
        int spot = 4;
        for (int i = 0; i < count; i++) {
            String callingCode = valueString(spot);
            int spot2 = spot + 4;
            String country = valueString(spot2);
            int spot3 = spot2 + 4;
            int offset = value32(spot3) + base;
            spot = spot3 + 4;
            if (country.equals(this.defaultCountry)) {
                this.defaultCallingCode = callingCode;
            }
            this.countryCallingCode.put(country, callingCode);
            this.callingCodeOffsets.put(callingCode, Integer.valueOf(offset));
            ArrayList<String> countries = this.callingCodeCountries.get(callingCode);
            if (countries == null) {
                countries = new ArrayList<>();
                this.callingCodeCountries.put(callingCode, countries);
            }
            countries.add(country);
        }
        String str = this.defaultCallingCode;
        if (str != null) {
            callingCodeInfo(str);
        }
    }
}
