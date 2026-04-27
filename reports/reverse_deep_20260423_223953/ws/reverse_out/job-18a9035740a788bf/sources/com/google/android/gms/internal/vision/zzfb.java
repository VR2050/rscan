package com.google.android.gms.internal.vision;

/* JADX INFO: loaded from: classes.dex */
final class zzfb {
    static String zzd(zzbo zzboVar) {
        String str;
        zzfc zzfcVar = new zzfc(zzboVar);
        StringBuilder sb = new StringBuilder(zzfcVar.size());
        for (int i = 0; i < zzfcVar.size(); i++) {
            int iZzl = zzfcVar.zzl(i);
            if (iZzl == 34) {
                str = "\\\"";
            } else if (iZzl == 39) {
                str = "\\'";
            } else if (iZzl != 92) {
                switch (iZzl) {
                    case 7:
                        str = "\\a";
                        break;
                    case 8:
                        str = "\\b";
                        break;
                    case 9:
                        str = "\\t";
                        break;
                    case 10:
                        str = "\\n";
                        break;
                    case 11:
                        str = "\\v";
                        break;
                    case 12:
                        str = "\\f";
                        break;
                    case 13:
                        str = "\\r";
                        break;
                    default:
                        if (iZzl < 32 || iZzl > 126) {
                            sb.append('\\');
                            sb.append((char) (((iZzl >>> 6) & 3) + 48));
                            sb.append((char) (((iZzl >>> 3) & 7) + 48));
                            iZzl = (iZzl & 7) + 48;
                        }
                        sb.append((char) iZzl);
                        continue;
                        break;
                }
            } else {
                str = "\\\\";
            }
            sb.append(str);
        }
        return sb.toString();
    }
}
