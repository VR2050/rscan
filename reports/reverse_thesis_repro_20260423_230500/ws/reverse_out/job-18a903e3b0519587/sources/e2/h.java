package e2;

import android.webkit.MimeTypeMap;

/* JADX INFO: loaded from: classes.dex */
public abstract class h {
    public static String a(String str) {
        return MimeTypeMap.getSingleton().getExtensionFromMimeType(str);
    }

    public static String b(String str) {
        int iLastIndexOf = str.lastIndexOf(46);
        String strSubstring = iLastIndexOf >= 0 ? str.substring(iLastIndexOf + 1) : null;
        if (strSubstring != null) {
            return MimeTypeMap.getSingleton().getMimeTypeFromExtension(strSubstring);
        }
        return null;
    }
}
