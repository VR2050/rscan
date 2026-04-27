package z2;

/* JADX INFO: Access modifiers changed from: package-private */
/* JADX INFO: loaded from: classes.dex */
public abstract class s extends r {
    public static String o0(String str, int i3) {
        t2.j.f(str, "<this>");
        if (i3 >= 0) {
            String strSubstring = str.substring(0, w2.d.e(i3, str.length()));
            t2.j.e(strSubstring, "substring(...)");
            return strSubstring;
        }
        throw new IllegalArgumentException(("Requested character count " + i3 + " is less than zero.").toString());
    }
}
