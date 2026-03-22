package p476m.p477a.p485b;

/* renamed from: m.a.b.m */
/* loaded from: classes3.dex */
public class C4873m extends Exception {
    private static final long serialVersionUID = -5437299376222011036L;

    public C4873m(String str) {
        super(m5544a(str));
    }

    /* renamed from: a */
    public static String m5544a(String str) {
        char[] charArray = str.toCharArray();
        int i2 = 0;
        while (i2 < charArray.length && charArray[i2] >= ' ') {
            i2++;
        }
        if (i2 == charArray.length) {
            return str;
        }
        StringBuilder sb = new StringBuilder(charArray.length * 2);
        for (int i3 = 0; i3 < charArray.length; i3++) {
            char c2 = charArray[i3];
            if (c2 < ' ') {
                sb.append("[0x");
                String hexString = Integer.toHexString(i3);
                if (hexString.length() == 1) {
                    sb.append("0");
                }
                sb.append(hexString);
                sb.append("]");
            } else {
                sb.append(c2);
            }
        }
        return sb.toString();
    }

    public C4873m(String str, Throwable th) {
        super(m5544a(str));
        initCause(th);
    }
}
