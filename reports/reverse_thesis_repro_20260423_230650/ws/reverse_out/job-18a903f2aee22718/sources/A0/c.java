package A0;

/* JADX INFO: loaded from: classes.dex */
public abstract class c {
    public static boolean a(char c3) {
        return c3 >= '0' && c3 <= '9';
    }

    public static boolean b(char c3) {
        return (c3 >= 'a' && c3 <= 'z') || (c3 >= 'A' && c3 <= 'Z');
    }

    public static boolean c(char c3) {
        return b(c3) || a(c3);
    }

    public static boolean d(CharSequence charSequence, int i3, int i4, int i5, int i6) {
        int i7;
        if (i4 >= charSequence.length() || (i7 = (i4 - i3) + 1) < i5 || i7 > i6) {
            return false;
        }
        while (i3 <= i4) {
            if (!c(charSequence.charAt(i3))) {
                return false;
            }
            i3++;
        }
        return true;
    }

    public static boolean e(CharSequence charSequence, int i3, int i4) {
        return d(charSequence, i3, i4, 3, 8);
    }
}
