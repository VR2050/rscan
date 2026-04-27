package z2;

/* JADX INFO: loaded from: classes.dex */
abstract class c extends b {
    public static final boolean d(char c3, char c4, boolean z3) {
        if (c3 == c4) {
            return true;
        }
        if (!z3) {
            return false;
        }
        char upperCase = Character.toUpperCase(c3);
        char upperCase2 = Character.toUpperCase(c4);
        return upperCase == upperCase2 || Character.toLowerCase(upperCase) == Character.toLowerCase(upperCase2);
    }
}
