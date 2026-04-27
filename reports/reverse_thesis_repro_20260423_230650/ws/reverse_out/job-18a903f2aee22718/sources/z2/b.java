package z2;

/* JADX INFO: Access modifiers changed from: package-private */
/* JADX INFO: loaded from: classes.dex */
public abstract class b {
    public static int a(int i3) {
        if (2 <= i3 && i3 < 37) {
            return i3;
        }
        throw new IllegalArgumentException("radix " + i3 + " was not in valid range " + new w2.c(2, 36));
    }

    public static final int b(char c3, int i3) {
        return Character.digit((int) c3, i3);
    }

    public static final boolean c(char c3) {
        return Character.isWhitespace(c3) || Character.isSpaceChar(c3);
    }
}
