package i2;

import java.util.List;

/* JADX INFO: Access modifiers changed from: package-private */
/* JADX INFO: loaded from: classes.dex */
public abstract class v extends u {
    public static List v(List list) {
        t2.j.f(list, "<this>");
        return new J(list);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final int w(List list, int i3) {
        if (i3 >= 0 && i3 <= AbstractC0586n.h(list)) {
            return AbstractC0586n.h(list) - i3;
        }
        throw new IndexOutOfBoundsException("Element index " + i3 + " must be in range [" + new w2.c(0, AbstractC0586n.h(list)) + "].");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final int x(List list, int i3) {
        return AbstractC0586n.h(list) - i3;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final int y(List list, int i3) {
        if (i3 >= 0 && i3 <= list.size()) {
            return list.size() - i3;
        }
        throw new IndexOutOfBoundsException("Position index " + i3 + " must be in range [" + new w2.c(0, list.size()) + "].");
    }
}
