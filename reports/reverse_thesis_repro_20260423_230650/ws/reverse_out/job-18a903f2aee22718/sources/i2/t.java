package i2;

import java.util.Collections;
import java.util.List;

/* JADX INFO: Access modifiers changed from: package-private */
/* JADX INFO: loaded from: classes.dex */
public abstract class t extends s {
    public static void p(List list) {
        t2.j.f(list, "<this>");
        if (list.size() > 1) {
            Collections.sort(list);
        }
    }
}
