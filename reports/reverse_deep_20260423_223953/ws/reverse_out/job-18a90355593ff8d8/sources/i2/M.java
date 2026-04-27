package i2;

import java.util.Set;

/* JADX INFO: Access modifiers changed from: package-private */
/* JADX INFO: loaded from: classes.dex */
public abstract class M extends L {
    public static Set b() {
        return C0572B.f9332b;
    }

    public static final Set c(Set set) {
        t2.j.f(set, "<this>");
        int size = set.size();
        return size != 0 ? size != 1 ? set : L.a(set.iterator().next()) : K.b();
    }
}
