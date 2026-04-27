package i2;

import java.util.Collections;
import java.util.Set;

/* JADX INFO: loaded from: classes.dex */
abstract class L {
    public static final Set a(Object obj) {
        Set setSingleton = Collections.singleton(obj);
        t2.j.e(setSingleton, "singleton(...)");
        return setSingleton;
    }
}
