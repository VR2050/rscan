package p005b.p199l.p200a.p201a;

import java.util.HashSet;

/* renamed from: b.l.a.a.e0 */
/* loaded from: classes.dex */
public final class C1960e0 {

    /* renamed from: a */
    public static final HashSet<String> f3387a = new HashSet<>();

    /* renamed from: b */
    public static String f3388b = "goog.exo.core";

    /* renamed from: a */
    public static synchronized void m1454a(String str) {
        synchronized (C1960e0.class) {
            if (f3387a.add(str)) {
                f3388b += ", " + str;
            }
        }
    }
}
