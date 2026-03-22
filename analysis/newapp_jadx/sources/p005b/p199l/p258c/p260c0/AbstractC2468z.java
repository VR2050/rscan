package p005b.p199l.p258c.p260c0;

import java.lang.reflect.Modifier;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: b.l.c.c0.z */
/* loaded from: classes2.dex */
public abstract class AbstractC2468z {
    /* renamed from: a */
    public static void m2825a(Class<?> cls) {
        int modifiers = cls.getModifiers();
        if (Modifier.isInterface(modifiers)) {
            throw new UnsupportedOperationException(C1499a.m623j(cls, C1499a.m586H("Interface can't be instantiated! Interface name: ")));
        }
        if (Modifier.isAbstract(modifiers)) {
            throw new UnsupportedOperationException(C1499a.m623j(cls, C1499a.m586H("Abstract class can't be instantiated! Class name: ")));
        }
    }

    /* renamed from: b */
    public abstract <T> T mo2824b(Class<T> cls);
}
