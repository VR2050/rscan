package p005b.p143g.p144a.p164o;

import java.lang.reflect.InvocationTargetException;
import p005b.p131d.p132a.p133a.C1499a;

@Deprecated
/* renamed from: b.g.a.o.e */
/* loaded from: classes.dex */
public final class C1766e {
    /* renamed from: a */
    public static InterfaceC1764c m1064a(String str) {
        try {
            Class<?> cls = Class.forName(str);
            try {
                Object newInstance = cls.getDeclaredConstructor(new Class[0]).newInstance(new Object[0]);
                if (newInstance instanceof InterfaceC1764c) {
                    return (InterfaceC1764c) newInstance;
                }
                throw new RuntimeException(C1499a.m636v("Expected instanceof GlideModule, but found: ", newInstance));
            } catch (IllegalAccessException e2) {
                m1065b(cls, e2);
                throw null;
            } catch (InstantiationException e3) {
                m1065b(cls, e3);
                throw null;
            } catch (NoSuchMethodException e4) {
                m1065b(cls, e4);
                throw null;
            } catch (InvocationTargetException e5) {
                m1065b(cls, e5);
                throw null;
            }
        } catch (ClassNotFoundException e6) {
            throw new IllegalArgumentException("Unable to find GlideModule implementation", e6);
        }
    }

    /* renamed from: b */
    public static void m1065b(Class<?> cls, Exception exc) {
        throw new RuntimeException(C1499a.m635u("Unable to instantiate GlideModule implementation for ", cls), exc);
    }
}
