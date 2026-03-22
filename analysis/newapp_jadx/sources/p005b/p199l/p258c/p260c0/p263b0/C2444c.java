package p005b.p199l.p258c.p260c0.p263b0;

import java.lang.reflect.AccessibleObject;
import java.lang.reflect.Field;
import p005b.p199l.p258c.C2486p;

/* renamed from: b.l.c.c0.b0.c */
/* loaded from: classes2.dex */
public final class C2444c extends AbstractC2443b {

    /* renamed from: b */
    public static Class f6584b;

    /* renamed from: c */
    public final Object f6585c;

    /* renamed from: d */
    public final Field f6586d;

    public C2444c() {
        Object obj;
        Field field = null;
        try {
            Class<?> cls = Class.forName("sun.misc.Unsafe");
            f6584b = cls;
            Field declaredField = cls.getDeclaredField("theUnsafe");
            declaredField.setAccessible(true);
            obj = declaredField.get(null);
        } catch (Exception unused) {
            obj = null;
        }
        this.f6585c = obj;
        try {
            field = AccessibleObject.class.getDeclaredField("override");
        } catch (NoSuchFieldException unused2) {
        }
        this.f6586d = field;
    }

    @Override // p005b.p199l.p258c.p260c0.p263b0.AbstractC2443b
    /* renamed from: a */
    public void mo2811a(AccessibleObject accessibleObject) {
        boolean z = false;
        if (this.f6585c != null && this.f6586d != null) {
            try {
                f6584b.getMethod("putBoolean", Object.class, Long.TYPE, Boolean.TYPE).invoke(this.f6585c, accessibleObject, Long.valueOf(((Long) f6584b.getMethod("objectFieldOffset", Field.class).invoke(this.f6585c, this.f6586d)).longValue()), Boolean.TRUE);
                z = true;
            } catch (Exception unused) {
            }
        }
        if (z) {
            return;
        }
        try {
            accessibleObject.setAccessible(true);
        } catch (SecurityException e2) {
            throw new C2486p("Gson couldn't modify fields for " + accessibleObject + "\nand sun.misc.Unsafe not found.\nEither write a custom type adapter, or make fields accessible, or include sun.misc.Unsafe.", e2);
        }
    }
}
