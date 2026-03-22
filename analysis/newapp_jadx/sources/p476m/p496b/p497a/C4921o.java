package p476m.p496b.p497a;

import java.lang.reflect.Method;
import org.greenrobot.eventbus.ThreadMode;

/* renamed from: m.b.a.o */
/* loaded from: classes3.dex */
public class C4921o {

    /* renamed from: a */
    public final Method f12553a;

    /* renamed from: b */
    public final ThreadMode f12554b;

    /* renamed from: c */
    public final Class<?> f12555c;

    /* renamed from: d */
    public final int f12556d;

    /* renamed from: e */
    public final boolean f12557e;

    /* renamed from: f */
    public String f12558f;

    public C4921o(Method method, Class<?> cls, ThreadMode threadMode, int i2, boolean z) {
        this.f12553a = method;
        this.f12554b = threadMode;
        this.f12555c = cls;
        this.f12556d = i2;
        this.f12557e = z;
    }

    /* renamed from: a */
    public final synchronized void m5587a() {
        if (this.f12558f == null) {
            StringBuilder sb = new StringBuilder(64);
            sb.append(this.f12553a.getDeclaringClass().getName());
            sb.append('#');
            sb.append(this.f12553a.getName());
            sb.append('(');
            sb.append(this.f12555c.getName());
            this.f12558f = sb.toString();
        }
    }

    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof C4921o)) {
            return false;
        }
        m5587a();
        C4921o c4921o = (C4921o) obj;
        c4921o.m5587a();
        return this.f12558f.equals(c4921o.f12558f);
    }

    public int hashCode() {
        return this.f12553a.hashCode();
    }
}
