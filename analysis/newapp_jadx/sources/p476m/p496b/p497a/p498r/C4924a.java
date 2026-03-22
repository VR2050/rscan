package p476m.p496b.p497a.p498r;

import android.util.Log;
import java.util.logging.Level;
import p005b.p131d.p132a.p133a.C1499a;
import p476m.p496b.p497a.InterfaceC4913g;

/* renamed from: m.b.a.r.a */
/* loaded from: classes3.dex */
public class C4924a implements InterfaceC4913g {

    /* renamed from: a */
    public static final boolean f12571a;

    static {
        boolean z;
        try {
            Class.forName("android.util.Log");
            z = true;
        } catch (ClassNotFoundException unused) {
            z = false;
        }
        f12571a = z;
    }

    public C4924a(String str) {
    }

    @Override // p476m.p496b.p497a.InterfaceC4913g
    /* renamed from: a */
    public void mo5581a(Level level, String str) {
        if (level != Level.OFF) {
            Log.println(m5594c(level), "EventBus", str);
        }
    }

    @Override // p476m.p496b.p497a.InterfaceC4913g
    /* renamed from: b */
    public void mo5582b(Level level, String str, Throwable th) {
        if (level != Level.OFF) {
            int m5594c = m5594c(level);
            StringBuilder m590L = C1499a.m590L(str, "\n");
            m590L.append(Log.getStackTraceString(th));
            Log.println(m5594c, "EventBus", m590L.toString());
        }
    }

    /* renamed from: c */
    public final int m5594c(Level level) {
        int intValue = level.intValue();
        if (intValue < 800) {
            return intValue < 500 ? 2 : 3;
        }
        if (intValue < 900) {
            return 4;
        }
        return intValue < 1000 ? 5 : 6;
    }
}
