package p005b.p327w.p330b.p331b;

import android.app.Application;
import java.util.ArrayList;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.Nullable;
import p005b.p190k.p191a.p192a.C1882c;

/* renamed from: b.w.b.b.a */
/* loaded from: classes2.dex */
public class ApplicationC2828a extends Application {

    /* renamed from: c */
    public static ApplicationC2828a f7672c;

    /* renamed from: e */
    @Nullable
    public static List<InterfaceC2829b> f7673e;

    /* renamed from: a */
    public static final void m3280a() {
        List<InterfaceC2829b> m3281b = m3281b();
        Intrinsics.checkNotNull(m3281b);
        for (InterfaceC2829b interfaceC2829b : m3281b) {
            interfaceC2829b.loadingCurrentTheme();
            interfaceC2829b.notifyThemeChanged();
        }
    }

    /* renamed from: b */
    public static final List<InterfaceC2829b> m3281b() {
        if (f7673e == null) {
            f7673e = new ArrayList();
        }
        return f7673e;
    }

    /* renamed from: c */
    public static final void m3282c(@Nullable InterfaceC2829b interfaceC2829b) {
        List<InterfaceC2829b> m3281b = m3281b();
        Intrinsics.checkNotNull(m3281b);
        if (m3281b.contains(interfaceC2829b)) {
            return;
        }
        List<InterfaceC2829b> m3281b2 = m3281b();
        Intrinsics.checkNotNull(m3281b2);
        m3281b2.add(interfaceC2829b);
    }

    @Override // android.app.Application
    public void onCreate() {
        super.onCreate();
        Intrinsics.checkNotNullParameter(this, "<set-?>");
        f7672c = this;
        if (C1882c.f2913c == null) {
            C1882c.f2913c = new C1882c();
        }
        registerActivityLifecycleCallbacks(C1882c.f2913c);
    }
}
