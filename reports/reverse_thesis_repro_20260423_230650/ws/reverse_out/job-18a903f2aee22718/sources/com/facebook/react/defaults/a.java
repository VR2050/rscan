package com.facebook.react.defaults;

import h2.C0562h;
import h2.C0563i;
import h2.n;
import q1.C0655b;
import q1.C0659f;
import q1.C0660g;
import q1.C0661h;

/* JADX INFO: loaded from: classes.dex */
public final class a {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final a f6687a = new a();

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private static d1.f f6688b = d1.f.f9161d;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private static boolean f6689c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private static boolean f6690d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private static boolean f6691e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private static boolean f6692f;

    /* JADX INFO: renamed from: com.facebook.react.defaults.a$a, reason: collision with other inner class name */
    public /* synthetic */ class C0102a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        public static final /* synthetic */ int[] f6693a;

        static {
            int[] iArr = new int[d1.f.values().length];
            try {
                iArr[d1.f.f9159b.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                iArr[d1.f.f9160c.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                iArr[d1.f.f9161d.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            f6693a = iArr;
        }
    }

    private a() {
    }

    public static final boolean a() {
        return f6689c;
    }

    public static final void c(boolean z3, boolean z4, boolean z5) {
        C0563i c0563iB = f6687a.b(z3, z4, z5);
        boolean zBooleanValue = ((Boolean) c0563iB.a()).booleanValue();
        String str = (String) c0563iB.b();
        if (!zBooleanValue) {
            throw new IllegalStateException(str.toString());
        }
        int i3 = C0102a.f6693a[f6688b.ordinal()];
        if (i3 == 1) {
            C0655b.n(new C0660g());
        } else if (i3 == 2) {
            C0655b.n(new C0659f());
        } else {
            if (i3 != 3) {
                throw new C0562h();
            }
            C0655b.n(new C0661h(z4, z5, z3));
        }
        f6689c = z4;
        f6690d = z3;
        f6691e = z4;
        f6692f = z5;
        g.f6699a.a();
    }

    public static /* synthetic */ void d(boolean z3, boolean z4, boolean z5, int i3, Object obj) {
        if ((i3 & 1) != 0) {
            z3 = true;
        }
        if ((i3 & 2) != 0) {
            z4 = true;
        }
        if ((i3 & 4) != 0) {
            z5 = true;
        }
        c(z3, z4, z5);
    }

    public final C0563i b(boolean z3, boolean z4, boolean z5) {
        return (!z4 || z3) ? (!z5 || (z3 && z4)) ? n.a(Boolean.TRUE, "") : n.a(Boolean.FALSE, "bridgelessEnabled=true requires (turboModulesEnabled=true AND fabricEnabled=true) - Please update your DefaultNewArchitectureEntryPoint.load() parameters.") : n.a(Boolean.FALSE, "fabricEnabled=true requires turboModulesEnabled=true (is now false) - Please update your DefaultNewArchitectureEntryPoint.load() parameters.");
    }
}
