package h2;

import kotlin.Lazy;
import kotlin.jvm.internal.DefaultConstructorMarker;
import s2.InterfaceC0688a;

/* JADX INFO: Access modifiers changed from: package-private */
/* JADX INFO: renamed from: h2.e, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public abstract class AbstractC0559e {

    /* JADX INFO: renamed from: h2.e$a */
    public /* synthetic */ class a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        public static final /* synthetic */ int[] f9268a;

        static {
            int[] iArr = new int[EnumC0561g.values().length];
            try {
                iArr[EnumC0561g.f9269b.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                iArr[EnumC0561g.f9270c.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                iArr[EnumC0561g.f9271d.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            f9268a = iArr;
        }
    }

    public static Lazy a(EnumC0561g enumC0561g, InterfaceC0688a interfaceC0688a) {
        t2.j.f(enumC0561g, "mode");
        t2.j.f(interfaceC0688a, "initializer");
        int i3 = a.f9268a[enumC0561g.ordinal()];
        int i4 = 2;
        if (i3 == 1) {
            DefaultConstructorMarker defaultConstructorMarker = null;
            return new m(interfaceC0688a, defaultConstructorMarker, i4, defaultConstructorMarker);
        }
        if (i3 == 2) {
            return new l(interfaceC0688a);
        }
        if (i3 == 3) {
            return new s(interfaceC0688a);
        }
        throw new C0562h();
    }

    public static Lazy b(InterfaceC0688a interfaceC0688a) {
        t2.j.f(interfaceC0688a, "initializer");
        DefaultConstructorMarker defaultConstructorMarker = null;
        return new m(interfaceC0688a, defaultConstructorMarker, 2, defaultConstructorMarker);
    }
}
