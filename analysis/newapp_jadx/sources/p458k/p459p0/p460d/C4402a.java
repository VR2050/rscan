package p458k.p459p0.p460d;

import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt__StringsJVMKt;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p458k.C4374d;
import p458k.C4381g0;
import p458k.C4389k0;
import p458k.C4487x;
import p458k.C4488y;
import p458k.EnumC4377e0;
import p458k.InterfaceC4369a0;
import p458k.p459p0.p462f.C4413c;

/* renamed from: k.p0.d.a */
/* loaded from: classes3.dex */
public final class C4402a implements InterfaceC4369a0 {

    /* renamed from: a */
    public static final a f11562a = new a(null);

    /* renamed from: b */
    @Nullable
    public final C4374d f11563b;

    /* renamed from: k.p0.d.a$a */
    public static final class a {
        public a(DefaultConstructorMarker defaultConstructorMarker) {
        }

        /* renamed from: a */
        public static final C4389k0 m5041a(a aVar, C4389k0 response) {
            if ((response != null ? response.f11491k : null) == null) {
                return response;
            }
            Intrinsics.checkParameterIsNotNull(response, "response");
            C4381g0 c4381g0 = response.f11485e;
            EnumC4377e0 enumC4377e0 = response.f11486f;
            int i2 = response.f11488h;
            String str = response.f11487g;
            C4487x c4487x = response.f11489i;
            C4488y.a m5279c = response.f11490j.m5279c();
            C4389k0 c4389k0 = response.f11492l;
            C4389k0 c4389k02 = response.f11493m;
            C4389k0 c4389k03 = response.f11494n;
            long j2 = response.f11495o;
            long j3 = response.f11496p;
            C4413c c4413c = response.f11497q;
            if (!(i2 >= 0)) {
                throw new IllegalStateException(C1499a.m626l("code < 0: ", i2).toString());
            }
            if (c4381g0 == null) {
                throw new IllegalStateException("request == null".toString());
            }
            if (enumC4377e0 == null) {
                throw new IllegalStateException("protocol == null".toString());
            }
            if (str != null) {
                return new C4389k0(c4381g0, enumC4377e0, str, i2, c4487x, m5279c.m5285d(), null, c4389k0, c4389k02, c4389k03, j2, j3, c4413c);
            }
            throw new IllegalStateException("message == null".toString());
        }

        /* renamed from: b */
        public final boolean m5042b(String str) {
            return StringsKt__StringsJVMKt.equals("Content-Length", str, true) || StringsKt__StringsJVMKt.equals("Content-Encoding", str, true) || StringsKt__StringsJVMKt.equals("Content-Type", str, true);
        }

        /* renamed from: c */
        public final boolean m5043c(String str) {
            return (StringsKt__StringsJVMKt.equals("Connection", str, true) || StringsKt__StringsJVMKt.equals("Keep-Alive", str, true) || StringsKt__StringsJVMKt.equals("Proxy-Authenticate", str, true) || StringsKt__StringsJVMKt.equals("Proxy-Authorization", str, true) || StringsKt__StringsJVMKt.equals("TE", str, true) || StringsKt__StringsJVMKt.equals("Trailers", str, true) || StringsKt__StringsJVMKt.equals("Transfer-Encoding", str, true) || StringsKt__StringsJVMKt.equals("Upgrade", str, true)) ? false : true;
        }
    }

    public C4402a(@Nullable C4374d c4374d) {
        this.f11563b = c4374d;
    }

    /* JADX WARN: Code restructure failed: missing block: B:383:0x026a, code lost:
    
        if (r5 > 0) goto L128;
     */
    /* JADX WARN: Removed duplicated region for block: B:103:0x0560 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:210:0x077d  */
    /* JADX WARN: Removed duplicated region for block: B:21:0x0106  */
    /* JADX WARN: Removed duplicated region for block: B:231:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:283:0x01c7  */
    /* JADX WARN: Removed duplicated region for block: B:33:0x0131  */
    /* JADX WARN: Removed duplicated region for block: B:414:0x01ae  */
    /* JADX WARN: Removed duplicated region for block: B:60:0x01c0  */
    /* JADX WARN: Removed duplicated region for block: B:65:0x04c0  */
    /* JADX WARN: Removed duplicated region for block: B:70:0x04d7  */
    /* JADX WARN: Removed duplicated region for block: B:82:0x04ff A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:95:0x0519 A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:99:0x0548  */
    /* JADX WARN: Type inference failed for: r1v2 */
    /* JADX WARN: Type inference failed for: r1v27 */
    /* JADX WARN: Type inference failed for: r1v3 */
    /* JADX WARN: Type inference failed for: r1v30, types: [k.g0, k.k0] */
    /* JADX WARN: Type inference failed for: r1v66 */
    @Override // p458k.InterfaceC4369a0
    @org.jetbrains.annotations.NotNull
    /* renamed from: a */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public p458k.C4389k0 mo280a(@org.jetbrains.annotations.NotNull p458k.InterfaceC4369a0.a r41) {
        /*
            Method dump skipped, instructions count: 2175
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p458k.p459p0.p460d.C4402a.mo280a(k.a0$a):k.k0");
    }
}
