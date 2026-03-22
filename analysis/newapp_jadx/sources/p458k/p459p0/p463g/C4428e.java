package p458k.p459p0.p463g;

import kotlin.jvm.JvmName;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt__StringsJVMKt;
import org.jetbrains.annotations.NotNull;
import p458k.C4389k0;
import p458k.p459p0.C4401c;
import p474l.C4747i;

@JvmName(name = "HttpHeaders")
/* renamed from: k.p0.g.e */
/* loaded from: classes3.dex */
public final class C4428e {
    static {
        C4747i.a aVar = C4747i.f12136e;
        aVar.m5412c("\"\\");
        aVar.m5412c("\t ,=");
    }

    /* renamed from: a */
    public static final boolean m5135a(@NotNull C4389k0 promisesBody) {
        Intrinsics.checkParameterIsNotNull(promisesBody, "$this$promisesBody");
        if (Intrinsics.areEqual(promisesBody.f11485e.f11441c, "HEAD")) {
            return false;
        }
        int i2 = promisesBody.f11488h;
        return (((i2 >= 100 && i2 < 200) || i2 == 204 || i2 == 304) && C4401c.m5026k(promisesBody) == -1 && !StringsKt__StringsJVMKt.equals("chunked", C4389k0.m4987d(promisesBody, "Transfer-Encoding", null, 2), true)) ? false : true;
    }

    /* JADX WARN: Code restructure failed: missing block: B:104:0x021f, code lost:
    
        if (okhttp3.internal.publicsuffix.PublicSuffixDatabase.f12977c.m5696a(r9) == null) goto L124;
     */
    /* JADX WARN: Code restructure failed: missing block: B:122:0x020a, code lost:
    
        if (r3 != false) goto L105;
     */
    /* JADX WARN: Code restructure failed: missing block: B:128:0x0206, code lost:
    
        if (p458k.p459p0.C4401c.f11561f.matches(r0) == false) goto L94;
     */
    /* renamed from: b */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void m5136b(@org.jetbrains.annotations.NotNull p458k.InterfaceC4481r r37, @org.jetbrains.annotations.NotNull p458k.C4489z r38, @org.jetbrains.annotations.NotNull p458k.C4488y r39) {
        /*
            Method dump skipped, instructions count: 670
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p458k.p459p0.p463g.C4428e.m5136b(k.r, k.z, k.y):void");
    }
}
