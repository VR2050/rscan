package p379c.p380a;

import kotlin.coroutines.ContinuationInterceptor;
import kotlin.coroutines.CoroutineContext;
import org.jetbrains.annotations.NotNull;

/* renamed from: c.a.a0 */
/* loaded from: classes2.dex */
public final class C2976a0 {

    /* renamed from: a */
    public static final boolean f8141a;

    /* JADX WARN: Code restructure failed: missing block: B:18:0x0028, code lost:
    
        if (r0.equals("on") != false) goto L19;
     */
    /* JADX WARN: Code restructure failed: missing block: B:20:0x0031, code lost:
    
        if (r0.equals("") != false) goto L19;
     */
    static {
        /*
            java.lang.String r0 = "kotlinx.coroutines.scheduler"
            java.lang.String r0 = p005b.p199l.p200a.p201a.p250p1.C2354n.m2421P1(r0)
            if (r0 != 0) goto L9
            goto L33
        L9:
            int r1 = r0.hashCode()
            if (r1 == 0) goto L2b
            r2 = 3551(0xddf, float:4.976E-42)
            if (r1 == r2) goto L22
            r2 = 109935(0x1ad6f, float:1.54052E-40)
            if (r1 != r2) goto L37
            java.lang.String r1 = "off"
            boolean r1 = r0.equals(r1)
            if (r1 == 0) goto L37
            r0 = 0
            goto L34
        L22:
            java.lang.String r1 = "on"
            boolean r1 = r0.equals(r1)
            if (r1 == 0) goto L37
            goto L33
        L2b:
            java.lang.String r1 = ""
            boolean r1 = r0.equals(r1)
            if (r1 == 0) goto L37
        L33:
            r0 = 1
        L34:
            p379c.p380a.C2976a0.f8141a = r0
            return
        L37:
            java.lang.StringBuilder r1 = new java.lang.StringBuilder
            r1.<init>()
            java.lang.String r2 = "System property 'kotlinx.coroutines.scheduler' has unrecognized value '"
            r1.append(r2)
            r1.append(r0)
            r0 = 39
            r1.append(r0)
            java.lang.String r0 = r1.toString()
            java.lang.IllegalStateException r1 = new java.lang.IllegalStateException
            java.lang.String r0 = r0.toString()
            r1.<init>(r0)
            throw r1
        */
        throw new UnsupportedOperationException("Method not decompiled: p379c.p380a.C2976a0.<clinit>():void");
    }

    @NotNull
    /* renamed from: a */
    public static final CoroutineContext m3455a(@NotNull InterfaceC3055e0 interfaceC3055e0, @NotNull CoroutineContext coroutineContext) {
        CoroutineContext plus = interfaceC3055e0.getCoroutineContext().plus(coroutineContext);
        AbstractC3036c0 abstractC3036c0 = C3079m0.f8430a;
        return (plus == abstractC3036c0 || plus.get(ContinuationInterceptor.INSTANCE) != null) ? plus : plus.plus(abstractC3036c0);
    }
}
