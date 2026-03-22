package p379c.p380a.p383b2.p384n;

import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Lambda;

/* renamed from: c.a.b2.n.n */
/* loaded from: classes2.dex */
public final class C3031n extends Lambda implements Function2<Integer, CoroutineContext.Element, Integer> {

    /* renamed from: c */
    public final /* synthetic */ C3029l f8332c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C3031n(C3029l c3029l) {
        super(2);
        this.f8332c = c3029l;
    }

    /* JADX WARN: Code restructure failed: missing block: B:17:0x002e, code lost:
    
        if (r1 == null) goto L17;
     */
    @Override // kotlin.jvm.functions.Function2
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Integer invoke(java.lang.Integer r4, kotlin.coroutines.CoroutineContext.Element r5) {
        /*
            r3 = this;
            java.lang.Number r4 = (java.lang.Number) r4
            int r4 = r4.intValue()
            kotlin.coroutines.CoroutineContext$Element r5 = (kotlin.coroutines.CoroutineContext.Element) r5
            kotlin.coroutines.CoroutineContext$Key r0 = r5.getKey()
            c.a.b2.n.l r1 = r3.f8332c
            kotlin.coroutines.CoroutineContext r1 = r1.f8329h
            kotlin.coroutines.CoroutineContext$Element r1 = r1.get(r0)
            c.a.d1$a r2 = p379c.p380a.InterfaceC3053d1.f8393b
            if (r0 == r2) goto L1d
            if (r5 == r1) goto L31
            r4 = -2147483648(0xffffffff80000000, float:-0.0)
            goto L33
        L1d:
            c.a.d1 r1 = (p379c.p380a.InterfaceC3053d1) r1
            c.a.d1 r5 = (p379c.p380a.InterfaceC3053d1) r5
        L21:
            if (r5 != 0) goto L25
            r5 = 0
            goto L2c
        L25:
            if (r5 != r1) goto L28
            goto L2c
        L28:
            boolean r0 = r5 instanceof p379c.p380a.p381a.C2968q
            if (r0 != 0) goto L66
        L2c:
            if (r5 != r1) goto L38
            if (r1 != 0) goto L31
            goto L33
        L31:
            int r4 = r4 + 1
        L33:
            java.lang.Integer r4 = java.lang.Integer.valueOf(r4)
            return r4
        L38:
            java.lang.StringBuilder r4 = new java.lang.StringBuilder
            r4.<init>()
            java.lang.String r0 = "Flow invariant is violated:\n\t\tEmission from another coroutine is detected.\n"
            r4.append(r0)
            java.lang.String r0 = "\t\tChild of "
            r4.append(r0)
            r4.append(r5)
            java.lang.String r5 = ", expected child of "
            r4.append(r5)
            r4.append(r1)
            java.lang.String r5 = ".\n"
            java.lang.String r0 = "\t\tFlowCollector is not thread-safe and concurrent emissions are prohibited.\n"
            java.lang.String r1 = "\t\tTo mitigate this restriction please use 'channelFlow' builder instead of 'flow'"
            java.lang.String r4 = p005b.p131d.p132a.p133a.C1499a.m583E(r4, r5, r0, r1)
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r4 = r4.toString()
            r5.<init>(r4)
            throw r5
        L66:
            c.a.a.q r5 = (p379c.p380a.p381a.C2968q) r5
            kotlin.coroutines.CoroutineContext r5 = r5.f8191f
            c.a.d1$a r0 = p379c.p380a.InterfaceC3053d1.f8393b
            kotlin.coroutines.CoroutineContext$Element r5 = r5.get(r0)
            c.a.d1 r5 = (p379c.p380a.InterfaceC3053d1) r5
            goto L21
        */
        throw new UnsupportedOperationException("Method not decompiled: p379c.p380a.p383b2.p384n.C3031n.invoke(java.lang.Object, java.lang.Object):java.lang.Object");
    }
}
