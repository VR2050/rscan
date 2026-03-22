package p379c.p380a;

import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;

/* renamed from: c.a.l */
/* loaded from: classes2.dex */
public final class C3075l extends C3108w {

    /* renamed from: c */
    public static final AtomicIntegerFieldUpdater f8427c = AtomicIntegerFieldUpdater.newUpdater(C3075l.class, "_resumed");
    public volatile int _resumed;

    /* JADX WARN: Illegal instructions before constructor call */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public C3075l(@org.jetbrains.annotations.NotNull kotlin.coroutines.Continuation<?> r3, @org.jetbrains.annotations.Nullable java.lang.Throwable r4, boolean r5) {
        /*
            r2 = this;
            if (r4 == 0) goto L3
            goto L1e
        L3:
            java.util.concurrent.CancellationException r4 = new java.util.concurrent.CancellationException
            java.lang.StringBuilder r0 = new java.lang.StringBuilder
            r0.<init>()
            java.lang.String r1 = "Continuation "
            r0.append(r1)
            r0.append(r3)
            java.lang.String r3 = " was cancelled normally"
            r0.append(r3)
            java.lang.String r3 = r0.toString()
            r4.<init>(r3)
        L1e:
            r2.<init>(r4, r5)
            r3 = 0
            r2._resumed = r3
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: p379c.p380a.C3075l.<init>(kotlin.coroutines.Continuation, java.lang.Throwable, boolean):void");
    }
}
