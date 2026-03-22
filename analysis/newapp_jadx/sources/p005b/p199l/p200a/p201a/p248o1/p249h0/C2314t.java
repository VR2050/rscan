package p005b.p199l.p200a.p201a.p248o1.p249h0;

import android.os.ConditionVariable;
import java.util.Objects;

/* renamed from: b.l.a.a.o1.h0.t */
/* loaded from: classes.dex */
public class C2314t extends Thread {

    /* renamed from: c */
    public final /* synthetic */ ConditionVariable f5900c;

    /* renamed from: e */
    public final /* synthetic */ C2315u f5901e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C2314t(C2315u c2315u, String str, ConditionVariable conditionVariable) {
        super(str);
        this.f5901e = c2315u;
        this.f5900c = conditionVariable;
    }

    @Override // java.lang.Thread, java.lang.Runnable
    public void run() {
        synchronized (this.f5901e) {
            this.f5900c.open();
            C2315u.m2254m(this.f5901e);
            Objects.requireNonNull((C2313s) this.f5901e.f5904c);
        }
    }
}
