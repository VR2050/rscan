package p005b.p143g.p144a.p147m.p150t.p151c0;

import java.util.ArrayDeque;
import java.util.Queue;
import p005b.p143g.p144a.p147m.p150t.p151c0.InterfaceC1622l;
import p005b.p143g.p144a.p170s.C1807i;

/* renamed from: b.g.a.m.t.c0.c */
/* loaded from: classes.dex */
public abstract class AbstractC1613c<T extends InterfaceC1622l> {

    /* renamed from: a */
    public final Queue<T> f2058a;

    public AbstractC1613c() {
        char[] cArr = C1807i.f2767a;
        this.f2058a = new ArrayDeque(20);
    }

    /* renamed from: a */
    public abstract T mo864a();

    /* renamed from: b */
    public T m865b() {
        T poll = this.f2058a.poll();
        return poll == null ? mo864a() : poll;
    }

    /* renamed from: c */
    public void m866c(T t) {
        if (this.f2058a.size() < 20) {
            this.f2058a.offer(t);
        }
    }
}
