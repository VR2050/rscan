package p005b.p143g.p144a.p147m.p150t.p152d0;

import java.util.ArrayDeque;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Queue;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/* renamed from: b.g.a.m.t.d0.c */
/* loaded from: classes.dex */
public final class C1627c {

    /* renamed from: a */
    public final Map<String, a> f2105a = new HashMap();

    /* renamed from: b */
    public final b f2106b = new b();

    /* renamed from: b.g.a.m.t.d0.c$a */
    public static class a {

        /* renamed from: a */
        public final Lock f2107a = new ReentrantLock();

        /* renamed from: b */
        public int f2108b;
    }

    /* renamed from: b.g.a.m.t.d0.c$b */
    public static class b {

        /* renamed from: a */
        public final Queue<a> f2109a = new ArrayDeque();
    }

    /* renamed from: a */
    public void m896a(String str) {
        a aVar;
        synchronized (this) {
            a aVar2 = this.f2105a.get(str);
            Objects.requireNonNull(aVar2, "Argument must not be null");
            aVar = aVar2;
            int i2 = aVar.f2108b;
            if (i2 < 1) {
                throw new IllegalStateException("Cannot release a lock that is not held, safeKey: " + str + ", interestedThreads: " + aVar.f2108b);
            }
            int i3 = i2 - 1;
            aVar.f2108b = i3;
            if (i3 == 0) {
                a remove = this.f2105a.remove(str);
                if (!remove.equals(aVar)) {
                    throw new IllegalStateException("Removed the wrong lock, expected to remove: " + aVar + ", but actually removed: " + remove + ", safeKey: " + str);
                }
                b bVar = this.f2106b;
                synchronized (bVar.f2109a) {
                    if (bVar.f2109a.size() < 10) {
                        bVar.f2109a.offer(remove);
                    }
                }
            }
        }
        aVar.f2107a.unlock();
    }
}
