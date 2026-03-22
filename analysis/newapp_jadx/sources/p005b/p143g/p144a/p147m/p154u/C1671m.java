package p005b.p143g.p144a.p147m.p154u;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.VisibleForTesting;
import java.util.ArrayDeque;
import java.util.Objects;
import java.util.Queue;
import p005b.p143g.p144a.p170s.C1804f;
import p005b.p143g.p144a.p170s.C1807i;

/* renamed from: b.g.a.m.u.m */
/* loaded from: classes.dex */
public class C1671m<A, B> {

    /* renamed from: a */
    public final C1804f<b<A>, B> f2376a;

    /* renamed from: b.g.a.m.u.m$a */
    public class a extends C1804f<b<A>, B> {
        public a(C1671m c1671m, long j2) {
            super(j2);
        }

        @Override // p005b.p143g.p144a.p170s.C1804f
        /* renamed from: c */
        public void mo900c(@NonNull Object obj, @Nullable Object obj2) {
            b<?> bVar = (b) obj;
            Objects.requireNonNull(bVar);
            Queue<b<?>> queue = b.f2377a;
            synchronized (queue) {
                queue.offer(bVar);
            }
        }
    }

    @VisibleForTesting
    /* renamed from: b.g.a.m.u.m$b */
    public static final class b<A> {

        /* renamed from: a */
        public static final Queue<b<?>> f2377a;

        /* renamed from: b */
        public int f2378b;

        /* renamed from: c */
        public int f2379c;

        /* renamed from: d */
        public A f2380d;

        static {
            char[] cArr = C1807i.f2767a;
            f2377a = new ArrayDeque(0);
        }

        /* renamed from: a */
        public static <A> b<A> m976a(A a, int i2, int i3) {
            b<A> bVar;
            Queue<b<?>> queue = f2377a;
            synchronized (queue) {
                bVar = (b) queue.poll();
            }
            if (bVar == null) {
                bVar = new b<>();
            }
            bVar.f2380d = a;
            bVar.f2379c = i2;
            bVar.f2378b = i3;
            return bVar;
        }

        public boolean equals(Object obj) {
            if (!(obj instanceof b)) {
                return false;
            }
            b bVar = (b) obj;
            return this.f2379c == bVar.f2379c && this.f2378b == bVar.f2378b && this.f2380d.equals(bVar.f2380d);
        }

        public int hashCode() {
            return this.f2380d.hashCode() + (((this.f2378b * 31) + this.f2379c) * 31);
        }
    }

    public C1671m(long j2) {
        this.f2376a = new a(this, j2);
    }
}
