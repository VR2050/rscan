package p005b.p143g.p144a.p170s.p171j;

import android.util.Log;
import androidx.annotation.NonNull;
import androidx.core.util.Pools;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p143g.p144a.p170s.p171j.AbstractC1811d;

/* renamed from: b.g.a.s.j.a */
/* loaded from: classes.dex */
public final class C1808a {

    /* renamed from: a */
    public static final e<Object> f2770a = new a();

    /* renamed from: b.g.a.s.j.a$a */
    public class a implements e<Object> {
        @Override // p005b.p143g.p144a.p170s.p171j.C1808a.e
        /* renamed from: a */
        public void mo1154a(@NonNull Object obj) {
        }
    }

    /* renamed from: b.g.a.s.j.a$b */
    public interface b<T> {
        T create();
    }

    /* renamed from: b.g.a.s.j.a$c */
    public static final class c<T> implements Pools.Pool<T> {

        /* renamed from: a */
        public final b<T> f2771a;

        /* renamed from: b */
        public final e<T> f2772b;

        /* renamed from: c */
        public final Pools.Pool<T> f2773c;

        public c(@NonNull Pools.Pool<T> pool, @NonNull b<T> bVar, @NonNull e<T> eVar) {
            this.f2773c = pool;
            this.f2771a = bVar;
            this.f2772b = eVar;
        }

        @Override // androidx.core.util.Pools.Pool
        public T acquire() {
            T acquire = this.f2773c.acquire();
            if (acquire == null) {
                acquire = this.f2771a.create();
                if (Log.isLoggable("FactoryPools", 2)) {
                    StringBuilder m586H = C1499a.m586H("Created new ");
                    m586H.append(acquire.getClass());
                    m586H.toString();
                }
            }
            if (acquire instanceof d) {
                ((AbstractC1811d.b) acquire.mo903b()).f2774a = false;
            }
            return (T) acquire;
        }

        @Override // androidx.core.util.Pools.Pool
        public boolean release(@NonNull T t) {
            if (t instanceof d) {
                ((AbstractC1811d.b) ((d) t).mo903b()).f2774a = true;
            }
            this.f2772b.mo1154a(t);
            return this.f2773c.release(t);
        }
    }

    /* renamed from: b.g.a.s.j.a$d */
    public interface d {
        @NonNull
        /* renamed from: b */
        AbstractC1811d mo903b();
    }

    /* renamed from: b.g.a.s.j.a$e */
    public interface e<T> {
        /* renamed from: a */
        void mo1154a(@NonNull T t);
    }

    @NonNull
    /* renamed from: a */
    public static <T extends d> Pools.Pool<T> m1153a(int i2, @NonNull b<T> bVar) {
        return new c(new Pools.SynchronizedPool(i2), bVar, f2770a);
    }
}
