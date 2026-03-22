package p005b.p199l.p200a.p201a.p250p1;

import android.os.Handler;
import java.util.Iterator;
import java.util.concurrent.CopyOnWriteArrayList;
import p005b.p199l.p200a.p201a.p250p1.C2352l;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.p1.l */
/* loaded from: classes.dex */
public final class C2352l<T> {

    /* renamed from: a */
    public final CopyOnWriteArrayList<b<T>> f6069a = new CopyOnWriteArrayList<>();

    /* renamed from: b.l.a.a.p1.l$a */
    public interface a<T> {
        /* renamed from: a */
        void mo2190a(T t);
    }

    /* renamed from: b.l.a.a.p1.l$b */
    public static final class b<T> {

        /* renamed from: a */
        public final Handler f6070a;

        /* renamed from: b */
        public final T f6071b;

        /* renamed from: c */
        public boolean f6072c;

        public b(Handler handler, T t) {
            this.f6070a = handler;
            this.f6071b = t;
        }
    }

    /* renamed from: a */
    public void m2363a(Handler handler, T t) {
        C4195m.m4765F((handler == null || t == null) ? false : true);
        m2365c(t);
        this.f6069a.add(new b<>(handler, t));
    }

    /* renamed from: b */
    public void m2364b(final a<T> aVar) {
        Iterator<b<T>> it = this.f6069a.iterator();
        while (it.hasNext()) {
            final b<T> next = it.next();
            next.f6070a.post(new Runnable() { // from class: b.l.a.a.p1.a
                @Override // java.lang.Runnable
                public final void run() {
                    C2352l.b bVar = C2352l.b.this;
                    C2352l.a aVar2 = aVar;
                    if (bVar.f6072c) {
                        return;
                    }
                    aVar2.mo2190a(bVar.f6071b);
                }
            });
        }
    }

    /* renamed from: c */
    public void m2365c(T t) {
        Iterator<b<T>> it = this.f6069a.iterator();
        while (it.hasNext()) {
            b<T> next = it.next();
            if (next.f6071b == t) {
                next.f6072c = true;
                this.f6069a.remove(next);
            }
        }
    }
}
