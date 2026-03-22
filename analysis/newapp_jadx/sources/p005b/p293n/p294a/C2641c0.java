package p005b.p293n.p294a;

import android.app.Activity;
import android.os.Bundle;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.Random;
import java.util.concurrent.atomic.AtomicInteger;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p293n.p294a.C2641c0;

/* renamed from: b.n.a.c0 */
/* loaded from: classes2.dex */
public final class C2641c0 {

    /* renamed from: a */
    @Nullable
    public InterfaceC2652i f7199a;

    /* renamed from: b */
    @Nullable
    public InterfaceC2656k f7200b;

    /* renamed from: c */
    public final Activity f7201c;

    /* renamed from: d */
    public final List<String> f7202d;

    /* renamed from: b.n.a.c0$a */
    public class a implements Runnable {

        /* renamed from: c */
        public final /* synthetic */ AtomicInteger f7203c;

        /* renamed from: e */
        public final /* synthetic */ List f7204e;

        /* renamed from: f */
        public final /* synthetic */ Activity f7205f;

        /* renamed from: g */
        public final /* synthetic */ Runnable f7206g;

        public a(AtomicInteger atomicInteger, List list, Activity activity, Runnable runnable) {
            this.f7203c = atomicInteger;
            this.f7204e = list;
            this.f7205f = activity;
            this.f7206g = runnable;
        }

        @Override // java.lang.Runnable
        public void run() {
            this.f7203c.incrementAndGet();
            if (this.f7203c.get() < this.f7204e.size()) {
                C2641c0.m3112d(this.f7205f, (String) this.f7204e.get(this.f7203c.get()), this);
            } else {
                this.f7206g.run();
            }
        }
    }

    /* renamed from: b.n.a.c0$b */
    public class b implements InterfaceC2658l {

        /* renamed from: a */
        public final /* synthetic */ Runnable f7207a;

        public b(Runnable runnable) {
            this.f7207a = runnable;
        }
    }

    /* renamed from: b.n.a.c0$c */
    public class c implements Runnable {

        /* renamed from: c */
        public final /* synthetic */ AtomicInteger f7208c;

        /* renamed from: e */
        public final /* synthetic */ List f7209e;

        /* renamed from: f */
        public final /* synthetic */ Activity f7210f;

        /* renamed from: g */
        public final /* synthetic */ Runnable f7211g;

        public c(AtomicInteger atomicInteger, List list, Activity activity, Runnable runnable) {
            this.f7208c = atomicInteger;
            this.f7209e = list;
            this.f7210f = activity;
            this.f7211g = runnable;
        }

        @Override // java.lang.Runnable
        public void run() {
            boolean z;
            this.f7208c.incrementAndGet();
            if (this.f7208c.get() >= this.f7209e.size()) {
                this.f7211g.run();
                return;
            }
            final List list = (List) this.f7209e.get(this.f7208c.get());
            Iterator<String> it = C2643d0.f7218e.iterator();
            while (true) {
                if (!it.hasNext()) {
                    z = false;
                    break;
                } else if (list.contains(it.next())) {
                    z = true;
                    break;
                }
            }
            long j2 = (z && C2354n.m2384D0()) ? 150L : 0L;
            if (j2 == 0) {
                C2641c0.m3111c(this.f7210f, list, this);
            } else {
                final Activity activity = this.f7210f;
                C2645e0.f7223a.postDelayed(new Runnable() { // from class: b.n.a.a
                    @Override // java.lang.Runnable
                    public final void run() {
                        C2641c0.c cVar = C2641c0.c.this;
                        Activity activity2 = activity;
                        List list2 = list;
                        Objects.requireNonNull(cVar);
                        C2641c0.m3111c(activity2, list2, cVar);
                    }
                }, j2);
            }
        }
    }

    public C2641c0(@NonNull Activity activity, @NonNull List<String> list) {
        this.f7201c = activity;
        this.f7202d = list;
    }

    /* renamed from: a */
    public static void m3109a(@NonNull Activity activity, @NonNull List<List<String>> list, @NonNull Runnable runnable) {
        if (!C2354n.m2390F0()) {
            runnable.run();
        } else if (list.isEmpty()) {
            runnable.run();
        } else {
            AtomicInteger atomicInteger = new AtomicInteger();
            m3111c(activity, list.get(atomicInteger.get()), new c(atomicInteger, list, activity, runnable));
        }
    }

    /* renamed from: b */
    public static void m3110b(@NonNull Activity activity, @NonNull List<String> list, @NonNull Runnable runnable) {
        if (list.isEmpty()) {
            runnable.run();
        } else {
            AtomicInteger atomicInteger = new AtomicInteger();
            m3112d(activity, list.get(atomicInteger.get()), new a(atomicInteger, list, activity, runnable));
        }
    }

    /* renamed from: c */
    public static void m3111c(@NonNull Activity activity, @NonNull List<String> list, @NonNull Runnable runnable) {
        int nextInt;
        List<Integer> list2;
        C2638b c2638b = new C2638b(runnable);
        FragmentC2651h0 fragmentC2651h0 = new FragmentC2651h0();
        Random random = new Random();
        do {
            nextInt = random.nextInt((int) Math.pow(2.0d, 8.0d));
            list2 = FragmentC2651h0.f7256g;
        } while (list2.contains(Integer.valueOf(nextInt)));
        list2.add(Integer.valueOf(nextInt));
        Bundle bundle = new Bundle();
        bundle.putInt("request_code", nextInt);
        if (list instanceof ArrayList) {
            bundle.putStringArrayList("request_permissions", (ArrayList) list);
        } else {
            bundle.putStringArrayList("request_permissions", new ArrayList<>(list));
        }
        fragmentC2651h0.setArguments(bundle);
        fragmentC2651h0.setRetainInstance(true);
        fragmentC2651h0.f7253c = true;
        fragmentC2651h0.f7257h = c2638b;
        fragmentC2651h0.m3135a(activity);
    }

    /* renamed from: d */
    public static void m3112d(@NonNull Activity activity, @NonNull String str, @NonNull Runnable runnable) {
        List singletonList = Collections.singletonList(str);
        b bVar = new b(runnable);
        RunnableC2653i0 runnableC2653i0 = new RunnableC2653i0();
        Bundle bundle = new Bundle();
        if (singletonList instanceof ArrayList) {
            bundle.putStringArrayList("request_permissions", (ArrayList) singletonList);
        } else {
            bundle.putStringArrayList("request_permissions", new ArrayList<>(singletonList));
        }
        runnableC2653i0.setArguments(bundle);
        runnableC2653i0.setRetainInstance(true);
        runnableC2653i0.f7253c = true;
        runnableC2653i0.f7258g = bVar;
        runnableC2653i0.m3135a(activity);
    }
}
