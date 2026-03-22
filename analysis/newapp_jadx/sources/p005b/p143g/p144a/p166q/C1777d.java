package p005b.p143g.p144a.p166q;

import android.graphics.drawable.Drawable;
import androidx.annotation.GuardedBy;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.VisibleForTesting;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import p005b.p143g.p144a.p147m.EnumC1569a;
import p005b.p143g.p144a.p147m.p150t.C1650r;
import p005b.p143g.p144a.p166q.p167i.InterfaceC1789h;
import p005b.p143g.p144a.p166q.p167i.InterfaceC1790i;
import p005b.p143g.p144a.p166q.p168j.InterfaceC1793b;
import p005b.p143g.p144a.p170s.C1807i;

/* renamed from: b.g.a.q.d */
/* loaded from: classes.dex */
public class C1777d<R> implements InterfaceC1778e<R>, InterfaceC1790i, InterfaceC1778e {

    /* renamed from: c */
    public static final a f2679c = new a();

    /* renamed from: e */
    public final int f2680e;

    /* renamed from: f */
    public final int f2681f;

    /* renamed from: g */
    @Nullable
    @GuardedBy("this")
    public R f2682g;

    /* renamed from: h */
    @Nullable
    @GuardedBy("this")
    public InterfaceC1775b f2683h;

    /* renamed from: i */
    @GuardedBy("this")
    public boolean f2684i;

    /* renamed from: j */
    @GuardedBy("this")
    public boolean f2685j;

    /* renamed from: k */
    @GuardedBy("this")
    public boolean f2686k;

    /* renamed from: l */
    @Nullable
    @GuardedBy("this")
    public C1650r f2687l;

    @VisibleForTesting
    /* renamed from: b.g.a.q.d$a */
    public static class a {
    }

    public C1777d(int i2, int i3) {
        this.f2680e = i2;
        this.f2681f = i3;
    }

    @Override // p005b.p143g.p144a.p166q.InterfaceC1778e
    /* renamed from: a */
    public synchronized boolean mo207a(@Nullable C1650r c1650r, Object obj, InterfaceC1790i<R> interfaceC1790i, boolean z) {
        this.f2686k = true;
        this.f2687l = c1650r;
        notifyAll();
        return false;
    }

    @Override // p005b.p143g.p144a.p166q.InterfaceC1778e
    /* renamed from: b */
    public synchronized boolean mo208b(R r, Object obj, InterfaceC1790i<R> interfaceC1790i, EnumC1569a enumC1569a, boolean z) {
        this.f2685j = true;
        this.f2682g = r;
        notifyAll();
        return false;
    }

    /* renamed from: c */
    public final synchronized R m1109c(Long l2) {
        if (!isDone() && !C1807i.m1150g()) {
            throw new IllegalArgumentException("You must call this method on a background thread");
        }
        if (this.f2684i) {
            throw new CancellationException();
        }
        if (this.f2686k) {
            throw new ExecutionException(this.f2687l);
        }
        if (this.f2685j) {
            return this.f2682g;
        }
        if (l2 == null) {
            wait(0L);
        } else if (l2.longValue() > 0) {
            long currentTimeMillis = System.currentTimeMillis();
            long longValue = l2.longValue() + currentTimeMillis;
            while (!isDone() && currentTimeMillis < longValue) {
                wait(longValue - currentTimeMillis);
                currentTimeMillis = System.currentTimeMillis();
            }
        }
        if (Thread.interrupted()) {
            throw new InterruptedException();
        }
        if (this.f2686k) {
            throw new ExecutionException(this.f2687l);
        }
        if (this.f2684i) {
            throw new CancellationException();
        }
        if (!this.f2685j) {
            throw new TimeoutException();
        }
        return this.f2682g;
    }

    public boolean cancel(boolean z) {
        synchronized (this) {
            if (isDone()) {
                return false;
            }
            this.f2684i = true;
            notifyAll();
            InterfaceC1775b interfaceC1775b = null;
            if (z) {
                InterfaceC1775b interfaceC1775b2 = this.f2683h;
                this.f2683h = null;
                interfaceC1775b = interfaceC1775b2;
            }
            if (interfaceC1775b != null) {
                interfaceC1775b.clear();
            }
            return true;
        }
    }

    public R get() {
        try {
            return m1109c(null);
        } catch (TimeoutException e2) {
            throw new AssertionError(e2);
        }
    }

    @Override // p005b.p143g.p144a.p166q.p167i.InterfaceC1790i
    @Nullable
    public synchronized InterfaceC1775b getRequest() {
        return this.f2683h;
    }

    @Override // p005b.p143g.p144a.p166q.p167i.InterfaceC1790i
    public void getSize(@NonNull InterfaceC1789h interfaceC1789h) {
        ((C1781h) interfaceC1789h).mo1111a(this.f2680e, this.f2681f);
    }

    public synchronized boolean isCancelled() {
        return this.f2684i;
    }

    public synchronized boolean isDone() {
        boolean z;
        if (!this.f2684i && !this.f2685j) {
            z = this.f2686k;
        }
        return z;
    }

    @Override // p005b.p143g.p144a.p163n.InterfaceC1755i
    public void onDestroy() {
    }

    @Override // p005b.p143g.p144a.p166q.p167i.InterfaceC1790i
    public void onLoadCleared(@Nullable Drawable drawable) {
    }

    @Override // p005b.p143g.p144a.p166q.p167i.InterfaceC1790i
    public synchronized void onLoadFailed(@Nullable Drawable drawable) {
    }

    @Override // p005b.p143g.p144a.p166q.p167i.InterfaceC1790i
    public void onLoadStarted(@Nullable Drawable drawable) {
    }

    @Override // p005b.p143g.p144a.p166q.p167i.InterfaceC1790i
    public synchronized void onResourceReady(@NonNull R r, @Nullable InterfaceC1793b<? super R> interfaceC1793b) {
    }

    @Override // p005b.p143g.p144a.p163n.InterfaceC1755i
    public void onStart() {
    }

    @Override // p005b.p143g.p144a.p163n.InterfaceC1755i
    public void onStop() {
    }

    @Override // p005b.p143g.p144a.p166q.p167i.InterfaceC1790i
    public void removeCallback(@NonNull InterfaceC1789h interfaceC1789h) {
    }

    @Override // p005b.p143g.p144a.p166q.p167i.InterfaceC1790i
    public synchronized void setRequest(@Nullable InterfaceC1775b interfaceC1775b) {
        this.f2683h = interfaceC1775b;
    }

    public R get(long j2, @NonNull TimeUnit timeUnit) {
        return m1109c(Long.valueOf(timeUnit.toMillis(j2)));
    }
}
