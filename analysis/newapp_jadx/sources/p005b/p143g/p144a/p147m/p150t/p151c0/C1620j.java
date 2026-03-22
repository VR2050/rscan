package p005b.p143g.p144a.p147m.p150t.p151c0;

import android.annotation.SuppressLint;
import android.graphics.Bitmap;
import android.os.Build;
import android.util.Log;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p143g.p144a.p170s.C1807i;

/* renamed from: b.g.a.m.t.c0.j */
/* loaded from: classes.dex */
public class C1620j implements InterfaceC1614d {

    /* renamed from: a */
    public static final Bitmap.Config f2074a = Bitmap.Config.ARGB_8888;

    /* renamed from: b */
    public final InterfaceC1621k f2075b;

    /* renamed from: c */
    public final Set<Bitmap.Config> f2076c;

    /* renamed from: d */
    public final a f2077d;

    /* renamed from: e */
    public long f2078e;

    /* renamed from: f */
    public long f2079f;

    /* renamed from: g */
    public int f2080g;

    /* renamed from: h */
    public int f2081h;

    /* renamed from: i */
    public int f2082i;

    /* renamed from: j */
    public int f2083j;

    /* renamed from: b.g.a.m.t.c0.j$a */
    public interface a {
    }

    /* renamed from: b.g.a.m.t.c0.j$b */
    public static final class b implements a {
    }

    public C1620j(long j2) {
        C1623m c1623m = new C1623m();
        HashSet hashSet = new HashSet(Arrays.asList(Bitmap.Config.values()));
        int i2 = Build.VERSION.SDK_INT;
        hashSet.add(null);
        if (i2 >= 26) {
            hashSet.remove(Bitmap.Config.HARDWARE);
        }
        Set<Bitmap.Config> unmodifiableSet = Collections.unmodifiableSet(hashSet);
        this.f2078e = j2;
        this.f2075b = c1623m;
        this.f2076c = unmodifiableSet;
        this.f2077d = new b();
    }

    @Override // p005b.p143g.p144a.p147m.p150t.p151c0.InterfaceC1614d
    @SuppressLint({"InlinedApi"})
    /* renamed from: a */
    public void mo867a(int i2) {
        Log.isLoggable("LruBitmapPool", 3);
        if (i2 >= 40 || (Build.VERSION.SDK_INT >= 23 && i2 >= 20)) {
            Log.isLoggable("LruBitmapPool", 3);
            m886i(0L);
        } else if (i2 >= 20 || i2 == 15) {
            m886i(this.f2078e / 2);
        }
    }

    @Override // p005b.p143g.p144a.p147m.p150t.p151c0.InterfaceC1614d
    /* renamed from: b */
    public void mo868b() {
        Log.isLoggable("LruBitmapPool", 3);
        m886i(0L);
    }

    @Override // p005b.p143g.p144a.p147m.p150t.p151c0.InterfaceC1614d
    @NonNull
    /* renamed from: c */
    public Bitmap mo869c(int i2, int i3, Bitmap.Config config) {
        Bitmap m885h = m885h(i2, i3, config);
        if (m885h != null) {
            return m885h;
        }
        if (config == null) {
            config = f2074a;
        }
        return Bitmap.createBitmap(i2, i3, config);
    }

    @Override // p005b.p143g.p144a.p147m.p150t.p151c0.InterfaceC1614d
    /* renamed from: d */
    public synchronized void mo870d(Bitmap bitmap) {
        try {
            if (bitmap == null) {
                throw new NullPointerException("Bitmap must not be null");
            }
            if (bitmap.isRecycled()) {
                throw new IllegalStateException("Cannot pool recycled bitmap");
            }
            if (bitmap.isMutable()) {
                Objects.requireNonNull((C1623m) this.f2075b);
                if (C1807i.m1147d(bitmap) <= this.f2078e && this.f2076c.contains(bitmap.getConfig())) {
                    Objects.requireNonNull((C1623m) this.f2075b);
                    int m1147d = C1807i.m1147d(bitmap);
                    ((C1623m) this.f2075b).m892f(bitmap);
                    Objects.requireNonNull((b) this.f2077d);
                    this.f2082i++;
                    this.f2079f += m1147d;
                    if (Log.isLoggable("LruBitmapPool", 2)) {
                        ((C1623m) this.f2075b).m891e(bitmap);
                    }
                    m883f();
                    m886i(this.f2078e);
                    return;
                }
            }
            if (Log.isLoggable("LruBitmapPool", 2)) {
                ((C1623m) this.f2075b).m891e(bitmap);
                bitmap.isMutable();
                this.f2076c.contains(bitmap.getConfig());
            }
            bitmap.recycle();
        } catch (Throwable th) {
            throw th;
        }
    }

    @Override // p005b.p143g.p144a.p147m.p150t.p151c0.InterfaceC1614d
    @NonNull
    /* renamed from: e */
    public Bitmap mo871e(int i2, int i3, Bitmap.Config config) {
        Bitmap m885h = m885h(i2, i3, config);
        if (m885h != null) {
            m885h.eraseColor(0);
            return m885h;
        }
        if (config == null) {
            config = f2074a;
        }
        return Bitmap.createBitmap(i2, i3, config);
    }

    /* renamed from: f */
    public final void m883f() {
        if (Log.isLoggable("LruBitmapPool", 2)) {
            m884g();
        }
    }

    /* renamed from: g */
    public final void m884g() {
        StringBuilder m586H = C1499a.m586H("Hits=");
        m586H.append(this.f2080g);
        m586H.append(", misses=");
        m586H.append(this.f2081h);
        m586H.append(", puts=");
        m586H.append(this.f2082i);
        m586H.append(", evictions=");
        m586H.append(this.f2083j);
        m586H.append(", currentSize=");
        m586H.append(this.f2079f);
        m586H.append(", maxSize=");
        m586H.append(this.f2078e);
        m586H.append("\nStrategy=");
        m586H.append(this.f2075b);
        m586H.toString();
    }

    @Nullable
    /* renamed from: h */
    public final synchronized Bitmap m885h(int i2, int i3, @Nullable Bitmap.Config config) {
        Bitmap m889b;
        if (Build.VERSION.SDK_INT >= 26 && config == Bitmap.Config.HARDWARE) {
            throw new IllegalArgumentException("Cannot create a mutable Bitmap with config: " + config + ". Consider setting Downsampler#ALLOW_HARDWARE_CONFIG to false in your RequestOptions and/or in GlideBuilder.setDefaultRequestOptions");
        }
        m889b = ((C1623m) this.f2075b).m889b(i2, i3, config != null ? config : f2074a);
        if (m889b == null) {
            if (Log.isLoggable("LruBitmapPool", 3)) {
                Objects.requireNonNull((C1623m) this.f2075b);
                C1623m.m887c(C1807i.m1146c(i2, i3, config), config);
            }
            this.f2081h++;
        } else {
            this.f2080g++;
            long j2 = this.f2079f;
            Objects.requireNonNull((C1623m) this.f2075b);
            this.f2079f = j2 - C1807i.m1147d(m889b);
            Objects.requireNonNull((b) this.f2077d);
            m889b.setHasAlpha(true);
            m889b.setPremultiplied(true);
        }
        if (Log.isLoggable("LruBitmapPool", 2)) {
            Objects.requireNonNull((C1623m) this.f2075b);
            C1623m.m887c(C1807i.m1146c(i2, i3, config), config);
        }
        m883f();
        return m889b;
    }

    /* renamed from: i */
    public final synchronized void m886i(long j2) {
        while (this.f2079f > j2) {
            C1623m c1623m = (C1623m) this.f2075b;
            Bitmap m874c = c1623m.f2090g.m874c();
            if (m874c != null) {
                c1623m.m888a(Integer.valueOf(C1807i.m1147d(m874c)), m874c);
            }
            if (m874c == null) {
                if (Log.isLoggable("LruBitmapPool", 5)) {
                    m884g();
                }
                this.f2079f = 0L;
                return;
            }
            Objects.requireNonNull((b) this.f2077d);
            long j3 = this.f2079f;
            Objects.requireNonNull((C1623m) this.f2075b);
            this.f2079f = j3 - C1807i.m1147d(m874c);
            this.f2083j++;
            if (Log.isLoggable("LruBitmapPool", 3)) {
                ((C1623m) this.f2075b).m891e(m874c);
            }
            m883f();
            m874c.recycle();
        }
    }
}
