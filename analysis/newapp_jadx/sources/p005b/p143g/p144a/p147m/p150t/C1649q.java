package p005b.p143g.p144a.p147m.p150t;

import androidx.annotation.NonNull;
import java.util.Objects;
import p005b.p143g.p144a.p147m.InterfaceC1579k;

/* renamed from: b.g.a.m.t.q */
/* loaded from: classes.dex */
public class C1649q<Z> implements InterfaceC1655w<Z> {

    /* renamed from: c */
    public final boolean f2293c;

    /* renamed from: e */
    public final boolean f2294e;

    /* renamed from: f */
    public final InterfaceC1655w<Z> f2295f;

    /* renamed from: g */
    public final a f2296g;

    /* renamed from: h */
    public final InterfaceC1579k f2297h;

    /* renamed from: i */
    public int f2298i;

    /* renamed from: j */
    public boolean f2299j;

    /* renamed from: b.g.a.m.t.q$a */
    public interface a {
        /* renamed from: a */
        void mo932a(InterfaceC1579k interfaceC1579k, C1649q<?> c1649q);
    }

    public C1649q(InterfaceC1655w<Z> interfaceC1655w, boolean z, boolean z2, InterfaceC1579k interfaceC1579k, a aVar) {
        Objects.requireNonNull(interfaceC1655w, "Argument must not be null");
        this.f2295f = interfaceC1655w;
        this.f2293c = z;
        this.f2294e = z2;
        this.f2297h = interfaceC1579k;
        Objects.requireNonNull(aVar, "Argument must not be null");
        this.f2296g = aVar;
    }

    @Override // p005b.p143g.p144a.p147m.p150t.InterfaceC1655w
    @NonNull
    /* renamed from: a */
    public Class<Z> mo947a() {
        return this.f2295f.mo947a();
    }

    /* renamed from: b */
    public synchronized void m948b() {
        if (this.f2299j) {
            throw new IllegalStateException("Cannot acquire a recycled resource");
        }
        this.f2298i++;
    }

    /* renamed from: c */
    public void m949c() {
        boolean z;
        synchronized (this) {
            int i2 = this.f2298i;
            if (i2 <= 0) {
                throw new IllegalStateException("Cannot release a recycled or not yet acquired resource");
            }
            z = true;
            int i3 = i2 - 1;
            this.f2298i = i3;
            if (i3 != 0) {
                z = false;
            }
        }
        if (z) {
            this.f2296g.mo932a(this.f2297h, this);
        }
    }

    @Override // p005b.p143g.p144a.p147m.p150t.InterfaceC1655w
    @NonNull
    public Z get() {
        return this.f2295f.get();
    }

    @Override // p005b.p143g.p144a.p147m.p150t.InterfaceC1655w
    public int getSize() {
        return this.f2295f.getSize();
    }

    @Override // p005b.p143g.p144a.p147m.p150t.InterfaceC1655w
    public synchronized void recycle() {
        if (this.f2298i > 0) {
            throw new IllegalStateException("Cannot recycle a resource while it is still acquired");
        }
        if (this.f2299j) {
            throw new IllegalStateException("Cannot recycle a resource that has already been recycled");
        }
        this.f2299j = true;
        if (this.f2294e) {
            this.f2295f.recycle();
        }
    }

    public synchronized String toString() {
        return "EngineResource{isMemoryCacheable=" + this.f2293c + ", listener=" + this.f2296g + ", key=" + this.f2297h + ", acquired=" + this.f2298i + ", isRecycled=" + this.f2299j + ", resource=" + this.f2295f + '}';
    }
}
