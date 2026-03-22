package p005b.p199l.p200a.p201a.p202a1;

import androidx.annotation.CallSuper;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import p005b.p199l.p200a.p201a.p202a1.InterfaceC1920l;

/* renamed from: b.l.a.a.a1.r */
/* loaded from: classes.dex */
public abstract class AbstractC1926r implements InterfaceC1920l {

    /* renamed from: b */
    public InterfaceC1920l.a f3122b;

    /* renamed from: c */
    public InterfaceC1920l.a f3123c;

    /* renamed from: d */
    public InterfaceC1920l.a f3124d;

    /* renamed from: e */
    public InterfaceC1920l.a f3125e;

    /* renamed from: f */
    public ByteBuffer f3126f;

    /* renamed from: g */
    public ByteBuffer f3127g;

    /* renamed from: h */
    public boolean f3128h;

    public AbstractC1926r() {
        ByteBuffer byteBuffer = InterfaceC1920l.f3076a;
        this.f3126f = byteBuffer;
        this.f3127g = byteBuffer;
        InterfaceC1920l.a aVar = InterfaceC1920l.a.f3077a;
        this.f3124d = aVar;
        this.f3125e = aVar;
        this.f3122b = aVar;
        this.f3123c = aVar;
    }

    /* renamed from: a */
    public abstract InterfaceC1920l.a mo1259a(InterfaceC1920l.a aVar);

    @Override // p005b.p199l.p200a.p201a.p202a1.InterfaceC1920l
    /* renamed from: b */
    public boolean mo1253b() {
        return this.f3125e != InterfaceC1920l.a.f3077a;
    }

    @Override // p005b.p199l.p200a.p201a.p202a1.InterfaceC1920l
    @CallSuper
    /* renamed from: c */
    public boolean mo1254c() {
        return this.f3128h && this.f3127g == InterfaceC1920l.f3076a;
    }

    @Override // p005b.p199l.p200a.p201a.p202a1.InterfaceC1920l
    @CallSuper
    /* renamed from: d */
    public ByteBuffer mo1255d() {
        ByteBuffer byteBuffer = this.f3127g;
        this.f3127g = InterfaceC1920l.f3076a;
        return byteBuffer;
    }

    @Override // p005b.p199l.p200a.p201a.p202a1.InterfaceC1920l
    /* renamed from: f */
    public final InterfaceC1920l.a mo1257f(InterfaceC1920l.a aVar) {
        this.f3124d = aVar;
        this.f3125e = mo1259a(aVar);
        return mo1253b() ? this.f3125e : InterfaceC1920l.a.f3077a;
    }

    @Override // p005b.p199l.p200a.p201a.p202a1.InterfaceC1920l
    public final void flush() {
        this.f3127g = InterfaceC1920l.f3076a;
        this.f3128h = false;
        this.f3122b = this.f3124d;
        this.f3123c = this.f3125e;
        mo1260h();
    }

    @Override // p005b.p199l.p200a.p201a.p202a1.InterfaceC1920l
    /* renamed from: g */
    public final void mo1258g() {
        this.f3128h = true;
        mo1261i();
    }

    /* renamed from: h */
    public void mo1260h() {
    }

    /* renamed from: i */
    public void mo1261i() {
    }

    /* renamed from: j */
    public void mo1262j() {
    }

    /* renamed from: k */
    public final ByteBuffer m1278k(int i2) {
        if (this.f3126f.capacity() < i2) {
            this.f3126f = ByteBuffer.allocateDirect(i2).order(ByteOrder.nativeOrder());
        } else {
            this.f3126f.clear();
        }
        ByteBuffer byteBuffer = this.f3126f;
        this.f3127g = byteBuffer;
        return byteBuffer;
    }

    @Override // p005b.p199l.p200a.p201a.p202a1.InterfaceC1920l
    public final void reset() {
        flush();
        this.f3126f = InterfaceC1920l.f3076a;
        InterfaceC1920l.a aVar = InterfaceC1920l.a.f3077a;
        this.f3124d = aVar;
        this.f3125e = aVar;
        this.f3122b = aVar;
        this.f3123c = aVar;
        mo1262j();
    }
}
