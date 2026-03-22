package p005b.p143g.p144a.p147m.p150t;

import androidx.annotation.NonNull;
import java.io.File;
import java.util.List;
import p005b.p143g.p144a.p147m.EnumC1569a;
import p005b.p143g.p144a.p147m.InterfaceC1579k;
import p005b.p143g.p144a.p147m.p148s.InterfaceC1590d;
import p005b.p143g.p144a.p147m.p150t.InterfaceC1639g;
import p005b.p143g.p144a.p147m.p154u.InterfaceC1672n;

/* renamed from: b.g.a.m.t.d */
/* loaded from: classes.dex */
public class C1624d implements InterfaceC1639g, InterfaceC1590d.a<Object> {

    /* renamed from: c */
    public final List<InterfaceC1579k> f2096c;

    /* renamed from: e */
    public final C1640h<?> f2097e;

    /* renamed from: f */
    public final InterfaceC1639g.a f2098f;

    /* renamed from: g */
    public int f2099g;

    /* renamed from: h */
    public InterfaceC1579k f2100h;

    /* renamed from: i */
    public List<InterfaceC1672n<File, ?>> f2101i;

    /* renamed from: j */
    public int f2102j;

    /* renamed from: k */
    public volatile InterfaceC1672n.a<?> f2103k;

    /* renamed from: l */
    public File f2104l;

    public C1624d(C1640h<?> c1640h, InterfaceC1639g.a aVar) {
        List<InterfaceC1579k> m906a = c1640h.m906a();
        this.f2099g = -1;
        this.f2096c = m906a;
        this.f2097e = c1640h;
        this.f2098f = aVar;
    }

    @Override // p005b.p143g.p144a.p147m.p150t.InterfaceC1639g
    /* renamed from: b */
    public boolean mo854b() {
        while (true) {
            List<InterfaceC1672n<File, ?>> list = this.f2101i;
            if (list != null) {
                if (this.f2102j < list.size()) {
                    this.f2103k = null;
                    boolean z = false;
                    while (!z) {
                        if (!(this.f2102j < this.f2101i.size())) {
                            break;
                        }
                        List<InterfaceC1672n<File, ?>> list2 = this.f2101i;
                        int i2 = this.f2102j;
                        this.f2102j = i2 + 1;
                        InterfaceC1672n<File, ?> interfaceC1672n = list2.get(i2);
                        File file = this.f2104l;
                        C1640h<?> c1640h = this.f2097e;
                        this.f2103k = interfaceC1672n.mo961b(file, c1640h.f2153e, c1640h.f2154f, c1640h.f2157i);
                        if (this.f2103k != null && this.f2097e.m912g(this.f2103k.f2383c.mo832a())) {
                            this.f2103k.f2383c.mo837d(this.f2097e.f2163o, this);
                            z = true;
                        }
                    }
                    return z;
                }
            }
            int i3 = this.f2099g + 1;
            this.f2099g = i3;
            if (i3 >= this.f2096c.size()) {
                return false;
            }
            InterfaceC1579k interfaceC1579k = this.f2096c.get(this.f2099g);
            C1640h<?> c1640h2 = this.f2097e;
            File mo895b = c1640h2.m907b().mo895b(new C1636e(interfaceC1579k, c1640h2.f2162n));
            this.f2104l = mo895b;
            if (mo895b != null) {
                this.f2100h = interfaceC1579k;
                this.f2101i = this.f2097e.f2151c.f1836c.m748f(mo895b);
                this.f2102j = 0;
            }
        }
    }

    @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d.a
    /* renamed from: c */
    public void mo839c(@NonNull Exception exc) {
        this.f2098f.mo853a(this.f2100h, exc, this.f2103k.f2383c, EnumC1569a.DATA_DISK_CACHE);
    }

    @Override // p005b.p143g.p144a.p147m.p150t.InterfaceC1639g
    public void cancel() {
        InterfaceC1672n.a<?> aVar = this.f2103k;
        if (aVar != null) {
            aVar.f2383c.cancel();
        }
    }

    @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d.a
    /* renamed from: e */
    public void mo840e(Object obj) {
        this.f2098f.mo856d(this.f2100h, obj, this.f2103k.f2383c, EnumC1569a.DATA_DISK_CACHE, this.f2100h);
    }

    public C1624d(List<InterfaceC1579k> list, C1640h<?> c1640h, InterfaceC1639g.a aVar) {
        this.f2099g = -1;
        this.f2096c = list;
        this.f2097e = c1640h;
        this.f2098f = aVar;
    }
}
