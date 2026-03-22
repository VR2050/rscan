package com.qunidayede.supportlibrary.imageloader;

import android.content.Context;
import androidx.annotation.NonNull;
import java.nio.ByteBuffer;
import p005b.p143g.p144a.C1554d;
import p005b.p143g.p144a.C1557g;
import p005b.p143g.p144a.ComponentCallbacks2C1553c;
import p005b.p143g.p144a.p147m.p150t.p151c0.C1620j;
import p005b.p143g.p144a.p147m.p150t.p152d0.C1632h;
import p005b.p143g.p144a.p147m.p150t.p152d0.C1634j;
import p005b.p143g.p144a.p147m.p154u.C1674p;
import p005b.p143g.p144a.p147m.p154u.C1676r;
import p005b.p143g.p144a.p164o.AbstractC1762a;
import p005b.p327w.p330b.p336c.C2856g;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* loaded from: classes2.dex */
public class XAppGlideModule extends AbstractC1762a {
    @Override // p005b.p143g.p144a.p164o.AbstractC1762a, p005b.p143g.p144a.p164o.InterfaceC1763b
    /* renamed from: a */
    public void mo1061a(@NonNull Context context, @NonNull C1554d c1554d) {
        C1634j.a aVar = new C1634j.a(context);
        C4195m.m4763E(true, "Memory cache screens must be greater than or equal to 0");
        aVar.f2128e = 2.0f;
        C4195m.m4763E(true, "Bitmap pool screens must be greater than or equal to 0");
        aVar.f2129f = 3.0f;
        C1634j c1634j = new C1634j(aVar);
        c1554d.f1823e = new C1632h(c1634j.f2121b);
        c1554d.f1821c = new C1620j(c1634j.f2120a);
    }

    @Override // p005b.p143g.p144a.p164o.AbstractC1765d, p005b.p143g.p144a.p164o.InterfaceC1767f
    /* renamed from: b */
    public void mo1063b(@NonNull Context context, @NonNull ComponentCallbacks2C1553c componentCallbacks2C1553c, @NonNull C1557g c1557g) {
        C2856g c2856g = new C2856g();
        C1674p c1674p = c1557g.f1850a;
        synchronized (c1674p) {
            C1676r c1676r = c1674p.f2384a;
            synchronized (c1676r) {
                c1676r.f2399c.add(0, new C1676r.b<>(String.class, ByteBuffer.class, c2856g));
            }
            c1674p.f2385b.f2386a.clear();
        }
    }
}
