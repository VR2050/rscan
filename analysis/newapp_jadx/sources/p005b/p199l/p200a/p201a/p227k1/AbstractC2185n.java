package p005b.p199l.p200a.p201a.p227k1;

import android.os.Handler;
import android.os.Looper;
import androidx.annotation.Nullable;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Objects;
import p005b.p199l.p200a.p201a.AbstractC2404x0;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2202y;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2203z;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2291f0;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.k1.n */
/* loaded from: classes.dex */
public abstract class AbstractC2185n implements InterfaceC2202y {

    /* renamed from: c */
    public final ArrayList<InterfaceC2202y.b> f5126c = new ArrayList<>(1);

    /* renamed from: e */
    public final HashSet<InterfaceC2202y.b> f5127e = new HashSet<>(1);

    /* renamed from: f */
    public final InterfaceC2203z.a f5128f = new InterfaceC2203z.a();

    /* renamed from: g */
    @Nullable
    public Looper f5129g;

    /* renamed from: h */
    @Nullable
    public AbstractC2404x0 f5130h;

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2202y
    /* renamed from: b */
    public final void mo1992b(InterfaceC2202y.b bVar) {
        this.f5126c.remove(bVar);
        if (!this.f5126c.isEmpty()) {
            mo1995e(bVar);
            return;
        }
        this.f5129g = null;
        this.f5130h = null;
        this.f5127e.clear();
        mo1793q();
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2202y
    /* renamed from: c */
    public final void mo1993c(Handler handler, InterfaceC2203z interfaceC2203z) {
        InterfaceC2203z.a aVar = this.f5128f;
        Objects.requireNonNull(aVar);
        C4195m.m4765F((handler == null || interfaceC2203z == null) ? false : true);
        aVar.f5254c.add(new InterfaceC2203z.a.C5114a(handler, interfaceC2203z));
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2202y
    /* renamed from: d */
    public final void mo1994d(InterfaceC2203z interfaceC2203z) {
        InterfaceC2203z.a aVar = this.f5128f;
        Iterator<InterfaceC2203z.a.C5114a> it = aVar.f5254c.iterator();
        while (it.hasNext()) {
            InterfaceC2203z.a.C5114a next = it.next();
            if (next.f5257b == interfaceC2203z) {
                aVar.f5254c.remove(next);
            }
        }
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2202y
    /* renamed from: e */
    public final void mo1995e(InterfaceC2202y.b bVar) {
        boolean z = !this.f5127e.isEmpty();
        this.f5127e.remove(bVar);
        if (z && this.f5127e.isEmpty()) {
            mo1999m();
        }
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2202y
    /* renamed from: h */
    public final void mo1996h(InterfaceC2202y.b bVar, @Nullable InterfaceC2291f0 interfaceC2291f0) {
        Looper myLooper = Looper.myLooper();
        Looper looper = this.f5129g;
        C4195m.m4765F(looper == null || looper == myLooper);
        AbstractC2404x0 abstractC2404x0 = this.f5130h;
        this.f5126c.add(bVar);
        if (this.f5129g == null) {
            this.f5129g = myLooper;
            this.f5127e.add(bVar);
            mo1792o(interfaceC2291f0);
        } else if (abstractC2404x0 != null) {
            boolean isEmpty = this.f5127e.isEmpty();
            this.f5127e.add(bVar);
            if (isEmpty) {
                mo2000n();
            }
            bVar.mo1414a(this, abstractC2404x0);
        }
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2202y
    /* renamed from: i */
    public final void mo1997i(InterfaceC2202y.b bVar) {
        Objects.requireNonNull(this.f5129g);
        boolean isEmpty = this.f5127e.isEmpty();
        this.f5127e.add(bVar);
        if (isEmpty) {
            mo2000n();
        }
    }

    /* renamed from: j */
    public final InterfaceC2203z.a m1998j(@Nullable InterfaceC2202y.a aVar) {
        return this.f5128f.m2045u(0, null, 0L);
    }

    /* renamed from: m */
    public void mo1999m() {
    }

    /* renamed from: n */
    public void mo2000n() {
    }

    /* renamed from: o */
    public abstract void mo1792o(@Nullable InterfaceC2291f0 interfaceC2291f0);

    /* renamed from: p */
    public final void m2001p(AbstractC2404x0 abstractC2404x0) {
        this.f5130h = abstractC2404x0;
        Iterator<InterfaceC2202y.b> it = this.f5126c.iterator();
        while (it.hasNext()) {
            it.next().mo1414a(this, abstractC2404x0);
        }
    }

    /* renamed from: q */
    public abstract void mo1793q();
}
