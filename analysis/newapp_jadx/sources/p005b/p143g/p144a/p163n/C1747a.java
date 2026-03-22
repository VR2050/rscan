package p005b.p143g.p144a.p163n;

import androidx.annotation.NonNull;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.Set;
import java.util.WeakHashMap;
import p005b.p143g.p144a.p170s.C1807i;

/* renamed from: b.g.a.n.a */
/* loaded from: classes.dex */
public class C1747a implements InterfaceC1754h {

    /* renamed from: a */
    public final Set<InterfaceC1755i> f2607a = Collections.newSetFromMap(new WeakHashMap());

    /* renamed from: b */
    public boolean f2608b;

    /* renamed from: c */
    public boolean f2609c;

    @Override // p005b.p143g.p144a.p163n.InterfaceC1754h
    /* renamed from: a */
    public void mo1040a(@NonNull InterfaceC1755i interfaceC1755i) {
        this.f2607a.add(interfaceC1755i);
        if (this.f2609c) {
            interfaceC1755i.onDestroy();
        } else if (this.f2608b) {
            interfaceC1755i.onStart();
        } else {
            interfaceC1755i.onStop();
        }
    }

    @Override // p005b.p143g.p144a.p163n.InterfaceC1754h
    /* renamed from: b */
    public void mo1041b(@NonNull InterfaceC1755i interfaceC1755i) {
        this.f2607a.remove(interfaceC1755i);
    }

    /* renamed from: c */
    public void m1042c() {
        this.f2609c = true;
        Iterator it = ((ArrayList) C1807i.m1148e(this.f2607a)).iterator();
        while (it.hasNext()) {
            ((InterfaceC1755i) it.next()).onDestroy();
        }
    }

    /* renamed from: d */
    public void m1043d() {
        this.f2608b = true;
        Iterator it = ((ArrayList) C1807i.m1148e(this.f2607a)).iterator();
        while (it.hasNext()) {
            ((InterfaceC1755i) it.next()).onStart();
        }
    }

    /* renamed from: e */
    public void m1044e() {
        this.f2608b = false;
        Iterator it = ((ArrayList) C1807i.m1148e(this.f2607a)).iterator();
        while (it.hasNext()) {
            ((InterfaceC1755i) it.next()).onStop();
        }
    }
}
