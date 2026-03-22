package p005b.p143g.p144a.p163n;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.Set;
import java.util.WeakHashMap;
import p005b.p143g.p144a.p166q.p167i.InterfaceC1790i;
import p005b.p143g.p144a.p170s.C1807i;

/* renamed from: b.g.a.n.o */
/* loaded from: classes.dex */
public final class C1761o implements InterfaceC1755i {

    /* renamed from: c */
    public final Set<InterfaceC1790i<?>> f2635c = Collections.newSetFromMap(new WeakHashMap());

    @Override // p005b.p143g.p144a.p163n.InterfaceC1755i
    public void onDestroy() {
        Iterator it = ((ArrayList) C1807i.m1148e(this.f2635c)).iterator();
        while (it.hasNext()) {
            ((InterfaceC1790i) it.next()).onDestroy();
        }
    }

    @Override // p005b.p143g.p144a.p163n.InterfaceC1755i
    public void onStart() {
        Iterator it = ((ArrayList) C1807i.m1148e(this.f2635c)).iterator();
        while (it.hasNext()) {
            ((InterfaceC1790i) it.next()).onStart();
        }
    }

    @Override // p005b.p143g.p144a.p163n.InterfaceC1755i
    public void onStop() {
        Iterator it = ((ArrayList) C1807i.m1148e(this.f2635c)).iterator();
        while (it.hasNext()) {
            ((InterfaceC1790i) it.next()).onStop();
        }
    }
}
