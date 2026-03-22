package p005b.p143g.p144a.p163n;

import androidx.annotation.Nullable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.WeakHashMap;
import p005b.p143g.p144a.p166q.InterfaceC1775b;

/* renamed from: b.g.a.n.n */
/* loaded from: classes.dex */
public class C1760n {

    /* renamed from: a */
    public final Set<InterfaceC1775b> f2632a = Collections.newSetFromMap(new WeakHashMap());

    /* renamed from: b */
    public final List<InterfaceC1775b> f2633b = new ArrayList();

    /* renamed from: c */
    public boolean f2634c;

    /* renamed from: a */
    public boolean m1060a(@Nullable InterfaceC1775b interfaceC1775b) {
        boolean z = true;
        if (interfaceC1775b == null) {
            return true;
        }
        boolean remove = this.f2632a.remove(interfaceC1775b);
        if (!this.f2633b.remove(interfaceC1775b) && !remove) {
            z = false;
        }
        if (z) {
            interfaceC1775b.clear();
        }
        return z;
    }

    public String toString() {
        return super.toString() + "{numRequests=" + this.f2632a.size() + ", isPaused=" + this.f2634c + "}";
    }
}
