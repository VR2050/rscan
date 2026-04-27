package G0;

import java.util.LinkedHashSet;

/* JADX INFO: renamed from: G0.d, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0175d {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final int f777a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final LinkedHashSet f778b;

    public C0175d(int i3) {
        this.f777a = i3;
        this.f778b = new LinkedHashSet(i3);
    }

    public final synchronized boolean a(Object obj) {
        try {
            if (this.f778b.size() == this.f777a) {
                LinkedHashSet linkedHashSet = this.f778b;
                linkedHashSet.remove(linkedHashSet.iterator().next());
            }
            this.f778b.remove(obj);
        } catch (Throwable th) {
            throw th;
        }
        return this.f778b.add(obj);
    }

    public final synchronized boolean b(Object obj) {
        return this.f778b.contains(obj);
    }
}
