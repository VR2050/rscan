package Q0;

import android.util.SparseArray;
import java.util.LinkedList;

/* JADX INFO: loaded from: classes.dex */
public class k {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    protected final SparseArray f2371a = new SparseArray();

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    a f2372b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    a f2373c;

    static class a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        a f2374a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        int f2375b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        LinkedList f2376c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        a f2377d;

        public String toString() {
            return "LinkedEntry(key: " + this.f2375b + ")";
        }

        private a(a aVar, int i3, LinkedList linkedList, a aVar2) {
            this.f2374a = aVar;
            this.f2375b = i3;
            this.f2376c = linkedList;
            this.f2377d = aVar2;
        }
    }

    private void b(a aVar) {
        if (aVar == null || !aVar.f2376c.isEmpty()) {
            return;
        }
        d(aVar);
        this.f2371a.remove(aVar.f2375b);
    }

    private void c(a aVar) {
        if (this.f2372b == aVar) {
            return;
        }
        d(aVar);
        a aVar2 = this.f2372b;
        if (aVar2 == null) {
            this.f2372b = aVar;
            this.f2373c = aVar;
        } else {
            aVar.f2377d = aVar2;
            aVar2.f2374a = aVar;
            this.f2372b = aVar;
        }
    }

    private synchronized void d(a aVar) {
        try {
            a aVar2 = aVar.f2374a;
            a aVar3 = aVar.f2377d;
            if (aVar2 != null) {
                aVar2.f2377d = aVar3;
            }
            if (aVar3 != null) {
                aVar3.f2374a = aVar2;
            }
            aVar.f2374a = null;
            aVar.f2377d = null;
            if (aVar == this.f2372b) {
                this.f2372b = aVar3;
            }
            if (aVar == this.f2373c) {
                this.f2373c = aVar2;
            }
        } catch (Throwable th) {
            throw th;
        }
    }

    public synchronized Object a(int i3) {
        a aVar = (a) this.f2371a.get(i3);
        if (aVar == null) {
            return null;
        }
        Object objPollFirst = aVar.f2376c.pollFirst();
        c(aVar);
        return objPollFirst;
    }

    public synchronized void e(int i3, Object obj) {
        try {
            a aVar = (a) this.f2371a.get(i3);
            if (aVar == null) {
                aVar = new a(null, i3, new LinkedList(), null);
                this.f2371a.put(i3, aVar);
            }
            aVar.f2376c.addLast(obj);
            c(aVar);
        } catch (Throwable th) {
            throw th;
        }
    }

    public synchronized Object f() {
        a aVar = this.f2373c;
        if (aVar == null) {
            return null;
        }
        Object objPollLast = aVar.f2376c.pollLast();
        b(aVar);
        return objPollLast;
    }
}
