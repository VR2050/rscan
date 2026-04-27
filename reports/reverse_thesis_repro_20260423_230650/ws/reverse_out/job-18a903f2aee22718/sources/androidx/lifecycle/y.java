package androidx.lifecycle;

import java.io.Closeable;
import java.io.IOException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/* JADX INFO: loaded from: classes.dex */
public abstract class y {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Map f5183a = new HashMap();

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final Set f5184b = new LinkedHashSet();

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private volatile boolean f5185c = false;

    private static void b(Object obj) {
        if (obj instanceof Closeable) {
            try {
                ((Closeable) obj).close();
            } catch (IOException e3) {
                throw new RuntimeException(e3);
            }
        }
    }

    final void a() {
        this.f5185c = true;
        Map map = this.f5183a;
        if (map != null) {
            synchronized (map) {
                try {
                    Iterator it = this.f5183a.values().iterator();
                    while (it.hasNext()) {
                        b(it.next());
                    }
                } finally {
                }
            }
        }
        Set set = this.f5184b;
        if (set != null) {
            synchronized (set) {
                try {
                    Iterator it2 = this.f5184b.iterator();
                    while (it2.hasNext()) {
                        b((Closeable) it2.next());
                    }
                } finally {
                }
            }
        }
        d();
    }

    Object c(String str) {
        Object obj;
        Map map = this.f5183a;
        if (map == null) {
            return null;
        }
        synchronized (map) {
            obj = this.f5183a.get(str);
        }
        return obj;
    }

    protected void d() {
    }
}
