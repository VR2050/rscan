package p476m.p496b.p500b.p502g;

import java.lang.ref.Reference;
import java.lang.ref.WeakReference;
import java.util.HashMap;
import java.util.concurrent.locks.ReentrantLock;

/* renamed from: m.b.b.g.c */
/* loaded from: classes3.dex */
public class C4940c<K, T> implements InterfaceC4938a<K, T> {

    /* renamed from: a */
    public final HashMap<K, Reference<T>> f12591a = new HashMap<>();

    /* renamed from: b */
    public final ReentrantLock f12592b = new ReentrantLock();

    @Override // p476m.p496b.p500b.p502g.InterfaceC4938a
    /* renamed from: a */
    public void mo5606a(K k2, T t) {
        this.f12591a.put(k2, new WeakReference(t));
    }

    @Override // p476m.p496b.p500b.p502g.InterfaceC4938a
    /* renamed from: b */
    public T mo5607b(K k2) {
        Reference<T> reference = this.f12591a.get(k2);
        if (reference != null) {
            return reference.get();
        }
        return null;
    }

    @Override // p476m.p496b.p500b.p502g.InterfaceC4938a
    /* renamed from: c */
    public void mo5608c(int i2) {
    }

    @Override // p476m.p496b.p500b.p502g.InterfaceC4938a
    public T get(K k2) {
        this.f12592b.lock();
        try {
            Reference<T> reference = this.f12591a.get(k2);
            if (reference != null) {
                return reference.get();
            }
            return null;
        } finally {
            this.f12592b.unlock();
        }
    }

    @Override // p476m.p496b.p500b.p502g.InterfaceC4938a
    public void lock() {
        this.f12592b.lock();
    }

    @Override // p476m.p496b.p500b.p502g.InterfaceC4938a
    public void put(K k2, T t) {
        this.f12592b.lock();
        try {
            this.f12591a.put(k2, new WeakReference(t));
        } finally {
            this.f12592b.unlock();
        }
    }

    @Override // p476m.p496b.p500b.p502g.InterfaceC4938a
    public void remove(K k2) {
        this.f12592b.lock();
        try {
            this.f12591a.remove(k2);
        } finally {
            this.f12592b.unlock();
        }
    }

    @Override // p476m.p496b.p500b.p502g.InterfaceC4938a
    public void unlock() {
        this.f12592b.unlock();
    }
}
