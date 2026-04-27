package Q0;

import a0.InterfaceC0215a;
import a0.InterfaceC0218d;
import a0.InterfaceC0223i;
import com.facebook.imagepipeline.memory.AshmemMemoryChunkPool;
import com.facebook.imagepipeline.memory.BufferMemoryChunkPool;
import com.facebook.imagepipeline.memory.NativeMemoryChunkPool;
import java.lang.reflect.InvocationTargetException;

/* JADX INFO: loaded from: classes.dex */
public class E {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final C f2342a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private com.facebook.imagepipeline.memory.e f2343b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private i f2344c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private com.facebook.imagepipeline.memory.e f2345d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private com.facebook.imagepipeline.memory.e f2346e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private InterfaceC0223i f2347f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private a0.l f2348g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private InterfaceC0215a f2349h;

    public E(C c3) {
        this.f2342a = (C) X.k.g(c3);
    }

    private com.facebook.imagepipeline.memory.e a() {
        if (this.f2343b == null) {
            try {
                this.f2343b = (com.facebook.imagepipeline.memory.e) AshmemMemoryChunkPool.class.getConstructor(InterfaceC0218d.class, F.class, G.class).newInstance(this.f2342a.i(), this.f2342a.g(), this.f2342a.h());
            } catch (ClassNotFoundException unused) {
                this.f2343b = null;
            } catch (IllegalAccessException unused2) {
                this.f2343b = null;
            } catch (InstantiationException unused3) {
                this.f2343b = null;
            } catch (NoSuchMethodException unused4) {
                this.f2343b = null;
            } catch (InvocationTargetException unused5) {
                this.f2343b = null;
            }
        }
        return this.f2343b;
    }

    private com.facebook.imagepipeline.memory.e e(int i3) {
        if (i3 == 0) {
            return f();
        }
        if (i3 == 1) {
            return c();
        }
        if (i3 == 2) {
            return a();
        }
        throw new IllegalArgumentException("Invalid MemoryChunkType");
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    /* JADX WARN: Removed duplicated region for block: B:22:0x0047  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public Q0.i b() {
        /*
            Method dump skipped, instruction units count: 222
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: Q0.E.b():Q0.i");
    }

    public com.facebook.imagepipeline.memory.e c() {
        if (this.f2345d == null) {
            try {
                this.f2345d = (com.facebook.imagepipeline.memory.e) BufferMemoryChunkPool.class.getConstructor(InterfaceC0218d.class, F.class, G.class).newInstance(this.f2342a.i(), this.f2342a.g(), this.f2342a.h());
            } catch (ClassNotFoundException unused) {
                this.f2345d = null;
            } catch (IllegalAccessException unused2) {
                this.f2345d = null;
            } catch (InstantiationException unused3) {
                this.f2345d = null;
            } catch (NoSuchMethodException unused4) {
                this.f2345d = null;
            } catch (InvocationTargetException unused5) {
                this.f2345d = null;
            }
        }
        return this.f2345d;
    }

    public int d() {
        return this.f2342a.f().f2356g;
    }

    public com.facebook.imagepipeline.memory.e f() {
        if (this.f2346e == null) {
            try {
                this.f2346e = (com.facebook.imagepipeline.memory.e) NativeMemoryChunkPool.class.getConstructor(InterfaceC0218d.class, F.class, G.class).newInstance(this.f2342a.i(), this.f2342a.g(), this.f2342a.h());
            } catch (ClassNotFoundException e3) {
                Y.a.n("PoolFactory", "", e3);
                this.f2346e = null;
            } catch (IllegalAccessException e4) {
                Y.a.n("PoolFactory", "", e4);
                this.f2346e = null;
            } catch (InstantiationException e5) {
                Y.a.n("PoolFactory", "", e5);
                this.f2346e = null;
            } catch (NoSuchMethodException e6) {
                Y.a.n("PoolFactory", "", e6);
                this.f2346e = null;
            } catch (InvocationTargetException e7) {
                Y.a.n("PoolFactory", "", e7);
                this.f2346e = null;
            }
        }
        return this.f2346e;
    }

    public InterfaceC0223i g(int i3) {
        if (this.f2347f == null) {
            com.facebook.imagepipeline.memory.e eVarE = e(i3);
            X.k.h(eVarE, "failed to get pool for chunk type: " + i3);
            this.f2347f = new z(eVarE, h());
        }
        return this.f2347f;
    }

    public a0.l h() {
        if (this.f2348g == null) {
            this.f2348g = new a0.l(i());
        }
        return this.f2348g;
    }

    public InterfaceC0215a i() {
        if (this.f2349h == null) {
            this.f2349h = new com.facebook.imagepipeline.memory.d(this.f2342a.i(), this.f2342a.j(), this.f2342a.k());
        }
        return this.f2349h;
    }
}
