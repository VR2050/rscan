package Q0;

import a0.InterfaceC0223i;
import java.io.IOException;
import java.io.InputStream;

/* JADX INFO: loaded from: classes.dex */
public final class z implements InterfaceC0223i {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final com.facebook.imagepipeline.memory.e f2398a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final a0.l f2399b;

    public z(com.facebook.imagepipeline.memory.e eVar, a0.l lVar) {
        t2.j.f(eVar, "pool");
        t2.j.f(lVar, "pooledByteStreams");
        this.f2398a = eVar;
        this.f2399b = lVar;
    }

    public final y f(InputStream inputStream, com.facebook.imagepipeline.memory.f fVar) {
        t2.j.f(inputStream, "inputStream");
        t2.j.f(fVar, "outputStream");
        this.f2399b.a(inputStream, fVar);
        return fVar.b();
    }

    @Override // a0.InterfaceC0223i
    /* JADX INFO: renamed from: g, reason: merged with bridge method [inline-methods] */
    public y d(InputStream inputStream) throws Throwable {
        t2.j.f(inputStream, "inputStream");
        com.facebook.imagepipeline.memory.f fVar = new com.facebook.imagepipeline.memory.f(this.f2398a, 0, 2, null);
        try {
            return f(inputStream, fVar);
        } finally {
            fVar.close();
        }
    }

    @Override // a0.InterfaceC0223i
    /* JADX INFO: renamed from: h, reason: merged with bridge method [inline-methods] */
    public y a(InputStream inputStream, int i3) throws Throwable {
        t2.j.f(inputStream, "inputStream");
        com.facebook.imagepipeline.memory.f fVar = new com.facebook.imagepipeline.memory.f(this.f2398a, i3);
        try {
            return f(inputStream, fVar);
        } finally {
            fVar.close();
        }
    }

    @Override // a0.InterfaceC0223i
    /* JADX INFO: renamed from: i, reason: merged with bridge method [inline-methods] */
    public y c(byte[] bArr) throws Throwable {
        t2.j.f(bArr, "bytes");
        com.facebook.imagepipeline.memory.f fVar = new com.facebook.imagepipeline.memory.f(this.f2398a, bArr.length);
        try {
            try {
                fVar.write(bArr, 0, bArr.length);
                return fVar.b();
            } catch (IOException e3) {
                throw X.p.a(e3);
            }
        } finally {
            fVar.close();
        }
    }

    @Override // a0.InterfaceC0223i
    /* JADX INFO: renamed from: j, reason: merged with bridge method [inline-methods] */
    public com.facebook.imagepipeline.memory.f b() {
        return new com.facebook.imagepipeline.memory.f(this.f2398a, 0, 2, null);
    }

    @Override // a0.InterfaceC0223i
    /* JADX INFO: renamed from: k, reason: merged with bridge method [inline-methods] */
    public com.facebook.imagepipeline.memory.f e(int i3) {
        return new com.facebook.imagepipeline.memory.f(this.f2398a, i3);
    }
}
