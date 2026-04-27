package com.facebook.imagepipeline.platform;

import X.a;
import X.b;
import X.k;
import X.p;
import a0.InterfaceC0222h;
import a0.j;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.os.MemoryFile;
import b0.AbstractC0311a;
import com.facebook.imagepipeline.nativecode.DalvikPurgeableDecoder;
import d0.C0503a;
import g0.AbstractC0532b;
import java.io.FileDescriptor;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Method;

/* JADX INFO: loaded from: classes.dex */
public class GingerbreadPurgeableDecoder extends DalvikPurgeableDecoder {

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private static Method f6081c;

    public GingerbreadPurgeableDecoder() {
        AbstractC0532b.i();
    }

    private static MemoryFile h(AbstractC0311a abstractC0311a, int i3, byte[] bArr) throws Throwable {
        OutputStream outputStream;
        C0503a c0503a;
        j jVar;
        j jVar2 = null;
        OutputStream outputStream2 = null;
        MemoryFile memoryFile = new MemoryFile(null, (bArr == null ? 0 : bArr.length) + i3);
        memoryFile.allowPurging(false);
        try {
            jVar = new j((InterfaceC0222h) abstractC0311a.P());
            try {
                c0503a = new C0503a(jVar, i3);
            } catch (Throwable th) {
                th = th;
                outputStream = null;
                c0503a = null;
            }
        } catch (Throwable th2) {
            th = th2;
            outputStream = null;
            c0503a = null;
        }
        try {
            outputStream2 = memoryFile.getOutputStream();
            a.a(c0503a, outputStream2);
            if (bArr != null) {
                memoryFile.writeBytes(bArr, 0, i3, bArr.length);
            }
            AbstractC0311a.D(abstractC0311a);
            b.b(jVar);
            b.b(c0503a);
            b.a(outputStream2, true);
            return memoryFile;
        } catch (Throwable th3) {
            th = th3;
            outputStream = outputStream2;
            jVar2 = jVar;
            AbstractC0311a.D(abstractC0311a);
            b.b(jVar2);
            b.b(c0503a);
            b.a(outputStream, true);
            throw th;
        }
    }

    private Bitmap i(AbstractC0311a abstractC0311a, int i3, byte[] bArr, BitmapFactory.Options options) {
        MemoryFile memoryFileH = null;
        try {
            try {
                memoryFileH = h(abstractC0311a, i3, bArr);
                k(memoryFileH);
                throw new IllegalStateException("WebpBitmapFactory is null");
            } catch (IOException e3) {
                throw p.a(e3);
            }
        } catch (Throwable th) {
            if (memoryFileH != null) {
                memoryFileH.close();
            }
            throw th;
        }
    }

    private synchronized Method j() {
        if (f6081c == null) {
            try {
                f6081c = MemoryFile.class.getDeclaredMethod("getFileDescriptor", new Class[0]);
            } catch (Exception e3) {
                throw p.a(e3);
            }
        }
        return f6081c;
    }

    private FileDescriptor k(MemoryFile memoryFile) {
        try {
            return (FileDescriptor) k.g(j().invoke(memoryFile, new Object[0]));
        } catch (Exception e3) {
            throw p.a(e3);
        }
    }

    @Override // com.facebook.imagepipeline.nativecode.DalvikPurgeableDecoder
    protected Bitmap c(AbstractC0311a abstractC0311a, BitmapFactory.Options options) {
        return i(abstractC0311a, ((InterfaceC0222h) abstractC0311a.P()).size(), null, options);
    }

    @Override // com.facebook.imagepipeline.nativecode.DalvikPurgeableDecoder
    protected Bitmap d(AbstractC0311a abstractC0311a, int i3, BitmapFactory.Options options) {
        return i(abstractC0311a, i3, DalvikPurgeableDecoder.e(abstractC0311a, i3) ? null : DalvikPurgeableDecoder.f6070b, options);
    }
}
