package R0;

import Q0.E;
import Q0.i;
import a0.C0216b;
import android.os.Build;
import java.nio.ByteBuffer;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class g {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final g f2630a = new g();

    private g() {
    }

    public static final f a(E e3, boolean z3, boolean z4, h hVar) {
        j.f(e3, "poolFactory");
        j.f(hVar, "platformDecoderOptions");
        if (Build.VERSION.SDK_INT >= 26) {
            i iVarB = e3.b();
            j.e(iVarB, "getBitmapPool(...)");
            return new e(iVarB, b(e3, z4), hVar);
        }
        i iVarB2 = e3.b();
        j.e(iVarB2, "getBitmapPool(...)");
        return new a(iVarB2, b(e3, z4), hVar);
    }

    public static final q.e b(E e3, boolean z3) {
        j.f(e3, "poolFactory");
        if (z3) {
            C0216b c0216b = C0216b.f2913a;
            j.e(c0216b, "INSTANCE");
            return c0216b;
        }
        int iD = e3.d();
        q.f fVar = new q.f(iD);
        for (int i3 = 0; i3 < iD; i3++) {
            ByteBuffer byteBufferAllocate = ByteBuffer.allocate(C0216b.e());
            j.e(byteBufferAllocate, "allocate(...)");
            fVar.a(byteBufferAllocate);
        }
        return fVar;
    }
}
