package p005b.p143g.p144a.p147m.p156v.p157c;

import android.graphics.Bitmap;
import android.graphics.ImageDecoder;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.concurrent.atomic.AtomicReference;
import p005b.p143g.p144a.p147m.C1582n;
import p005b.p143g.p144a.p147m.InterfaceC1584p;
import p005b.p143g.p144a.p147m.p150t.InterfaceC1655w;
import p005b.p143g.p144a.p170s.C1799a;

@RequiresApi(api = 28)
/* renamed from: b.g.a.m.v.c.u */
/* loaded from: classes.dex */
public final class C1716u implements InterfaceC1584p<InputStream, Bitmap> {

    /* renamed from: a */
    public final C1697d f2536a = new C1697d();

    @Override // p005b.p143g.p144a.p147m.InterfaceC1584p
    /* renamed from: a */
    public /* bridge */ /* synthetic */ boolean mo829a(@NonNull InputStream inputStream, @NonNull C1582n c1582n) {
        return true;
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1584p
    @Nullable
    /* renamed from: b */
    public InterfaceC1655w<Bitmap> mo830b(@NonNull InputStream inputStream, int i2, int i3, @NonNull C1582n c1582n) {
        InputStream inputStream2 = inputStream;
        AtomicReference<byte[]> atomicReference = C1799a.f2744a;
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream(16384);
        byte[] andSet = C1799a.f2744a.getAndSet(null);
        if (andSet == null) {
            andSet = new byte[16384];
        }
        while (true) {
            int read = inputStream2.read(andSet);
            if (read < 0) {
                C1799a.f2744a.set(andSet);
                byte[] byteArray = byteArrayOutputStream.toByteArray();
                return this.f2536a.mo830b(ImageDecoder.createSource((ByteBuffer) ByteBuffer.allocateDirect(byteArray.length).put(byteArray).position(0)), i2, i3, c1582n);
            }
            byteArrayOutputStream.write(andSet, 0, read);
        }
    }
}
