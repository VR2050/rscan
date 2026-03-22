package p005b.p143g.p144a.p147m.p156v.p161g;

import android.util.Log;
import androidx.annotation.NonNull;
import com.bumptech.glide.load.ImageHeaderParser;
import com.bumptech.glide.load.resource.gif.GifDrawable;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.List;
import p005b.p143g.p144a.p147m.C1582n;
import p005b.p143g.p144a.p147m.InterfaceC1584p;
import p005b.p143g.p144a.p147m.p150t.InterfaceC1655w;
import p005b.p143g.p144a.p147m.p150t.p151c0.InterfaceC1612b;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.g.a.m.v.g.i */
/* loaded from: classes.dex */
public class C1739i implements InterfaceC1584p<InputStream, GifDrawable> {

    /* renamed from: a */
    public final List<ImageHeaderParser> f2593a;

    /* renamed from: b */
    public final InterfaceC1584p<ByteBuffer, GifDrawable> f2594b;

    /* renamed from: c */
    public final InterfaceC1612b f2595c;

    public C1739i(List<ImageHeaderParser> list, InterfaceC1584p<ByteBuffer, GifDrawable> interfaceC1584p, InterfaceC1612b interfaceC1612b) {
        this.f2593a = list;
        this.f2594b = interfaceC1584p;
        this.f2595c = interfaceC1612b;
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1584p
    /* renamed from: a */
    public boolean mo829a(@NonNull InputStream inputStream, @NonNull C1582n c1582n) {
        return !((Boolean) c1582n.m827a(C1738h.f2592b)).booleanValue() && C4195m.m4811i0(this.f2593a, inputStream, this.f2595c) == ImageHeaderParser.ImageType.GIF;
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1584p
    /* renamed from: b */
    public InterfaceC1655w<GifDrawable> mo830b(@NonNull InputStream inputStream, int i2, int i3, @NonNull C1582n c1582n) {
        byte[] bArr;
        InputStream inputStream2 = inputStream;
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream(16384);
        try {
            byte[] bArr2 = new byte[16384];
            while (true) {
                int read = inputStream2.read(bArr2);
                if (read == -1) {
                    break;
                }
                byteArrayOutputStream.write(bArr2, 0, read);
            }
            byteArrayOutputStream.flush();
            bArr = byteArrayOutputStream.toByteArray();
        } catch (IOException unused) {
            Log.isLoggable("StreamGifDecoder", 5);
            bArr = null;
        }
        if (bArr == null) {
            return null;
        }
        return this.f2594b.mo830b(ByteBuffer.wrap(bArr), i2, i3, c1582n);
    }
}
