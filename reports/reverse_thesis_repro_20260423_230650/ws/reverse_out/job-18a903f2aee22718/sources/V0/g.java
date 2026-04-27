package V0;

import N0.j;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.ColorSpace;
import android.graphics.Matrix;
import android.os.Build;
import java.io.OutputStream;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public final class g implements c {

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    public static final a f2819d = new a(null);

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final boolean f2820a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final int f2821b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final String f2822c = "SimpleImageTranscoder";

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public final Bitmap.CompressFormat b(C0.c cVar) {
            return cVar == null ? Bitmap.CompressFormat.JPEG : cVar == C0.b.f549b ? Bitmap.CompressFormat.JPEG : cVar == C0.b.f550c ? Bitmap.CompressFormat.PNG : C0.b.a(cVar) ? Bitmap.CompressFormat.WEBP : Bitmap.CompressFormat.JPEG;
        }

        private a() {
        }
    }

    public g(boolean z3, int i3) {
        this.f2820a = z3;
        this.f2821b = i3;
    }

    private final int e(j jVar, H0.h hVar, H0.g gVar) {
        if (this.f2820a) {
            return V0.a.b(hVar, gVar, jVar, this.f2821b);
        }
        return 1;
    }

    @Override // V0.c
    public boolean a(j jVar, H0.h hVar, H0.g gVar) {
        t2.j.f(jVar, "encodedImage");
        if (hVar == null) {
            hVar = H0.h.f1025c.a();
        }
        return this.f2820a && V0.a.b(hVar, gVar, jVar, this.f2821b) > 1;
    }

    @Override // V0.c
    public String b() {
        return this.f2822c;
    }

    @Override // V0.c
    public b c(j jVar, OutputStream outputStream, H0.h hVar, H0.g gVar, C0.c cVar, Integer num, ColorSpace colorSpace) throws Throwable {
        g gVar2;
        H0.h hVarA;
        Bitmap bitmapCreateBitmap;
        b bVar;
        t2.j.f(jVar, "encodedImage");
        t2.j.f(outputStream, "outputStream");
        Integer num2 = num == null ? 85 : num;
        if (hVar == null) {
            hVarA = H0.h.f1025c.a();
            gVar2 = this;
        } else {
            gVar2 = this;
            hVarA = hVar;
        }
        int iE = gVar2.e(jVar, hVarA, gVar);
        BitmapFactory.Options options = new BitmapFactory.Options();
        options.inSampleSize = iE;
        if (colorSpace != null && Build.VERSION.SDK_INT >= 26) {
            options.inPreferredColorSpace = colorSpace;
        }
        try {
            Bitmap bitmapDecodeStream = BitmapFactory.decodeStream(jVar.P(), null, options);
            if (bitmapDecodeStream == null) {
                Y.a.m("SimpleImageTranscoder", "Couldn't decode the EncodedImage InputStream ! ");
                return new b(2);
            }
            Matrix matrixG = e.g(jVar, hVarA);
            if (matrixG != null) {
                try {
                    bitmapCreateBitmap = Bitmap.createBitmap(bitmapDecodeStream, 0, 0, bitmapDecodeStream.getWidth(), bitmapDecodeStream.getHeight(), matrixG, false);
                } catch (OutOfMemoryError e3) {
                    e = e3;
                    bitmapCreateBitmap = bitmapDecodeStream;
                    Y.a.n("SimpleImageTranscoder", "Out-Of-Memory during transcode", e);
                    bVar = new b(2);
                    bitmapCreateBitmap.recycle();
                    bitmapDecodeStream.recycle();
                    return bVar;
                } catch (Throwable th) {
                    th = th;
                    bitmapCreateBitmap = bitmapDecodeStream;
                    bitmapCreateBitmap.recycle();
                    bitmapDecodeStream.recycle();
                    throw th;
                }
            } else {
                bitmapCreateBitmap = bitmapDecodeStream;
            }
            try {
                try {
                    bitmapCreateBitmap.compress(f2819d.b(cVar), num2.intValue(), outputStream);
                    bVar = new b(iE > 1 ? 0 : 1);
                } catch (OutOfMemoryError e4) {
                    e = e4;
                    Y.a.n("SimpleImageTranscoder", "Out-Of-Memory during transcode", e);
                    bVar = new b(2);
                }
                bitmapCreateBitmap.recycle();
                bitmapDecodeStream.recycle();
                return bVar;
            } catch (Throwable th2) {
                th = th2;
                bitmapCreateBitmap.recycle();
                bitmapDecodeStream.recycle();
                throw th;
            }
        } catch (OutOfMemoryError e5) {
            Y.a.n("SimpleImageTranscoder", "Out-Of-Memory during transcode", e5);
            return new b(2);
        }
    }

    @Override // V0.c
    public boolean d(C0.c cVar) {
        t2.j.f(cVar, "imageFormat");
        return cVar == C0.b.f559l || cVar == C0.b.f549b;
    }
}
