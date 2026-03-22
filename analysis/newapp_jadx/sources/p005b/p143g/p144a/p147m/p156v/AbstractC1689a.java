package p005b.p143g.p144a.p147m.p156v;

import android.annotation.SuppressLint;
import android.graphics.Bitmap;
import android.graphics.ColorSpace;
import android.graphics.ImageDecoder;
import android.os.Build;
import android.util.Log;
import android.util.Size;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;
import p005b.p143g.p144a.p147m.C1581m;
import p005b.p143g.p144a.p147m.C1582n;
import p005b.p143g.p144a.p147m.EnumC1570b;
import p005b.p143g.p144a.p147m.EnumC1583o;
import p005b.p143g.p144a.p147m.InterfaceC1584p;
import p005b.p143g.p144a.p147m.p150t.InterfaceC1655w;
import p005b.p143g.p144a.p147m.p156v.p157c.AbstractC1708m;
import p005b.p143g.p144a.p147m.p156v.p157c.C1697d;
import p005b.p143g.p144a.p147m.p156v.p157c.C1699e;
import p005b.p143g.p144a.p147m.p156v.p157c.C1709n;
import p005b.p143g.p144a.p147m.p156v.p157c.C1714s;

@RequiresApi(api = 28)
/* renamed from: b.g.a.m.v.a */
/* loaded from: classes.dex */
public abstract class AbstractC1689a<T> implements InterfaceC1584p<ImageDecoder.Source, T> {

    /* renamed from: a */
    public final C1714s f2451a = C1714s.m1017a();

    /* renamed from: b.g.a.m.v.a$a */
    public class a implements ImageDecoder.OnHeaderDecodedListener {

        /* renamed from: a */
        public final /* synthetic */ int f2452a;

        /* renamed from: b */
        public final /* synthetic */ int f2453b;

        /* renamed from: c */
        public final /* synthetic */ boolean f2454c;

        /* renamed from: d */
        public final /* synthetic */ EnumC1570b f2455d;

        /* renamed from: e */
        public final /* synthetic */ AbstractC1708m f2456e;

        /* renamed from: f */
        public final /* synthetic */ EnumC1583o f2457f;

        /* renamed from: b.g.a.m.v.a$a$a, reason: collision with other inner class name */
        public class C5111a implements ImageDecoder.OnPartialImageListener {
            public C5111a(a aVar) {
            }

            @Override // android.graphics.ImageDecoder.OnPartialImageListener
            public boolean onPartialImage(@NonNull ImageDecoder.DecodeException decodeException) {
                return false;
            }
        }

        public a(int i2, int i3, boolean z, EnumC1570b enumC1570b, AbstractC1708m abstractC1708m, EnumC1583o enumC1583o) {
            this.f2452a = i2;
            this.f2453b = i3;
            this.f2454c = z;
            this.f2455d = enumC1570b;
            this.f2456e = abstractC1708m;
            this.f2457f = enumC1583o;
        }

        @Override // android.graphics.ImageDecoder.OnHeaderDecodedListener
        @SuppressLint({"Override"})
        public void onHeaderDecoded(ImageDecoder imageDecoder, ImageDecoder.ImageInfo imageInfo, ImageDecoder.Source source) {
            boolean z = false;
            if (AbstractC1689a.this.f2451a.m1018b(this.f2452a, this.f2453b, this.f2454c, false)) {
                imageDecoder.setAllocator(3);
            } else {
                imageDecoder.setAllocator(1);
            }
            if (this.f2455d == EnumC1570b.PREFER_RGB_565) {
                imageDecoder.setMemorySizePolicy(0);
            }
            imageDecoder.setOnPartialImageListener(new C5111a(this));
            Size size = imageInfo.getSize();
            int i2 = this.f2452a;
            if (i2 == Integer.MIN_VALUE) {
                i2 = size.getWidth();
            }
            int i3 = this.f2453b;
            if (i3 == Integer.MIN_VALUE) {
                i3 = size.getHeight();
            }
            float mo1004b = this.f2456e.mo1004b(size.getWidth(), size.getHeight(), i2, i3);
            int round = Math.round(size.getWidth() * mo1004b);
            int round2 = Math.round(mo1004b * size.getHeight());
            if (Log.isLoggable("ImageDecoder", 2)) {
                size.getWidth();
                size.getHeight();
            }
            imageDecoder.setTargetSize(round, round2);
            int i4 = Build.VERSION.SDK_INT;
            if (i4 < 28) {
                if (i4 >= 26) {
                    imageDecoder.setTargetColorSpace(ColorSpace.get(ColorSpace.Named.SRGB));
                }
            } else {
                if (this.f2457f == EnumC1583o.DISPLAY_P3 && imageInfo.getColorSpace() != null && imageInfo.getColorSpace().isWideGamut()) {
                    z = true;
                }
                imageDecoder.setTargetColorSpace(ColorSpace.get(z ? ColorSpace.Named.DISPLAY_P3 : ColorSpace.Named.SRGB));
            }
        }
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1584p
    /* renamed from: a */
    public /* bridge */ /* synthetic */ boolean mo829a(@NonNull ImageDecoder.Source source, @NonNull C1582n c1582n) {
        return true;
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1584p
    @Nullable
    /* renamed from: c, reason: merged with bridge method [inline-methods] */
    public final InterfaceC1655w<T> mo830b(@NonNull ImageDecoder.Source source, int i2, int i3, @NonNull C1582n c1582n) {
        EnumC1570b enumC1570b = (EnumC1570b) c1582n.m827a(C1709n.f2506a);
        AbstractC1708m abstractC1708m = (AbstractC1708m) c1582n.m827a(AbstractC1708m.f2504f);
        C1581m<Boolean> c1581m = C1709n.f2509d;
        a aVar = new a(i2, i3, c1582n.m827a(c1581m) != null && ((Boolean) c1582n.m827a(c1581m)).booleanValue(), enumC1570b, abstractC1708m, (EnumC1583o) c1582n.m827a(C1709n.f2507b));
        C1697d c1697d = (C1697d) this;
        Bitmap decodeBitmap = ImageDecoder.decodeBitmap(source, aVar);
        if (Log.isLoggable("BitmapImageDecoder", 2)) {
            decodeBitmap.getWidth();
            decodeBitmap.getHeight();
        }
        return new C1699e(decodeBitmap, c1697d.f2477b);
    }
}
