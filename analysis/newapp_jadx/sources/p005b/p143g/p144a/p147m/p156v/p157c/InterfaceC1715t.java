package p005b.p143g.p144a.p147m.p156v.p157c;

import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.os.ParcelFileDescriptor;
import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;
import com.bumptech.glide.load.ImageHeaderParser;
import java.io.InputStream;
import java.util.List;
import java.util.Objects;
import p005b.p143g.p144a.p147m.C1575g;
import p005b.p143g.p144a.p147m.C1576h;
import p005b.p143g.p144a.p147m.p148s.C1597k;
import p005b.p143g.p144a.p147m.p148s.C1599m;
import p005b.p143g.p144a.p147m.p150t.p151c0.InterfaceC1612b;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.g.a.m.v.c.t */
/* loaded from: classes.dex */
public interface InterfaceC1715t {

    /* renamed from: b.g.a.m.v.c.t$a */
    public static final class a implements InterfaceC1715t {

        /* renamed from: a */
        public final C1597k f2530a;

        /* renamed from: b */
        public final InterfaceC1612b f2531b;

        /* renamed from: c */
        public final List<ImageHeaderParser> f2532c;

        public a(InputStream inputStream, List<ImageHeaderParser> list, InterfaceC1612b interfaceC1612b) {
            Objects.requireNonNull(interfaceC1612b, "Argument must not be null");
            this.f2531b = interfaceC1612b;
            Objects.requireNonNull(list, "Argument must not be null");
            this.f2532c = list;
            this.f2530a = new C1597k(inputStream, interfaceC1612b);
        }

        @Override // p005b.p143g.p144a.p147m.p156v.p157c.InterfaceC1715t
        /* renamed from: a */
        public int mo1019a() {
            return C4195m.m4807g0(this.f2532c, this.f2530a.mo841a(), this.f2531b);
        }

        @Override // p005b.p143g.p144a.p147m.p156v.p157c.InterfaceC1715t
        @Nullable
        /* renamed from: b */
        public Bitmap mo1020b(BitmapFactory.Options options) {
            return BitmapFactory.decodeStream(this.f2530a.mo841a(), null, options);
        }

        @Override // p005b.p143g.p144a.p147m.p156v.p157c.InterfaceC1715t
        /* renamed from: c */
        public void mo1021c() {
            C1719x c1719x = this.f2530a.f2020a;
            synchronized (c1719x) {
                c1719x.f2542f = c1719x.f2540c.length;
            }
        }

        @Override // p005b.p143g.p144a.p147m.p156v.p157c.InterfaceC1715t
        /* renamed from: d */
        public ImageHeaderParser.ImageType mo1022d() {
            return C4195m.m4811i0(this.f2532c, this.f2530a.mo841a(), this.f2531b);
        }
    }

    @RequiresApi(21)
    /* renamed from: b.g.a.m.v.c.t$b */
    public static final class b implements InterfaceC1715t {

        /* renamed from: a */
        public final InterfaceC1612b f2533a;

        /* renamed from: b */
        public final List<ImageHeaderParser> f2534b;

        /* renamed from: c */
        public final C1599m f2535c;

        public b(ParcelFileDescriptor parcelFileDescriptor, List<ImageHeaderParser> list, InterfaceC1612b interfaceC1612b) {
            Objects.requireNonNull(interfaceC1612b, "Argument must not be null");
            this.f2533a = interfaceC1612b;
            Objects.requireNonNull(list, "Argument must not be null");
            this.f2534b = list;
            this.f2535c = new C1599m(parcelFileDescriptor);
        }

        @Override // p005b.p143g.p144a.p147m.p156v.p157c.InterfaceC1715t
        /* renamed from: a */
        public int mo1019a() {
            return C4195m.m4809h0(this.f2534b, new C1576h(this.f2535c, this.f2533a));
        }

        @Override // p005b.p143g.p144a.p147m.p156v.p157c.InterfaceC1715t
        @Nullable
        /* renamed from: b */
        public Bitmap mo1020b(BitmapFactory.Options options) {
            return BitmapFactory.decodeFileDescriptor(this.f2535c.mo841a().getFileDescriptor(), null, options);
        }

        @Override // p005b.p143g.p144a.p147m.p156v.p157c.InterfaceC1715t
        /* renamed from: c */
        public void mo1021c() {
        }

        @Override // p005b.p143g.p144a.p147m.p156v.p157c.InterfaceC1715t
        /* renamed from: d */
        public ImageHeaderParser.ImageType mo1022d() {
            return C4195m.m4813j0(this.f2534b, new C1575g(this.f2535c, this.f2533a));
        }
    }

    /* renamed from: a */
    int mo1019a();

    @Nullable
    /* renamed from: b */
    Bitmap mo1020b(BitmapFactory.Options options);

    /* renamed from: c */
    void mo1021c();

    /* renamed from: d */
    ImageHeaderParser.ImageType mo1022d();
}
