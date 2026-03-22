package p005b.p143g.p144a.p147m.p156v.p157c;

import android.graphics.Bitmap;
import androidx.annotation.NonNull;
import p005b.p143g.p144a.p147m.C1582n;
import p005b.p143g.p144a.p147m.InterfaceC1584p;
import p005b.p143g.p144a.p147m.p150t.InterfaceC1655w;
import p005b.p143g.p144a.p170s.C1807i;

/* renamed from: b.g.a.m.v.c.c0 */
/* loaded from: classes.dex */
public final class C1696c0 implements InterfaceC1584p<Bitmap, Bitmap> {

    /* renamed from: b.g.a.m.v.c.c0$a */
    public static final class a implements InterfaceC1655w<Bitmap> {

        /* renamed from: c */
        public final Bitmap f2476c;

        public a(@NonNull Bitmap bitmap) {
            this.f2476c = bitmap;
        }

        @Override // p005b.p143g.p144a.p147m.p150t.InterfaceC1655w
        @NonNull
        /* renamed from: a */
        public Class<Bitmap> mo947a() {
            return Bitmap.class;
        }

        @Override // p005b.p143g.p144a.p147m.p150t.InterfaceC1655w
        @NonNull
        public Bitmap get() {
            return this.f2476c;
        }

        @Override // p005b.p143g.p144a.p147m.p150t.InterfaceC1655w
        public int getSize() {
            return C1807i.m1147d(this.f2476c);
        }

        @Override // p005b.p143g.p144a.p147m.p150t.InterfaceC1655w
        public void recycle() {
        }
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1584p
    /* renamed from: a */
    public /* bridge */ /* synthetic */ boolean mo829a(@NonNull Bitmap bitmap, @NonNull C1582n c1582n) {
        return true;
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1584p
    /* renamed from: b */
    public InterfaceC1655w<Bitmap> mo830b(@NonNull Bitmap bitmap, int i2, int i3, @NonNull C1582n c1582n) {
        return new a(bitmap);
    }
}
