package p005b.p143g.p144a.p147m.p156v.p161g;

import android.graphics.Bitmap;
import androidx.annotation.NonNull;
import com.bumptech.glide.load.resource.gif.GifDrawable;
import p005b.p143g.p144a.p147m.p150t.InterfaceC1651s;
import p005b.p143g.p144a.p147m.p156v.p159e.AbstractC1725b;
import p005b.p143g.p144a.p147m.p156v.p161g.C1736f;

/* renamed from: b.g.a.m.v.g.d */
/* loaded from: classes.dex */
public class C1734d extends AbstractC1725b<GifDrawable> implements InterfaceC1651s {
    public C1734d(GifDrawable gifDrawable) {
        super(gifDrawable);
    }

    @Override // p005b.p143g.p144a.p147m.p150t.InterfaceC1655w
    @NonNull
    /* renamed from: a */
    public Class<GifDrawable> mo947a() {
        return GifDrawable.class;
    }

    @Override // p005b.p143g.p144a.p147m.p150t.InterfaceC1655w
    public int getSize() {
        C1736f c1736f = ((GifDrawable) this.f2553c).f8843c.f8854a;
        return c1736f.f2567a.mo810g() + c1736f.f2582p;
    }

    @Override // p005b.p143g.p144a.p147m.p156v.p159e.AbstractC1725b, p005b.p143g.p144a.p147m.p150t.InterfaceC1651s
    public void initialize() {
        ((GifDrawable) this.f2553c).m3892b().prepareToDraw();
    }

    @Override // p005b.p143g.p144a.p147m.p150t.InterfaceC1655w
    public void recycle() {
        ((GifDrawable) this.f2553c).stop();
        GifDrawable gifDrawable = (GifDrawable) this.f2553c;
        gifDrawable.f8846g = true;
        C1736f c1736f = gifDrawable.f8843c.f8854a;
        c1736f.f2569c.clear();
        Bitmap bitmap = c1736f.f2578l;
        if (bitmap != null) {
            c1736f.f2571e.mo870d(bitmap);
            c1736f.f2578l = null;
        }
        c1736f.f2572f = false;
        C1736f.a aVar = c1736f.f2575i;
        if (aVar != null) {
            c1736f.f2570d.m772e(aVar);
            c1736f.f2575i = null;
        }
        C1736f.a aVar2 = c1736f.f2577k;
        if (aVar2 != null) {
            c1736f.f2570d.m772e(aVar2);
            c1736f.f2577k = null;
        }
        C1736f.a aVar3 = c1736f.f2580n;
        if (aVar3 != null) {
            c1736f.f2570d.m772e(aVar3);
            c1736f.f2580n = null;
        }
        c1736f.f2567a.clear();
        c1736f.f2576j = true;
    }
}
