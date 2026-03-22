package p005b.p143g.p144a.p147m.p156v.p159e;

import android.graphics.drawable.Drawable;
import androidx.annotation.NonNull;

/* renamed from: b.g.a.m.v.e.c */
/* loaded from: classes.dex */
public final class C1726c extends AbstractC1725b<Drawable> {
    public C1726c(Drawable drawable) {
        super(drawable);
    }

    @Override // p005b.p143g.p144a.p147m.p150t.InterfaceC1655w
    @NonNull
    /* renamed from: a */
    public Class<Drawable> mo947a() {
        return this.f2553c.getClass();
    }

    @Override // p005b.p143g.p144a.p147m.p150t.InterfaceC1655w
    public int getSize() {
        return Math.max(1, this.f2553c.getIntrinsicHeight() * this.f2553c.getIntrinsicWidth() * 4);
    }

    @Override // p005b.p143g.p144a.p147m.p150t.InterfaceC1655w
    public void recycle() {
    }
}
