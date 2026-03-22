package p005b.p143g.p144a.p147m.p156v.p159e;

import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.Drawable;
import androidx.annotation.NonNull;
import com.bumptech.glide.load.resource.gif.GifDrawable;
import java.util.Objects;
import p005b.p143g.p144a.p147m.p150t.InterfaceC1651s;
import p005b.p143g.p144a.p147m.p150t.InterfaceC1655w;

/* renamed from: b.g.a.m.v.e.b */
/* loaded from: classes.dex */
public abstract class AbstractC1725b<T extends Drawable> implements InterfaceC1655w<T>, InterfaceC1651s {

    /* renamed from: c */
    public final T f2553c;

    public AbstractC1725b(T t) {
        Objects.requireNonNull(t, "Argument must not be null");
        this.f2553c = t;
    }

    @Override // p005b.p143g.p144a.p147m.p150t.InterfaceC1655w
    @NonNull
    public Object get() {
        Drawable.ConstantState constantState = this.f2553c.getConstantState();
        return constantState == null ? this.f2553c : constantState.newDrawable();
    }

    @Override // p005b.p143g.p144a.p147m.p150t.InterfaceC1651s
    public void initialize() {
        T t = this.f2553c;
        if (t instanceof BitmapDrawable) {
            ((BitmapDrawable) t).getBitmap().prepareToDraw();
        } else if (t instanceof GifDrawable) {
            ((GifDrawable) t).m3892b().prepareToDraw();
        }
    }
}
