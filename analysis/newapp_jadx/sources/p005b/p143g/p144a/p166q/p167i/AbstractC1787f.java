package p005b.p143g.p144a.p166q.p167i;

import android.graphics.drawable.Animatable;
import android.graphics.drawable.Drawable;
import android.widget.ImageView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import p005b.p143g.p144a.p166q.p168j.InterfaceC1793b;

/* renamed from: b.g.a.q.i.f */
/* loaded from: classes.dex */
public abstract class AbstractC1787f<Z> extends AbstractC1791j<ImageView, Z> {

    /* renamed from: g */
    @Nullable
    public Animatable f2727g;

    public AbstractC1787f(ImageView imageView) {
        super(imageView);
    }

    /* renamed from: a */
    public abstract void mo205a(@Nullable Z z);

    /* renamed from: b */
    public final void m1128b(@Nullable Z z) {
        mo205a(z);
        if (!(z instanceof Animatable)) {
            this.f2727g = null;
            return;
        }
        Animatable animatable = (Animatable) z;
        this.f2727g = animatable;
        animatable.start();
    }

    @Override // p005b.p143g.p144a.p166q.p167i.InterfaceC1790i
    public void onLoadCleared(@Nullable Drawable drawable) {
        this.f2730f.m1129a();
        Animatable animatable = this.f2727g;
        if (animatable != null) {
            animatable.stop();
        }
        m1128b(null);
        ((ImageView) this.f2729e).setImageDrawable(drawable);
    }

    @Override // p005b.p143g.p144a.p166q.p167i.InterfaceC1790i
    public void onLoadFailed(@Nullable Drawable drawable) {
        m1128b(null);
        ((ImageView) this.f2729e).setImageDrawable(drawable);
    }

    @Override // p005b.p143g.p144a.p166q.p167i.InterfaceC1790i
    public void onLoadStarted(@Nullable Drawable drawable) {
        m1128b(null);
        ((ImageView) this.f2729e).setImageDrawable(drawable);
    }

    @Override // p005b.p143g.p144a.p166q.p167i.InterfaceC1790i
    public void onResourceReady(@NonNull Z z, @Nullable InterfaceC1793b<? super Z> interfaceC1793b) {
        m1128b(z);
    }

    @Override // p005b.p143g.p144a.p163n.InterfaceC1755i
    public void onStart() {
        Animatable animatable = this.f2727g;
        if (animatable != null) {
            animatable.start();
        }
    }

    @Override // p005b.p143g.p144a.p163n.InterfaceC1755i
    public void onStop() {
        Animatable animatable = this.f2727g;
        if (animatable != null) {
            animatable.stop();
        }
    }
}
