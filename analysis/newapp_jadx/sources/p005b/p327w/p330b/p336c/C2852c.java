package p005b.p327w.p330b.p336c;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.drawable.Drawable;
import androidx.annotation.CheckResult;
import androidx.annotation.DrawableRes;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.RawRes;
import com.bumptech.glide.load.resource.gif.GifDrawable;
import p005b.p143g.p144a.C1558h;
import p005b.p143g.p144a.ComponentCallbacks2C1553c;
import p005b.p143g.p144a.ComponentCallbacks2C1559i;
import p005b.p143g.p144a.p163n.InterfaceC1754h;
import p005b.p143g.p144a.p163n.InterfaceC1759m;
import p005b.p143g.p144a.p166q.C1779f;

/* renamed from: b.w.b.c.c */
/* loaded from: classes2.dex */
public class C2852c extends ComponentCallbacks2C1559i {
    public C2852c(@NonNull ComponentCallbacks2C1553c componentCallbacks2C1553c, @NonNull InterfaceC1754h interfaceC1754h, @NonNull InterfaceC1759m interfaceC1759m, @NonNull Context context) {
        super(componentCallbacks2C1553c, interfaceC1754h, interfaceC1759m, context);
    }

    @Override // p005b.p143g.p144a.ComponentCallbacks2C1559i
    @NonNull
    @CheckResult
    /* renamed from: a */
    public C1558h mo768a(@NonNull Class cls) {
        return new C2851b(this.f1873f, this, cls, this.f1874g);
    }

    @Override // p005b.p143g.p144a.ComponentCallbacks2C1559i
    @NonNull
    @CheckResult
    /* renamed from: c */
    public C1558h mo770c() {
        return (C2851b) super.mo770c();
    }

    @Override // p005b.p143g.p144a.ComponentCallbacks2C1559i
    @NonNull
    @CheckResult
    /* renamed from: d */
    public C1558h mo771d() {
        return (C2851b) mo768a(GifDrawable.class).mo766a(ComponentCallbacks2C1559i.f1872e);
    }

    @Override // p005b.p143g.p144a.ComponentCallbacks2C1559i
    @NonNull
    @CheckResult
    /* renamed from: f */
    public C1558h mo773f(@Nullable Drawable drawable) {
        return (C2851b) mo770c().mo759T(drawable);
    }

    @Override // p005b.p143g.p144a.ComponentCallbacks2C1559i
    @NonNull
    @CheckResult
    /* renamed from: g */
    public C1558h mo774g(@Nullable Object obj) {
        C1558h mo770c = mo770c();
        mo770c.mo762W(obj);
        return (C2851b) mo770c;
    }

    @Override // p005b.p143g.p144a.ComponentCallbacks2C1559i
    @NonNull
    @CheckResult
    /* renamed from: h */
    public C1558h mo775h(@Nullable String str) {
        C1558h mo770c = mo770c();
        mo770c.mo763X(str);
        return (C2851b) mo770c;
    }

    @Override // p005b.p143g.p144a.ComponentCallbacks2C1559i
    @NonNull
    /* renamed from: k */
    public ComponentCallbacks2C1559i mo778k(@NonNull C1779f c1779f) {
        synchronized (this) {
            synchronized (this) {
                mo779l(c1779f);
            }
            return this;
        }
        return this;
    }

    @Override // p005b.p143g.p144a.ComponentCallbacks2C1559i
    /* renamed from: l */
    public void mo779l(@NonNull C1779f c1779f) {
        if (c1779f instanceof C2850a) {
            super.mo779l(c1779f);
        } else {
            super.mo779l(new C2850a().m3286M(c1779f));
        }
    }

    @Override // p005b.p143g.p144a.ComponentCallbacks2C1559i
    @NonNull
    @CheckResult
    /* renamed from: n, reason: merged with bridge method [inline-methods] */
    public C2851b<Bitmap> mo769b() {
        return (C2851b) super.mo769b();
    }

    @NonNull
    @CheckResult
    /* renamed from: o */
    public C2851b<Drawable> m3297o(@Nullable @DrawableRes @RawRes Integer num) {
        return (C2851b) mo770c().mo761V(num);
    }

    @NonNull
    @CheckResult
    /* renamed from: p */
    public C2851b<Drawable> m3298p(@Nullable String str) {
        C1558h mo770c = mo770c();
        mo770c.mo763X(str);
        return (C2851b) mo770c;
    }
}
