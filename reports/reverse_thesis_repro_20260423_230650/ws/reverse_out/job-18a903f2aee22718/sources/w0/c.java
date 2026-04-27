package w0;

import X.i;
import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.Bitmap;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.view.MotionEvent;
import android.view.View;
import android.widget.ImageView;
import v0.InterfaceC0705a;
import v0.InterfaceC0706b;
import w0.AbstractC0712a;

/* JADX INFO: loaded from: classes.dex */
public abstract class c extends ImageView {

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private static boolean f10289h = false;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final AbstractC0712a.C0154a f10290b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private float f10291c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private C0713b f10292d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private boolean f10293e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private boolean f10294f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private Object f10295g;

    public c(Context context) {
        super(context);
        this.f10290b = new AbstractC0712a.C0154a();
        this.f10291c = 0.0f;
        this.f10293e = false;
        this.f10294f = false;
        this.f10295g = null;
        c(context);
    }

    private void c(Context context) {
        try {
            if (U0.b.d()) {
                U0.b.a("DraweeView#init");
            }
            if (this.f10293e) {
                if (U0.b.d()) {
                    U0.b.b();
                    return;
                }
                return;
            }
            boolean z3 = true;
            this.f10293e = true;
            this.f10292d = C0713b.c(null, context);
            ColorStateList imageTintList = getImageTintList();
            if (imageTintList == null) {
                if (U0.b.d()) {
                    U0.b.b();
                    return;
                }
                return;
            }
            setColorFilter(imageTintList.getDefaultColor());
            if (!f10289h || context.getApplicationInfo().targetSdkVersion < 24) {
                z3 = false;
            }
            this.f10294f = z3;
            if (U0.b.d()) {
                U0.b.b();
            }
        } catch (Throwable th) {
            if (U0.b.d()) {
                U0.b.b();
            }
            throw th;
        }
    }

    private void d() {
        Drawable drawable;
        if (!this.f10294f || (drawable = getDrawable()) == null) {
            return;
        }
        drawable.setVisible(getVisibility() == 0, false);
    }

    public static void setGlobalLegacyVisibilityHandlingEnabled(boolean z3) {
        f10289h = z3;
    }

    protected void a() {
        this.f10292d.j();
    }

    protected void b() {
        this.f10292d.k();
    }

    protected void e() {
        a();
    }

    protected void f() {
        b();
    }

    public float getAspectRatio() {
        return this.f10291c;
    }

    public InterfaceC0705a getController() {
        return this.f10292d.e();
    }

    public Object getExtraData() {
        return this.f10295g;
    }

    public InterfaceC0706b getHierarchy() {
        return this.f10292d.f();
    }

    public Drawable getTopLevelDrawable() {
        return this.f10292d.g();
    }

    @Override // android.widget.ImageView, android.view.View
    protected void onAttachedToWindow() {
        super.onAttachedToWindow();
        d();
        e();
    }

    @Override // android.widget.ImageView, android.view.View
    protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        d();
        f();
    }

    @Override // android.view.View
    public void onFinishTemporaryDetach() {
        super.onFinishTemporaryDetach();
        d();
        e();
    }

    @Override // android.widget.ImageView, android.view.View
    protected void onMeasure(int i3, int i4) {
        AbstractC0712a.C0154a c0154a = this.f10290b;
        c0154a.f10281a = i3;
        c0154a.f10282b = i4;
        AbstractC0712a.b(c0154a, this.f10291c, getLayoutParams(), getPaddingLeft() + getPaddingRight(), getPaddingTop() + getPaddingBottom());
        AbstractC0712a.C0154a c0154a2 = this.f10290b;
        super.onMeasure(c0154a2.f10281a, c0154a2.f10282b);
    }

    @Override // android.view.View
    public void onStartTemporaryDetach() {
        super.onStartTemporaryDetach();
        d();
        f();
    }

    @Override // android.view.View
    public boolean onTouchEvent(MotionEvent motionEvent) {
        if (this.f10292d.l(motionEvent)) {
            return true;
        }
        return super.onTouchEvent(motionEvent);
    }

    @Override // android.view.View
    protected void onVisibilityChanged(View view, int i3) {
        super.onVisibilityChanged(view, i3);
        d();
    }

    public void setAspectRatio(float f3) {
        if (f3 == this.f10291c) {
            return;
        }
        this.f10291c = f3;
        requestLayout();
    }

    public void setController(InterfaceC0705a interfaceC0705a) {
        this.f10292d.o(interfaceC0705a);
        super.setImageDrawable(this.f10292d.g());
    }

    public void setExtraData(Object obj) {
        this.f10295g = obj;
    }

    public void setHierarchy(InterfaceC0706b interfaceC0706b) {
        this.f10292d.p(interfaceC0706b);
        super.setImageDrawable(this.f10292d.g());
    }

    @Override // android.widget.ImageView
    @Deprecated
    public void setImageBitmap(Bitmap bitmap) {
        c(getContext());
        this.f10292d.n();
        super.setImageBitmap(bitmap);
    }

    @Override // android.widget.ImageView
    @Deprecated
    public void setImageDrawable(Drawable drawable) {
        c(getContext());
        this.f10292d.n();
        super.setImageDrawable(drawable);
    }

    @Override // android.widget.ImageView
    @Deprecated
    public void setImageResource(int i3) {
        c(getContext());
        this.f10292d.n();
        super.setImageResource(i3);
    }

    @Override // android.widget.ImageView
    @Deprecated
    public void setImageURI(Uri uri) {
        c(getContext());
        this.f10292d.n();
        super.setImageURI(uri);
    }

    public void setLegacyVisibilityHandlingEnabled(boolean z3) {
        this.f10294f = z3;
    }

    @Override // android.view.View
    public String toString() {
        i.a aVarB = i.b(this);
        C0713b c0713b = this.f10292d;
        return aVarB.b("holder", c0713b != null ? c0713b.toString() : "<no holder set>").toString();
    }
}
