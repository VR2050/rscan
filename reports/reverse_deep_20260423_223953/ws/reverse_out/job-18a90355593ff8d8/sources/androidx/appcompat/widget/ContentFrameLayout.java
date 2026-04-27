package androidx.appcompat.widget;

import android.content.Context;
import android.graphics.Rect;
import android.util.AttributeSet;
import android.util.TypedValue;
import android.widget.FrameLayout;

/* JADX INFO: loaded from: classes.dex */
public class ContentFrameLayout extends FrameLayout {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private TypedValue f3728b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private TypedValue f3729c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private TypedValue f3730d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private TypedValue f3731e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private TypedValue f3732f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private TypedValue f3733g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private final Rect f3734h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private a f3735i;

    public interface a {
        void a();

        void onDetachedFromWindow();
    }

    public ContentFrameLayout(Context context) {
        this(context, null);
    }

    public void a(int i3, int i4, int i5, int i6) {
        this.f3734h.set(i3, i4, i5, i6);
        if (isLaidOut()) {
            requestLayout();
        }
    }

    public TypedValue getFixedHeightMajor() {
        if (this.f3732f == null) {
            this.f3732f = new TypedValue();
        }
        return this.f3732f;
    }

    public TypedValue getFixedHeightMinor() {
        if (this.f3733g == null) {
            this.f3733g = new TypedValue();
        }
        return this.f3733g;
    }

    public TypedValue getFixedWidthMajor() {
        if (this.f3730d == null) {
            this.f3730d = new TypedValue();
        }
        return this.f3730d;
    }

    public TypedValue getFixedWidthMinor() {
        if (this.f3731e == null) {
            this.f3731e = new TypedValue();
        }
        return this.f3731e;
    }

    public TypedValue getMinWidthMajor() {
        if (this.f3728b == null) {
            this.f3728b = new TypedValue();
        }
        return this.f3728b;
    }

    public TypedValue getMinWidthMinor() {
        if (this.f3729c == null) {
            this.f3729c = new TypedValue();
        }
        return this.f3729c;
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onAttachedToWindow() {
        super.onAttachedToWindow();
        a aVar = this.f3735i;
        if (aVar != null) {
            aVar.a();
        }
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        a aVar = this.f3735i;
        if (aVar != null) {
            aVar.onDetachedFromWindow();
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:21:0x004a  */
    /* JADX WARN: Removed duplicated region for block: B:22:0x0060  */
    /* JADX WARN: Removed duplicated region for block: B:37:0x0086  */
    /* JADX WARN: Removed duplicated region for block: B:54:0x00cc  */
    /* JADX WARN: Removed duplicated region for block: B:56:0x00d6  */
    /* JADX WARN: Removed duplicated region for block: B:57:0x00db  */
    @Override // android.widget.FrameLayout, android.view.View
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    protected void onMeasure(int r14, int r15) {
        /*
            Method dump skipped, instruction units count: 226
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.appcompat.widget.ContentFrameLayout.onMeasure(int, int):void");
    }

    public void setAttachListener(a aVar) {
        this.f3735i = aVar;
    }

    public ContentFrameLayout(Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 0);
    }

    public ContentFrameLayout(Context context, AttributeSet attributeSet, int i3) {
        super(context, attributeSet, i3);
        this.f3734h = new Rect();
    }
}
