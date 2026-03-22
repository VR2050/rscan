package com.google.android.exoplayer2.p395ui;

import android.annotation.TargetApi;
import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Point;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewParent;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityNodeInfo;
import androidx.annotation.ColorInt;
import androidx.annotation.Nullable;
import com.google.android.exoplayer2.p395ui.DefaultTimeBar;
import java.util.Collections;
import java.util.Formatter;
import java.util.Iterator;
import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArraySet;
import p005b.p199l.p200a.p201a.p246n1.InterfaceC2268f;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* loaded from: classes.dex */
public class DefaultTimeBar extends View implements InterfaceC2268f {

    /* renamed from: A */
    public final int[] f9578A;

    /* renamed from: B */
    public final Point f9579B;

    /* renamed from: C */
    public final float f9580C;

    /* renamed from: D */
    public int f9581D;

    /* renamed from: E */
    public long f9582E;

    /* renamed from: F */
    public int f9583F;

    /* renamed from: G */
    public Rect f9584G;

    /* renamed from: H */
    public boolean f9585H;

    /* renamed from: I */
    public long f9586I;

    /* renamed from: J */
    public long f9587J;

    /* renamed from: K */
    public long f9588K;

    /* renamed from: L */
    public long f9589L;

    /* renamed from: M */
    public int f9590M;

    /* renamed from: N */
    @Nullable
    public long[] f9591N;

    /* renamed from: O */
    @Nullable
    public boolean[] f9592O;

    /* renamed from: c */
    public final Rect f9593c;

    /* renamed from: e */
    public final Rect f9594e;

    /* renamed from: f */
    public final Rect f9595f;

    /* renamed from: g */
    public final Rect f9596g;

    /* renamed from: h */
    public final Paint f9597h;

    /* renamed from: i */
    public final Paint f9598i;

    /* renamed from: j */
    public final Paint f9599j;

    /* renamed from: k */
    public final Paint f9600k;

    /* renamed from: l */
    public final Paint f9601l;

    /* renamed from: m */
    public final Paint f9602m;

    /* renamed from: n */
    @Nullable
    public final Drawable f9603n;

    /* renamed from: o */
    public final int f9604o;

    /* renamed from: p */
    public final int f9605p;

    /* renamed from: q */
    public final int f9606q;

    /* renamed from: r */
    public final int f9607r;

    /* renamed from: s */
    public final int f9608s;

    /* renamed from: t */
    public final int f9609t;

    /* renamed from: u */
    public final int f9610u;

    /* renamed from: v */
    public final int f9611v;

    /* renamed from: w */
    public final StringBuilder f9612w;

    /* renamed from: x */
    public final Formatter f9613x;

    /* renamed from: y */
    public final Runnable f9614y;

    /* renamed from: z */
    public final CopyOnWriteArraySet<InterfaceC2268f.a> f9615z;

    public DefaultTimeBar(Context context) {
        this(context, null);
    }

    /* renamed from: b */
    public static int m4080b(float f2, int i2) {
        return (int) ((i2 * f2) + 0.5f);
    }

    private long getPositionIncrement() {
        long j2 = this.f9582E;
        if (j2 != -9223372036854775807L) {
            return j2;
        }
        long j3 = this.f9587J;
        if (j3 == -9223372036854775807L) {
            return 0L;
        }
        return j3 / this.f9581D;
    }

    private String getProgressText() {
        return C2344d0.m2340r(this.f9612w, this.f9613x, this.f9588K);
    }

    private long getScrubberPosition() {
        if (this.f9594e.width() <= 0 || this.f9587J == -9223372036854775807L) {
            return 0L;
        }
        return (this.f9596g.width() * this.f9587J) / this.f9594e.width();
    }

    @Override // p005b.p199l.p200a.p201a.p246n1.InterfaceC2268f
    /* renamed from: a */
    public void mo2168a(@Nullable long[] jArr, @Nullable boolean[] zArr, int i2) {
        C4195m.m4765F(i2 == 0 || !(jArr == null || zArr == null));
        this.f9590M = i2;
        this.f9591N = jArr;
        this.f9592O = zArr;
        m4085g();
    }

    @Override // p005b.p199l.p200a.p201a.p246n1.InterfaceC2268f
    public void addListener(InterfaceC2268f.a aVar) {
        this.f9615z.add(aVar);
    }

    /* renamed from: c */
    public final void m4081c(float f2) {
        Rect rect = this.f9596g;
        Rect rect2 = this.f9594e;
        rect.right = C2344d0.m2329g((int) f2, rect2.left, rect2.right);
    }

    /* renamed from: d */
    public final boolean m4082d(long j2) {
        long j3 = this.f9587J;
        if (j3 <= 0) {
            return false;
        }
        long j4 = this.f9585H ? this.f9586I : this.f9588K;
        long m2330h = C2344d0.m2330h(j4 + j2, 0L, j3);
        if (m2330h == j4) {
            return false;
        }
        if (this.f9585H) {
            m4087i(m2330h);
        } else {
            m4083e(m2330h);
        }
        m4085g();
        return true;
    }

    @Override // android.view.View
    public void drawableStateChanged() {
        super.drawableStateChanged();
        m4086h();
    }

    /* renamed from: e */
    public final void m4083e(long j2) {
        this.f9586I = j2;
        this.f9585H = true;
        setPressed(true);
        ViewParent parent = getParent();
        if (parent != null) {
            parent.requestDisallowInterceptTouchEvent(true);
        }
        Iterator<InterfaceC2268f.a> it = this.f9615z.iterator();
        while (it.hasNext()) {
            it.next().mo2171c(this, j2);
        }
    }

    /* renamed from: f */
    public final void m4084f(boolean z) {
        removeCallbacks(this.f9614y);
        this.f9585H = false;
        setPressed(false);
        ViewParent parent = getParent();
        if (parent != null) {
            parent.requestDisallowInterceptTouchEvent(false);
        }
        invalidate();
        Iterator<InterfaceC2268f.a> it = this.f9615z.iterator();
        while (it.hasNext()) {
            it.next().mo2170b(this, this.f9586I, z);
        }
    }

    /* renamed from: g */
    public final void m4085g() {
        this.f9595f.set(this.f9594e);
        this.f9596g.set(this.f9594e);
        long j2 = this.f9585H ? this.f9586I : this.f9588K;
        if (this.f9587J > 0) {
            int width = (int) ((this.f9594e.width() * this.f9589L) / this.f9587J);
            Rect rect = this.f9595f;
            Rect rect2 = this.f9594e;
            rect.right = Math.min(rect2.left + width, rect2.right);
            int width2 = (int) ((this.f9594e.width() * j2) / this.f9587J);
            Rect rect3 = this.f9596g;
            Rect rect4 = this.f9594e;
            rect3.right = Math.min(rect4.left + width2, rect4.right);
        } else {
            Rect rect5 = this.f9595f;
            int i2 = this.f9594e.left;
            rect5.right = i2;
            this.f9596g.right = i2;
        }
        invalidate(this.f9593c);
    }

    @Override // p005b.p199l.p200a.p201a.p246n1.InterfaceC2268f
    public long getPreferredUpdateDelay() {
        int width = (int) (this.f9594e.width() / this.f9580C);
        if (width != 0) {
            long j2 = this.f9587J;
            if (j2 != 0 && j2 != -9223372036854775807L) {
                return j2 / width;
            }
        }
        return Long.MAX_VALUE;
    }

    /* renamed from: h */
    public final void m4086h() {
        Drawable drawable = this.f9603n;
        if (drawable != null && drawable.isStateful() && this.f9603n.setState(getDrawableState())) {
            invalidate();
        }
    }

    /* renamed from: i */
    public final void m4087i(long j2) {
        if (this.f9586I == j2) {
            return;
        }
        this.f9586I = j2;
        Iterator<InterfaceC2268f.a> it = this.f9615z.iterator();
        while (it.hasNext()) {
            it.next().mo2169a(this, j2);
        }
    }

    @Override // android.view.View
    public void jumpDrawablesToCurrentState() {
        super.jumpDrawablesToCurrentState();
        Drawable drawable = this.f9603n;
        if (drawable != null) {
            drawable.jumpToCurrentState();
        }
    }

    @Override // android.view.View
    public void onDraw(Canvas canvas) {
        canvas.save();
        int height = this.f9594e.height();
        int centerY = this.f9594e.centerY() - (height / 2);
        int i2 = height + centerY;
        if (this.f9587J <= 0) {
            Rect rect = this.f9594e;
            canvas.drawRect(rect.left, centerY, rect.right, i2, this.f9599j);
        } else {
            Rect rect2 = this.f9595f;
            int i3 = rect2.left;
            int i4 = rect2.right;
            int max = Math.max(Math.max(this.f9594e.left, i4), this.f9596g.right);
            int i5 = this.f9594e.right;
            if (max < i5) {
                canvas.drawRect(max, centerY, i5, i2, this.f9599j);
            }
            int max2 = Math.max(i3, this.f9596g.right);
            if (i4 > max2) {
                canvas.drawRect(max2, centerY, i4, i2, this.f9598i);
            }
            if (this.f9596g.width() > 0) {
                Rect rect3 = this.f9596g;
                canvas.drawRect(rect3.left, centerY, rect3.right, i2, this.f9597h);
            }
            if (this.f9590M != 0) {
                long[] jArr = this.f9591N;
                Objects.requireNonNull(jArr);
                boolean[] zArr = this.f9592O;
                Objects.requireNonNull(zArr);
                int i6 = this.f9606q / 2;
                for (int i7 = 0; i7 < this.f9590M; i7++) {
                    int width = ((int) ((this.f9594e.width() * C2344d0.m2330h(jArr[i7], 0L, this.f9587J)) / this.f9587J)) - i6;
                    Rect rect4 = this.f9594e;
                    canvas.drawRect(Math.min(rect4.width() - this.f9606q, Math.max(0, width)) + rect4.left, centerY, r1 + this.f9606q, i2, zArr[i7] ? this.f9601l : this.f9600k);
                }
            }
        }
        if (this.f9587J > 0) {
            Rect rect5 = this.f9596g;
            int m2329g = C2344d0.m2329g(rect5.right, rect5.left, this.f9594e.right);
            int centerY2 = this.f9596g.centerY();
            Drawable drawable = this.f9603n;
            if (drawable == null) {
                canvas.drawCircle(m2329g, centerY2, ((this.f9585H || isFocused()) ? this.f9609t : isEnabled() ? this.f9607r : this.f9608s) / 2, this.f9602m);
            } else {
                int intrinsicWidth = drawable.getIntrinsicWidth() / 2;
                int intrinsicHeight = this.f9603n.getIntrinsicHeight() / 2;
                this.f9603n.setBounds(m2329g - intrinsicWidth, centerY2 - intrinsicHeight, m2329g + intrinsicWidth, centerY2 + intrinsicHeight);
                this.f9603n.draw(canvas);
            }
        }
        canvas.restore();
    }

    @Override // android.view.View
    public void onFocusChanged(boolean z, int i2, @Nullable Rect rect) {
        super.onFocusChanged(z, i2, rect);
        if (!this.f9585H || z) {
            return;
        }
        m4084f(false);
    }

    @Override // android.view.View
    public void onInitializeAccessibilityEvent(AccessibilityEvent accessibilityEvent) {
        super.onInitializeAccessibilityEvent(accessibilityEvent);
        if (accessibilityEvent.getEventType() == 4) {
            accessibilityEvent.getText().add(getProgressText());
        }
        accessibilityEvent.setClassName("android.widget.SeekBar");
    }

    @Override // android.view.View
    @TargetApi(21)
    public void onInitializeAccessibilityNodeInfo(AccessibilityNodeInfo accessibilityNodeInfo) {
        super.onInitializeAccessibilityNodeInfo(accessibilityNodeInfo);
        accessibilityNodeInfo.setClassName("android.widget.SeekBar");
        accessibilityNodeInfo.setContentDescription(getProgressText());
        if (this.f9587J <= 0) {
            return;
        }
        if (C2344d0.f6035a >= 21) {
            accessibilityNodeInfo.addAction(AccessibilityNodeInfo.AccessibilityAction.ACTION_SCROLL_FORWARD);
            accessibilityNodeInfo.addAction(AccessibilityNodeInfo.AccessibilityAction.ACTION_SCROLL_BACKWARD);
        } else {
            accessibilityNodeInfo.addAction(4096);
            accessibilityNodeInfo.addAction(8192);
        }
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Removed duplicated region for block: B:9:0x001a  */
    @Override // android.view.View, android.view.KeyEvent.Callback
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean onKeyDown(int r5, android.view.KeyEvent r6) {
        /*
            r4 = this;
            boolean r0 = r4.isEnabled()
            if (r0 == 0) goto L30
            long r0 = r4.getPositionIncrement()
            r2 = 66
            r3 = 1
            if (r5 == r2) goto L27
            switch(r5) {
                case 21: goto L13;
                case 22: goto L14;
                case 23: goto L27;
                default: goto L12;
            }
        L12:
            goto L30
        L13:
            long r0 = -r0
        L14:
            boolean r0 = r4.m4082d(r0)
            if (r0 == 0) goto L30
            java.lang.Runnable r5 = r4.f9614y
            r4.removeCallbacks(r5)
            java.lang.Runnable r5 = r4.f9614y
            r0 = 1000(0x3e8, double:4.94E-321)
            r4.postDelayed(r5, r0)
            return r3
        L27:
            boolean r0 = r4.f9585H
            if (r0 == 0) goto L30
            r5 = 0
            r4.m4084f(r5)
            return r3
        L30:
            boolean r5 = super.onKeyDown(r5, r6)
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.exoplayer2.p395ui.DefaultTimeBar.onKeyDown(int, android.view.KeyEvent):boolean");
    }

    @Override // android.view.View
    public void onLayout(boolean z, int i2, int i3, int i4, int i5) {
        Rect rect;
        int i6 = i4 - i2;
        int i7 = i5 - i3;
        int i8 = (i7 - this.f9605p) / 2;
        int paddingLeft = getPaddingLeft();
        int paddingRight = i6 - getPaddingRight();
        int i9 = this.f9605p;
        int i10 = ((i9 - this.f9604o) / 2) + i8;
        this.f9593c.set(paddingLeft, i8, paddingRight, i9 + i8);
        Rect rect2 = this.f9594e;
        Rect rect3 = this.f9593c;
        int i11 = rect3.left;
        int i12 = this.f9610u;
        rect2.set(i11 + i12, i10, rect3.right - i12, this.f9604o + i10);
        if (C2344d0.f6035a >= 29 && ((rect = this.f9584G) == null || rect.width() != i6 || this.f9584G.height() != i7)) {
            Rect rect4 = new Rect(0, 0, i6, i7);
            this.f9584G = rect4;
            setSystemGestureExclusionRects(Collections.singletonList(rect4));
        }
        m4085g();
    }

    @Override // android.view.View
    public void onMeasure(int i2, int i3) {
        int mode = View.MeasureSpec.getMode(i3);
        int size = View.MeasureSpec.getSize(i3);
        if (mode == 0) {
            size = this.f9605p;
        } else if (mode != 1073741824) {
            size = Math.min(this.f9605p, size);
        }
        setMeasuredDimension(View.MeasureSpec.getSize(i2), size);
        m4086h();
    }

    @Override // android.view.View
    public void onRtlPropertiesChanged(int i2) {
        Drawable drawable = this.f9603n;
        if (drawable != null) {
            if (C2344d0.f6035a >= 23 && drawable.setLayoutDirection(i2)) {
                invalidate();
            }
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:11:0x0042, code lost:
    
        if (r3 != 3) goto L34;
     */
    @Override // android.view.View
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean onTouchEvent(android.view.MotionEvent r8) {
        /*
            r7 = this;
            boolean r0 = r7.isEnabled()
            r1 = 0
            if (r0 == 0) goto L97
            long r2 = r7.f9587J
            r4 = 0
            int r0 = (r2 > r4 ? 1 : (r2 == r4 ? 0 : -1))
            if (r0 > 0) goto L11
            goto L97
        L11:
            int[] r0 = r7.f9578A
            r7.getLocationOnScreen(r0)
            android.graphics.Point r0 = r7.f9579B
            float r2 = r8.getRawX()
            int r2 = (int) r2
            int[] r3 = r7.f9578A
            r3 = r3[r1]
            int r2 = r2 - r3
            float r3 = r8.getRawY()
            int r3 = (int) r3
            int[] r4 = r7.f9578A
            r5 = 1
            r4 = r4[r5]
            int r3 = r3 - r4
            r0.set(r2, r3)
            android.graphics.Point r0 = r7.f9579B
            int r2 = r0.x
            int r0 = r0.y
            int r3 = r8.getAction()
            if (r3 == 0) goto L7a
            r4 = 3
            if (r3 == r5) goto L6b
            r6 = 2
            if (r3 == r6) goto L45
            if (r3 == r4) goto L6b
            goto L97
        L45:
            boolean r8 = r7.f9585H
            if (r8 == 0) goto L97
            int r8 = r7.f9611v
            if (r0 >= r8) goto L57
            int r8 = r7.f9583F
            int r2 = r2 - r8
            int r2 = r2 / r4
            int r2 = r2 + r8
            float r8 = (float) r2
            r7.m4081c(r8)
            goto L5d
        L57:
            r7.f9583F = r2
            float r8 = (float) r2
            r7.m4081c(r8)
        L5d:
            long r0 = r7.getScrubberPosition()
            r7.m4087i(r0)
            r7.m4085g()
            r7.invalidate()
            return r5
        L6b:
            boolean r0 = r7.f9585H
            if (r0 == 0) goto L97
            int r8 = r8.getAction()
            if (r8 != r4) goto L76
            r1 = 1
        L76:
            r7.m4084f(r1)
            return r5
        L7a:
            float r8 = (float) r2
            float r0 = (float) r0
            android.graphics.Rect r2 = r7.f9593c
            int r3 = (int) r8
            int r0 = (int) r0
            boolean r0 = r2.contains(r3, r0)
            if (r0 == 0) goto L97
            r7.m4081c(r8)
            long r0 = r7.getScrubberPosition()
            r7.m4083e(r0)
            r7.m4085g()
            r7.invalidate()
            return r5
        L97:
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.exoplayer2.p395ui.DefaultTimeBar.onTouchEvent(android.view.MotionEvent):boolean");
    }

    @Override // android.view.View
    public boolean performAccessibilityAction(int i2, @Nullable Bundle bundle) {
        if (super.performAccessibilityAction(i2, bundle)) {
            return true;
        }
        if (this.f9587J <= 0) {
            return false;
        }
        if (i2 == 8192) {
            if (m4082d(-getPositionIncrement())) {
                m4084f(false);
            }
        } else {
            if (i2 != 4096) {
                return false;
            }
            if (m4082d(getPositionIncrement())) {
                m4084f(false);
            }
        }
        sendAccessibilityEvent(4);
        return true;
    }

    @Override // p005b.p199l.p200a.p201a.p246n1.InterfaceC2268f
    public void removeListener(InterfaceC2268f.a aVar) {
        this.f9615z.remove(aVar);
    }

    public void setAdMarkerColor(@ColorInt int i2) {
        this.f9600k.setColor(i2);
        invalidate(this.f9593c);
    }

    public void setBufferedColor(@ColorInt int i2) {
        this.f9598i.setColor(i2);
        invalidate(this.f9593c);
    }

    @Override // p005b.p199l.p200a.p201a.p246n1.InterfaceC2268f
    public void setBufferedPosition(long j2) {
        this.f9589L = j2;
        m4085g();
    }

    @Override // p005b.p199l.p200a.p201a.p246n1.InterfaceC2268f
    public void setDuration(long j2) {
        this.f9587J = j2;
        if (this.f9585H && j2 == -9223372036854775807L) {
            m4084f(true);
        }
        m4085g();
    }

    @Override // android.view.View, p005b.p199l.p200a.p201a.p246n1.InterfaceC2268f
    public void setEnabled(boolean z) {
        super.setEnabled(z);
        if (!this.f9585H || z) {
            return;
        }
        m4084f(true);
    }

    public void setKeyCountIncrement(int i2) {
        C4195m.m4765F(i2 > 0);
        this.f9581D = i2;
        this.f9582E = -9223372036854775807L;
    }

    public void setKeyTimeIncrement(long j2) {
        C4195m.m4765F(j2 > 0);
        this.f9581D = -1;
        this.f9582E = j2;
    }

    public void setPlayedAdMarkerColor(@ColorInt int i2) {
        this.f9601l.setColor(i2);
        invalidate(this.f9593c);
    }

    public void setPlayedColor(@ColorInt int i2) {
        this.f9597h.setColor(i2);
        invalidate(this.f9593c);
    }

    @Override // p005b.p199l.p200a.p201a.p246n1.InterfaceC2268f
    public void setPosition(long j2) {
        this.f9588K = j2;
        setContentDescription(getProgressText());
        m4085g();
    }

    public void setScrubberColor(@ColorInt int i2) {
        this.f9602m.setColor(i2);
        invalidate(this.f9593c);
    }

    public void setUnplayedColor(@ColorInt int i2) {
        this.f9599j.setColor(i2);
        invalidate(this.f9593c);
    }

    public DefaultTimeBar(Context context, @Nullable AttributeSet attributeSet) {
        this(context, attributeSet, 0);
    }

    public DefaultTimeBar(Context context, @Nullable AttributeSet attributeSet, int i2) {
        this(context, attributeSet, i2, attributeSet);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r2v10, types: [boolean, int] */
    /* JADX WARN: Type inference failed for: r2v11 */
    /* JADX WARN: Type inference failed for: r2v9 */
    public DefaultTimeBar(Context context, @Nullable AttributeSet attributeSet, int i2, @Nullable AttributeSet attributeSet2) {
        super(context, attributeSet, i2);
        ?? r2;
        Paint paint;
        this.f9593c = new Rect();
        this.f9594e = new Rect();
        this.f9595f = new Rect();
        this.f9596g = new Rect();
        Paint paint2 = new Paint();
        this.f9597h = paint2;
        Paint paint3 = new Paint();
        this.f9598i = paint3;
        Paint paint4 = new Paint();
        this.f9599j = paint4;
        Paint paint5 = new Paint();
        this.f9600k = paint5;
        Paint paint6 = new Paint();
        this.f9601l = paint6;
        Paint paint7 = new Paint();
        this.f9602m = paint7;
        paint7.setAntiAlias(true);
        this.f9615z = new CopyOnWriteArraySet<>();
        this.f9578A = new int[2];
        this.f9579B = new Point();
        float f2 = context.getResources().getDisplayMetrics().density;
        this.f9580C = f2;
        this.f9611v = m4080b(f2, -50);
        int m4080b = m4080b(f2, 4);
        int m4080b2 = m4080b(f2, 26);
        int m4080b3 = m4080b(f2, 4);
        int m4080b4 = m4080b(f2, 12);
        int m4080b5 = m4080b(f2, 0);
        int m4080b6 = m4080b(f2, 16);
        if (attributeSet2 != null) {
            TypedArray obtainStyledAttributes = context.getTheme().obtainStyledAttributes(attributeSet2, R$styleable.DefaultTimeBar, 0, 0);
            try {
                Drawable drawable = obtainStyledAttributes.getDrawable(R$styleable.DefaultTimeBar_scrubber_drawable);
                this.f9603n = drawable;
                if (drawable != null) {
                    int i3 = C2344d0.f6035a;
                    if (i3 >= 23) {
                        paint = paint5;
                        int layoutDirection = getLayoutDirection();
                        if (i3 < 23 || !drawable.setLayoutDirection(layoutDirection)) {
                        }
                    } else {
                        paint = paint5;
                    }
                    m4080b2 = Math.max(drawable.getMinimumHeight(), m4080b2);
                } else {
                    paint = paint5;
                }
                this.f9604o = obtainStyledAttributes.getDimensionPixelSize(R$styleable.DefaultTimeBar_bar_height, m4080b);
                this.f9605p = obtainStyledAttributes.getDimensionPixelSize(R$styleable.DefaultTimeBar_touch_target_height, m4080b2);
                this.f9606q = obtainStyledAttributes.getDimensionPixelSize(R$styleable.DefaultTimeBar_ad_marker_width, m4080b3);
                this.f9607r = obtainStyledAttributes.getDimensionPixelSize(R$styleable.DefaultTimeBar_scrubber_enabled_size, m4080b4);
                this.f9608s = obtainStyledAttributes.getDimensionPixelSize(R$styleable.DefaultTimeBar_scrubber_disabled_size, m4080b5);
                this.f9609t = obtainStyledAttributes.getDimensionPixelSize(R$styleable.DefaultTimeBar_scrubber_dragged_size, m4080b6);
                int i4 = obtainStyledAttributes.getInt(R$styleable.DefaultTimeBar_played_color, -1);
                int i5 = obtainStyledAttributes.getInt(R$styleable.DefaultTimeBar_scrubber_color, -1);
                int i6 = obtainStyledAttributes.getInt(R$styleable.DefaultTimeBar_buffered_color, -855638017);
                int i7 = obtainStyledAttributes.getInt(R$styleable.DefaultTimeBar_unplayed_color, 872415231);
                int i8 = obtainStyledAttributes.getInt(R$styleable.DefaultTimeBar_ad_marker_color, -1291845888);
                int i9 = obtainStyledAttributes.getInt(R$styleable.DefaultTimeBar_played_ad_marker_color, 872414976);
                paint2.setColor(i4);
                paint7.setColor(i5);
                paint3.setColor(i6);
                paint4.setColor(i7);
                paint.setColor(i8);
                paint6.setColor(i9);
            } finally {
                obtainStyledAttributes.recycle();
            }
        } else {
            this.f9604o = m4080b;
            this.f9605p = m4080b2;
            this.f9606q = m4080b3;
            this.f9607r = m4080b4;
            this.f9608s = m4080b5;
            this.f9609t = m4080b6;
            paint2.setColor(-1);
            paint7.setColor(-1);
            paint3.setColor(-855638017);
            paint4.setColor(872415231);
            paint5.setColor(-1291845888);
            paint6.setColor(872414976);
            this.f9603n = null;
        }
        StringBuilder sb = new StringBuilder();
        this.f9612w = sb;
        this.f9613x = new Formatter(sb, Locale.getDefault());
        this.f9614y = new Runnable() { // from class: b.l.a.a.n1.b
            @Override // java.lang.Runnable
            public final void run() {
                DefaultTimeBar.this.m4084f(false);
            }
        };
        Drawable drawable2 = this.f9603n;
        if (drawable2 != null) {
            r2 = 1;
            this.f9610u = (drawable2.getMinimumWidth() + 1) / 2;
        } else {
            r2 = 1;
            this.f9610u = (Math.max(this.f9608s, Math.max(this.f9607r, this.f9609t)) + 1) / 2;
        }
        this.f9587J = -9223372036854775807L;
        this.f9582E = -9223372036854775807L;
        this.f9581D = 20;
        setFocusable((boolean) r2);
        if (getImportantForAccessibility() == 0) {
            setImportantForAccessibility(r2);
        }
    }
}
