package p005b.p190k.p195b.p196a;

import android.content.Context;
import android.graphics.Matrix;
import android.graphics.RectF;
import android.graphics.drawable.Drawable;
import android.view.GestureDetector;
import android.view.MotionEvent;
import android.view.View;
import android.view.animation.AccelerateDecelerateInterpolator;
import android.view.animation.Interpolator;
import android.widget.ImageView;
import android.widget.OverScroller;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: b.k.b.a.j */
/* loaded from: classes.dex */
public class ViewOnTouchListenerC1898j implements View.OnTouchListener, View.OnLayoutChangeListener {

    /* renamed from: A */
    public InterfaceC1896h f2953A;

    /* renamed from: B */
    public f f2954B;

    /* renamed from: k */
    public ImageView f2967k;

    /* renamed from: l */
    public GestureDetector f2968l;

    /* renamed from: m */
    public C1889a f2969m;

    /* renamed from: s */
    public InterfaceC1891c f2975s;

    /* renamed from: t */
    public InterfaceC1893e f2976t;

    /* renamed from: u */
    public InterfaceC1892d f2977u;

    /* renamed from: v */
    public InterfaceC1897i f2978v;

    /* renamed from: w */
    public View.OnClickListener f2979w;

    /* renamed from: x */
    public View.OnLongClickListener f2980x;

    /* renamed from: y */
    public InterfaceC1894f f2981y;

    /* renamed from: z */
    public InterfaceC1895g f2982z;

    /* renamed from: c */
    public Interpolator f2960c = new AccelerateDecelerateInterpolator();

    /* renamed from: e */
    public int f2961e = 200;

    /* renamed from: f */
    public float f2962f = 1.0f;

    /* renamed from: g */
    public float f2963g = 1.75f;

    /* renamed from: h */
    public float f2964h = 3.0f;

    /* renamed from: i */
    public boolean f2965i = true;

    /* renamed from: j */
    public boolean f2966j = false;

    /* renamed from: n */
    public final Matrix f2970n = new Matrix();

    /* renamed from: o */
    public final Matrix f2971o = new Matrix();

    /* renamed from: p */
    public final Matrix f2972p = new Matrix();

    /* renamed from: q */
    public final RectF f2973q = new RectF();

    /* renamed from: r */
    public final float[] f2974r = new float[9];

    /* renamed from: C */
    public int f2955C = 2;

    /* renamed from: D */
    public int f2956D = 2;

    /* renamed from: E */
    public boolean f2957E = true;

    /* renamed from: F */
    public ImageView.ScaleType f2958F = ImageView.ScaleType.FIT_CENTER;

    /* renamed from: G */
    public InterfaceC1890b f2959G = new a();

    /* renamed from: b.k.b.a.j$a */
    public class a implements InterfaceC1890b {
        public a() {
        }

        /* renamed from: a */
        public void m1250a(float f2, float f3, float f4) {
            float m1245h = ViewOnTouchListenerC1898j.this.m1245h();
            ViewOnTouchListenerC1898j viewOnTouchListenerC1898j = ViewOnTouchListenerC1898j.this;
            if (m1245h < viewOnTouchListenerC1898j.f2964h || f2 < 1.0f) {
                InterfaceC1894f interfaceC1894f = viewOnTouchListenerC1898j.f2981y;
                if (interfaceC1894f != null) {
                    interfaceC1894f.onScaleChange(f2, f3, f4);
                }
                ViewOnTouchListenerC1898j.this.f2972p.postScale(f2, f2, f3, f4);
                ViewOnTouchListenerC1898j.this.m1238a();
            }
        }
    }

    /* renamed from: b.k.b.a.j$b */
    public class b extends GestureDetector.SimpleOnGestureListener {
        public b() {
        }

        @Override // android.view.GestureDetector.SimpleOnGestureListener, android.view.GestureDetector.OnGestureListener
        public boolean onFling(MotionEvent motionEvent, MotionEvent motionEvent2, float f2, float f3) {
            ViewOnTouchListenerC1898j viewOnTouchListenerC1898j = ViewOnTouchListenerC1898j.this;
            if (viewOnTouchListenerC1898j.f2982z == null || viewOnTouchListenerC1898j.m1245h() > 1.0f || motionEvent.getPointerCount() > 1 || motionEvent2.getPointerCount() > 1) {
                return false;
            }
            return ViewOnTouchListenerC1898j.this.f2982z.onFling(motionEvent, motionEvent2, f2, f3);
        }

        @Override // android.view.GestureDetector.SimpleOnGestureListener, android.view.GestureDetector.OnGestureListener
        public void onLongPress(MotionEvent motionEvent) {
            ViewOnTouchListenerC1898j viewOnTouchListenerC1898j = ViewOnTouchListenerC1898j.this;
            View.OnLongClickListener onLongClickListener = viewOnTouchListenerC1898j.f2980x;
            if (onLongClickListener != null) {
                onLongClickListener.onLongClick(viewOnTouchListenerC1898j.f2967k);
            }
        }
    }

    /* renamed from: b.k.b.a.j$c */
    public class c implements GestureDetector.OnDoubleTapListener {
        public c() {
        }

        @Override // android.view.GestureDetector.OnDoubleTapListener
        public boolean onDoubleTap(MotionEvent motionEvent) {
            try {
                float m1245h = ViewOnTouchListenerC1898j.this.m1245h();
                float x = motionEvent.getX();
                float y = motionEvent.getY();
                ViewOnTouchListenerC1898j viewOnTouchListenerC1898j = ViewOnTouchListenerC1898j.this;
                float f2 = viewOnTouchListenerC1898j.f2963g;
                if (m1245h < f2) {
                    viewOnTouchListenerC1898j.m1247j(f2, x, y, true);
                } else {
                    if (m1245h >= f2) {
                        float f3 = viewOnTouchListenerC1898j.f2964h;
                        if (m1245h < f3) {
                            viewOnTouchListenerC1898j.m1247j(f3, x, y, true);
                        }
                    }
                    viewOnTouchListenerC1898j.m1247j(viewOnTouchListenerC1898j.f2962f, x, y, true);
                }
            } catch (ArrayIndexOutOfBoundsException unused) {
            }
            return true;
        }

        @Override // android.view.GestureDetector.OnDoubleTapListener
        public boolean onDoubleTapEvent(MotionEvent motionEvent) {
            return false;
        }

        @Override // android.view.GestureDetector.OnDoubleTapListener
        public boolean onSingleTapConfirmed(MotionEvent motionEvent) {
            ViewOnTouchListenerC1898j viewOnTouchListenerC1898j = ViewOnTouchListenerC1898j.this;
            View.OnClickListener onClickListener = viewOnTouchListenerC1898j.f2979w;
            if (onClickListener != null) {
                onClickListener.onClick(viewOnTouchListenerC1898j.f2967k);
            }
            RectF m1240c = ViewOnTouchListenerC1898j.this.m1240c();
            float x = motionEvent.getX();
            float y = motionEvent.getY();
            ViewOnTouchListenerC1898j viewOnTouchListenerC1898j2 = ViewOnTouchListenerC1898j.this;
            InterfaceC1897i interfaceC1897i = viewOnTouchListenerC1898j2.f2978v;
            if (interfaceC1897i != null) {
                interfaceC1897i.onViewTap(viewOnTouchListenerC1898j2.f2967k, x, y);
            }
            if (m1240c == null) {
                return false;
            }
            if (!m1240c.contains(x, y)) {
                ViewOnTouchListenerC1898j viewOnTouchListenerC1898j3 = ViewOnTouchListenerC1898j.this;
                InterfaceC1892d interfaceC1892d = viewOnTouchListenerC1898j3.f2977u;
                if (interfaceC1892d == null) {
                    return false;
                }
                interfaceC1892d.onOutsidePhotoTap(viewOnTouchListenerC1898j3.f2967k);
                return false;
            }
            float width = (x - m1240c.left) / m1240c.width();
            float height = (y - m1240c.top) / m1240c.height();
            ViewOnTouchListenerC1898j viewOnTouchListenerC1898j4 = ViewOnTouchListenerC1898j.this;
            InterfaceC1893e interfaceC1893e = viewOnTouchListenerC1898j4.f2976t;
            if (interfaceC1893e == null) {
                return true;
            }
            interfaceC1893e.onPhotoTap(viewOnTouchListenerC1898j4.f2967k, width, height);
            return true;
        }
    }

    /* renamed from: b.k.b.a.j$d */
    public static /* synthetic */ class d {

        /* renamed from: a */
        public static final /* synthetic */ int[] f2986a;

        static {
            int[] iArr = new int[ImageView.ScaleType.values().length];
            f2986a = iArr;
            try {
                iArr[ImageView.ScaleType.FIT_CENTER.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                f2986a[ImageView.ScaleType.FIT_START.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                f2986a[ImageView.ScaleType.FIT_END.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            try {
                f2986a[ImageView.ScaleType.FIT_XY.ordinal()] = 4;
            } catch (NoSuchFieldError unused4) {
            }
        }
    }

    /* renamed from: b.k.b.a.j$e */
    public class e implements Runnable {

        /* renamed from: c */
        public final float f2987c;

        /* renamed from: e */
        public final float f2988e;

        /* renamed from: f */
        public final long f2989f = System.currentTimeMillis();

        /* renamed from: g */
        public final float f2990g;

        /* renamed from: h */
        public final float f2991h;

        public e(float f2, float f3, float f4, float f5) {
            this.f2987c = f4;
            this.f2988e = f5;
            this.f2990g = f2;
            this.f2991h = f3;
        }

        @Override // java.lang.Runnable
        public void run() {
            float interpolation = ViewOnTouchListenerC1898j.this.f2960c.getInterpolation(Math.min(1.0f, ((System.currentTimeMillis() - this.f2989f) * 1.0f) / ViewOnTouchListenerC1898j.this.f2961e));
            float f2 = this.f2990g;
            ((a) ViewOnTouchListenerC1898j.this.f2959G).m1250a(C1499a.m627m(this.f2991h, f2, interpolation, f2) / ViewOnTouchListenerC1898j.this.m1245h(), this.f2987c, this.f2988e);
            if (interpolation < 1.0f) {
                ViewOnTouchListenerC1898j.this.f2967k.postOnAnimation(this);
            }
        }
    }

    /* renamed from: b.k.b.a.j$f */
    public class f implements Runnable {

        /* renamed from: c */
        public final OverScroller f2993c;

        /* renamed from: e */
        public int f2994e;

        /* renamed from: f */
        public int f2995f;

        public f(Context context) {
            this.f2993c = new OverScroller(context);
        }

        @Override // java.lang.Runnable
        public void run() {
            if (!this.f2993c.isFinished() && this.f2993c.computeScrollOffset()) {
                int currX = this.f2993c.getCurrX();
                int currY = this.f2993c.getCurrY();
                ViewOnTouchListenerC1898j.this.f2972p.postTranslate(this.f2994e - currX, this.f2995f - currY);
                ViewOnTouchListenerC1898j.this.m1238a();
                this.f2994e = currX;
                this.f2995f = currY;
                ViewOnTouchListenerC1898j.this.f2967k.postOnAnimation(this);
            }
        }
    }

    public ViewOnTouchListenerC1898j(ImageView imageView) {
        this.f2967k = imageView;
        imageView.setOnTouchListener(this);
        imageView.addOnLayoutChangeListener(this);
        if (imageView.isInEditMode()) {
            return;
        }
        this.f2969m = new C1889a(imageView.getContext(), this.f2959G);
        GestureDetector gestureDetector = new GestureDetector(imageView.getContext(), new b());
        this.f2968l = gestureDetector;
        gestureDetector.setOnDoubleTapListener(new c());
    }

    /* renamed from: a */
    public final void m1238a() {
        RectF m1241d;
        if (m1239b()) {
            Matrix m1242e = m1242e();
            this.f2967k.setImageMatrix(m1242e);
            if (this.f2975s == null || (m1241d = m1241d(m1242e)) == null) {
                return;
            }
            this.f2975s.onMatrixChanged(m1241d);
        }
    }

    /* renamed from: b */
    public final boolean m1239b() {
        float f2;
        float f3;
        float f4;
        float f5;
        float f6;
        RectF m1241d = m1241d(m1242e());
        if (m1241d == null) {
            return false;
        }
        float height = m1241d.height();
        float width = m1241d.width();
        float m1243f = m1243f(this.f2967k);
        float f7 = 0.0f;
        if (height <= m1243f) {
            int i2 = d.f2986a[this.f2958F.ordinal()];
            if (i2 != 2) {
                if (i2 != 3) {
                    f5 = (m1243f - height) / 2.0f;
                    f6 = m1241d.top;
                } else {
                    f5 = m1243f - height;
                    f6 = m1241d.top;
                }
                f2 = f5 - f6;
            } else {
                f2 = -m1241d.top;
            }
            this.f2956D = 2;
        } else {
            float f8 = m1241d.top;
            if (f8 > 0.0f) {
                this.f2956D = 0;
                f2 = -f8;
            } else {
                float f9 = m1241d.bottom;
                if (f9 < m1243f) {
                    this.f2956D = 1;
                    f2 = m1243f - f9;
                } else {
                    this.f2956D = -1;
                    f2 = 0.0f;
                }
            }
        }
        float m1244g = m1244g(this.f2967k);
        if (width <= m1244g) {
            int i3 = d.f2986a[this.f2958F.ordinal()];
            if (i3 != 2) {
                if (i3 != 3) {
                    f3 = (m1244g - width) / 2.0f;
                    f4 = m1241d.left;
                } else {
                    f3 = m1244g - width;
                    f4 = m1241d.left;
                }
                f7 = f3 - f4;
            } else {
                f7 = -m1241d.left;
            }
            this.f2955C = 2;
        } else {
            float f10 = m1241d.left;
            if (f10 > 0.0f) {
                this.f2955C = 0;
                f7 = -f10;
            } else {
                float f11 = m1241d.right;
                if (f11 < m1244g) {
                    f7 = m1244g - f11;
                    this.f2955C = 1;
                } else {
                    this.f2955C = -1;
                }
            }
        }
        this.f2972p.postTranslate(f7, f2);
        return true;
    }

    /* renamed from: c */
    public RectF m1240c() {
        m1239b();
        return m1241d(m1242e());
    }

    /* renamed from: d */
    public final RectF m1241d(Matrix matrix) {
        if (this.f2967k.getDrawable() == null) {
            return null;
        }
        this.f2973q.set(0.0f, 0.0f, r0.getIntrinsicWidth(), r0.getIntrinsicHeight());
        matrix.mapRect(this.f2973q);
        return this.f2973q;
    }

    /* renamed from: e */
    public final Matrix m1242e() {
        this.f2971o.set(this.f2970n);
        this.f2971o.postConcat(this.f2972p);
        return this.f2971o;
    }

    /* renamed from: f */
    public final int m1243f(ImageView imageView) {
        return (imageView.getHeight() - imageView.getPaddingTop()) - imageView.getPaddingBottom();
    }

    /* renamed from: g */
    public final int m1244g(ImageView imageView) {
        return (imageView.getWidth() - imageView.getPaddingLeft()) - imageView.getPaddingRight();
    }

    /* renamed from: h */
    public float m1245h() {
        this.f2972p.getValues(this.f2974r);
        float pow = (float) Math.pow(this.f2974r[0], 2.0d);
        this.f2972p.getValues(this.f2974r);
        return (float) Math.sqrt(pow + ((float) Math.pow(this.f2974r[3], 2.0d)));
    }

    /* renamed from: i */
    public final void m1246i() {
        RectF m1241d;
        this.f2972p.reset();
        this.f2972p.postRotate(0.0f);
        m1238a();
        Matrix m1242e = m1242e();
        this.f2967k.setImageMatrix(m1242e);
        if (this.f2975s != null && (m1241d = m1241d(m1242e)) != null) {
            this.f2975s.onMatrixChanged(m1241d);
        }
        m1239b();
    }

    /* renamed from: j */
    public void m1247j(float f2, float f3, float f4, boolean z) {
        if (f2 < this.f2962f || f2 > this.f2964h) {
            throw new IllegalArgumentException("Scale must be within the range of minScale and maxScale");
        }
        if (z) {
            this.f2967k.post(new e(m1245h(), f2, f3, f4));
        } else {
            this.f2972p.setScale(f2, f2, f3, f4);
            m1238a();
        }
    }

    /* renamed from: k */
    public void m1248k() {
        if (this.f2957E) {
            m1249l(this.f2967k.getDrawable());
        } else {
            m1246i();
        }
    }

    /* renamed from: l */
    public final void m1249l(Drawable drawable) {
        if (drawable == null) {
            return;
        }
        float m1244g = m1244g(this.f2967k);
        float m1243f = m1243f(this.f2967k);
        int intrinsicWidth = drawable.getIntrinsicWidth();
        int intrinsicHeight = drawable.getIntrinsicHeight();
        this.f2970n.reset();
        float f2 = intrinsicWidth;
        float f3 = m1244g / f2;
        float f4 = intrinsicHeight;
        float f5 = m1243f / f4;
        ImageView.ScaleType scaleType = this.f2958F;
        if (scaleType == ImageView.ScaleType.CENTER) {
            this.f2970n.postTranslate((m1244g - f2) / 2.0f, (m1243f - f4) / 2.0f);
        } else if (scaleType == ImageView.ScaleType.CENTER_CROP) {
            float max = Math.max(f3, f5);
            this.f2970n.postScale(max, max);
            this.f2970n.postTranslate((m1244g - (f2 * max)) / 2.0f, (m1243f - (f4 * max)) / 2.0f);
        } else if (scaleType == ImageView.ScaleType.CENTER_INSIDE) {
            float min = Math.min(1.0f, Math.min(f3, f5));
            this.f2970n.postScale(min, min);
            this.f2970n.postTranslate((m1244g - (f2 * min)) / 2.0f, (m1243f - (f4 * min)) / 2.0f);
        } else {
            RectF rectF = new RectF(0.0f, 0.0f, f2, f4);
            RectF rectF2 = new RectF(0.0f, 0.0f, m1244g, m1243f);
            if (((int) 0.0f) % 180 != 0) {
                rectF = new RectF(0.0f, 0.0f, f4, f2);
            }
            int i2 = d.f2986a[this.f2958F.ordinal()];
            if (i2 == 1) {
                this.f2970n.setRectToRect(rectF, rectF2, Matrix.ScaleToFit.CENTER);
            } else if (i2 == 2) {
                this.f2970n.setRectToRect(rectF, rectF2, Matrix.ScaleToFit.START);
            } else if (i2 == 3) {
                this.f2970n.setRectToRect(rectF, rectF2, Matrix.ScaleToFit.END);
            } else if (i2 == 4) {
                this.f2970n.setRectToRect(rectF, rectF2, Matrix.ScaleToFit.FILL);
            }
        }
        m1246i();
    }

    @Override // android.view.View.OnLayoutChangeListener
    public void onLayoutChange(View view, int i2, int i3, int i4, int i5, int i6, int i7, int i8, int i9) {
        if (i2 == i6 && i3 == i7 && i4 == i8 && i5 == i9) {
            return;
        }
        m1249l(this.f2967k.getDrawable());
    }

    /* JADX WARN: Removed duplicated region for block: B:15:0x008d  */
    /* JADX WARN: Removed duplicated region for block: B:42:0x00c0  */
    @Override // android.view.View.OnTouchListener
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean onTouch(android.view.View r11, android.view.MotionEvent r12) {
        /*
            r10 = this;
            boolean r0 = r10.f2957E
            r1 = 0
            r2 = 1
            if (r0 == 0) goto Lcc
            r0 = r11
            android.widget.ImageView r0 = (android.widget.ImageView) r0
            android.graphics.drawable.Drawable r0 = r0.getDrawable()
            if (r0 == 0) goto L11
            r0 = 1
            goto L12
        L11:
            r0 = 0
        L12:
            if (r0 == 0) goto Lcc
            int r0 = r12.getAction()
            if (r0 == 0) goto L73
            if (r0 == r2) goto L20
            r3 = 3
            if (r0 == r3) goto L20
            goto L88
        L20:
            float r0 = r10.m1245h()
            float r3 = r10.f2962f
            int r0 = (r0 > r3 ? 1 : (r0 == r3 ? 0 : -1))
            if (r0 >= 0) goto L49
            android.graphics.RectF r0 = r10.m1240c()
            if (r0 == 0) goto L88
            b.k.b.a.j$e r9 = new b.k.b.a.j$e
            float r5 = r10.m1245h()
            float r6 = r10.f2962f
            float r7 = r0.centerX()
            float r8 = r0.centerY()
            r3 = r9
            r4 = r10
            r3.<init>(r5, r6, r7, r8)
            r11.post(r9)
            goto L71
        L49:
            float r0 = r10.m1245h()
            float r3 = r10.f2964h
            int r0 = (r0 > r3 ? 1 : (r0 == r3 ? 0 : -1))
            if (r0 <= 0) goto L88
            android.graphics.RectF r0 = r10.m1240c()
            if (r0 == 0) goto L88
            b.k.b.a.j$e r9 = new b.k.b.a.j$e
            float r5 = r10.m1245h()
            float r6 = r10.f2964h
            float r7 = r0.centerX()
            float r8 = r0.centerY()
            r3 = r9
            r4 = r10
            r3.<init>(r5, r6, r7, r8)
            r11.post(r9)
        L71:
            r11 = 1
            goto L89
        L73:
            android.view.ViewParent r11 = r11.getParent()
            if (r11 == 0) goto L7c
            r11.requestDisallowInterceptTouchEvent(r2)
        L7c:
            b.k.b.a.j$f r11 = r10.f2954B
            if (r11 == 0) goto L88
            android.widget.OverScroller r11 = r11.f2993c
            r11.forceFinished(r2)
            r11 = 0
            r10.f2954B = r11
        L88:
            r11 = 0
        L89:
            b.k.b.a.a r0 = r10.f2969m
            if (r0 == 0) goto Lc0
            boolean r11 = r0.m1236c()
            b.k.b.a.a r0 = r10.f2969m
            boolean r3 = r0.f2946e
            android.view.ScaleGestureDetector r4 = r0.f2944c     // Catch: java.lang.IllegalArgumentException -> L9e
            r4.onTouchEvent(r12)     // Catch: java.lang.IllegalArgumentException -> L9e
            r0.m1237d(r12)     // Catch: java.lang.IllegalArgumentException -> L9e
            goto L9f
        L9e:
        L9f:
            if (r11 != 0) goto Lab
            b.k.b.a.a r11 = r10.f2969m
            boolean r11 = r11.m1236c()
            if (r11 != 0) goto Lab
            r11 = 1
            goto Lac
        Lab:
            r11 = 0
        Lac:
            if (r3 != 0) goto Lb6
            b.k.b.a.a r0 = r10.f2969m
            boolean r0 = r0.f2946e
            if (r0 != 0) goto Lb6
            r0 = 1
            goto Lb7
        Lb6:
            r0 = 0
        Lb7:
            if (r11 == 0) goto Lbc
            if (r0 == 0) goto Lbc
            r1 = 1
        Lbc:
            r10.f2966j = r1
            r1 = 1
            goto Lc1
        Lc0:
            r1 = r11
        Lc1:
            android.view.GestureDetector r11 = r10.f2968l
            if (r11 == 0) goto Lcc
            boolean r11 = r11.onTouchEvent(r12)
            if (r11 == 0) goto Lcc
            r1 = 1
        Lcc:
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p190k.p195b.p196a.ViewOnTouchListenerC1898j.onTouch(android.view.View, android.view.MotionEvent):boolean");
    }

    public void setOnClickListener(View.OnClickListener onClickListener) {
        this.f2979w = onClickListener;
    }

    public void setOnDoubleTapListener(GestureDetector.OnDoubleTapListener onDoubleTapListener) {
        this.f2968l.setOnDoubleTapListener(onDoubleTapListener);
    }

    public void setOnLongClickListener(View.OnLongClickListener onLongClickListener) {
        this.f2980x = onLongClickListener;
    }

    public void setOnMatrixChangeListener(InterfaceC1891c interfaceC1891c) {
        this.f2975s = interfaceC1891c;
    }

    public void setOnOutsidePhotoTapListener(InterfaceC1892d interfaceC1892d) {
        this.f2977u = interfaceC1892d;
    }

    public void setOnPhotoTapListener(InterfaceC1893e interfaceC1893e) {
        this.f2976t = interfaceC1893e;
    }

    public void setOnScaleChangeListener(InterfaceC1894f interfaceC1894f) {
        this.f2981y = interfaceC1894f;
    }

    public void setOnSingleFlingListener(InterfaceC1895g interfaceC1895g) {
        this.f2982z = interfaceC1895g;
    }

    public void setOnViewDragListener(InterfaceC1896h interfaceC1896h) {
        this.f2953A = interfaceC1896h;
    }

    public void setOnViewTapListener(InterfaceC1897i interfaceC1897i) {
        this.f2978v = interfaceC1897i;
    }
}
