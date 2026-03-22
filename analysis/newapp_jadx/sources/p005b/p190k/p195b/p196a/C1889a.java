package p005b.p190k.p195b.p196a;

import android.content.Context;
import android.graphics.RectF;
import android.view.MotionEvent;
import android.view.ScaleGestureDetector;
import android.view.VelocityTracker;
import android.view.ViewConfiguration;
import android.view.ViewParent;
import p005b.p190k.p195b.p196a.ViewOnTouchListenerC1898j;
import p005b.p190k.p195b.p196a.ViewOnTouchListenerC1898j.f;

/* renamed from: b.k.b.a.a */
/* loaded from: classes.dex */
public class C1889a {

    /* renamed from: a */
    public int f2942a = -1;

    /* renamed from: b */
    public int f2943b = 0;

    /* renamed from: c */
    public final ScaleGestureDetector f2944c;

    /* renamed from: d */
    public VelocityTracker f2945d;

    /* renamed from: e */
    public boolean f2946e;

    /* renamed from: f */
    public float f2947f;

    /* renamed from: g */
    public float f2948g;

    /* renamed from: h */
    public final float f2949h;

    /* renamed from: i */
    public final float f2950i;

    /* renamed from: j */
    public InterfaceC1890b f2951j;

    /* renamed from: b.k.b.a.a$a */
    public class a implements ScaleGestureDetector.OnScaleGestureListener {
        public a() {
        }

        @Override // android.view.ScaleGestureDetector.OnScaleGestureListener
        public boolean onScale(ScaleGestureDetector scaleGestureDetector) {
            float scaleFactor = scaleGestureDetector.getScaleFactor();
            if (Float.isNaN(scaleFactor) || Float.isInfinite(scaleFactor)) {
                return false;
            }
            if (scaleFactor < 0.0f) {
                return true;
            }
            ((ViewOnTouchListenerC1898j.a) C1889a.this.f2951j).m1250a(scaleFactor, scaleGestureDetector.getFocusX(), scaleGestureDetector.getFocusY());
            return true;
        }

        @Override // android.view.ScaleGestureDetector.OnScaleGestureListener
        public boolean onScaleBegin(ScaleGestureDetector scaleGestureDetector) {
            return true;
        }

        @Override // android.view.ScaleGestureDetector.OnScaleGestureListener
        public void onScaleEnd(ScaleGestureDetector scaleGestureDetector) {
        }
    }

    public C1889a(Context context, InterfaceC1890b interfaceC1890b) {
        ViewConfiguration viewConfiguration = ViewConfiguration.get(context);
        this.f2950i = viewConfiguration.getScaledMinimumFlingVelocity();
        this.f2949h = viewConfiguration.getScaledTouchSlop();
        this.f2951j = interfaceC1890b;
        this.f2944c = new ScaleGestureDetector(context, new a());
    }

    /* renamed from: a */
    public final float m1234a(MotionEvent motionEvent) {
        try {
            return motionEvent.getX(this.f2943b);
        } catch (Exception unused) {
            return motionEvent.getX();
        }
    }

    /* renamed from: b */
    public final float m1235b(MotionEvent motionEvent) {
        try {
            return motionEvent.getY(this.f2943b);
        } catch (Exception unused) {
            return motionEvent.getY();
        }
    }

    /* renamed from: c */
    public boolean m1236c() {
        return this.f2944c.isInProgress();
    }

    /* renamed from: d */
    public final boolean m1237d(MotionEvent motionEvent) {
        int i2;
        int i3;
        int i4;
        int i5;
        int i6;
        int action = motionEvent.getAction() & 255;
        if (action == 0) {
            this.f2942a = motionEvent.getPointerId(0);
            VelocityTracker obtain = VelocityTracker.obtain();
            this.f2945d = obtain;
            if (obtain != null) {
                obtain.addMovement(motionEvent);
            }
            this.f2947f = m1234a(motionEvent);
            this.f2948g = m1235b(motionEvent);
            this.f2946e = false;
        } else if (action == 1) {
            this.f2942a = -1;
            if (this.f2946e && this.f2945d != null) {
                this.f2947f = m1234a(motionEvent);
                this.f2948g = m1235b(motionEvent);
                this.f2945d.addMovement(motionEvent);
                this.f2945d.computeCurrentVelocity(1000);
                float xVelocity = this.f2945d.getXVelocity();
                float yVelocity = this.f2945d.getYVelocity();
                if (Math.max(Math.abs(xVelocity), Math.abs(yVelocity)) >= this.f2950i) {
                    ViewOnTouchListenerC1898j.a aVar = (ViewOnTouchListenerC1898j.a) this.f2951j;
                    ViewOnTouchListenerC1898j viewOnTouchListenerC1898j = ViewOnTouchListenerC1898j.this;
                    viewOnTouchListenerC1898j.f2954B = viewOnTouchListenerC1898j.new f(viewOnTouchListenerC1898j.f2967k.getContext());
                    ViewOnTouchListenerC1898j viewOnTouchListenerC1898j2 = ViewOnTouchListenerC1898j.this;
                    ViewOnTouchListenerC1898j.f fVar = viewOnTouchListenerC1898j2.f2954B;
                    int m1244g = viewOnTouchListenerC1898j2.m1244g(viewOnTouchListenerC1898j2.f2967k);
                    ViewOnTouchListenerC1898j viewOnTouchListenerC1898j3 = ViewOnTouchListenerC1898j.this;
                    int m1243f = viewOnTouchListenerC1898j3.m1243f(viewOnTouchListenerC1898j3.f2967k);
                    int i7 = (int) (-xVelocity);
                    int i8 = (int) (-yVelocity);
                    RectF m1240c = ViewOnTouchListenerC1898j.this.m1240c();
                    if (m1240c != null) {
                        int round = Math.round(-m1240c.left);
                        float f2 = m1244g;
                        if (f2 < m1240c.width()) {
                            i2 = Math.round(m1240c.width() - f2);
                            i3 = 0;
                        } else {
                            i2 = round;
                            i3 = i2;
                        }
                        int round2 = Math.round(-m1240c.top);
                        float f3 = m1243f;
                        if (f3 < m1240c.height()) {
                            i4 = Math.round(m1240c.height() - f3);
                            i5 = 0;
                        } else {
                            i4 = round2;
                            i5 = i4;
                        }
                        fVar.f2994e = round;
                        fVar.f2995f = round2;
                        if (round != i2 || round2 != i4) {
                            fVar.f2993c.fling(round, round2, i7, i8, i3, i2, i5, i4, 0, 0);
                        }
                    }
                    ViewOnTouchListenerC1898j viewOnTouchListenerC1898j4 = ViewOnTouchListenerC1898j.this;
                    viewOnTouchListenerC1898j4.f2967k.post(viewOnTouchListenerC1898j4.f2954B);
                }
            }
            VelocityTracker velocityTracker = this.f2945d;
            if (velocityTracker != null) {
                velocityTracker.recycle();
                this.f2945d = null;
            }
        } else if (action == 2) {
            float m1234a = m1234a(motionEvent);
            float m1235b = m1235b(motionEvent);
            float f4 = m1234a - this.f2947f;
            float f5 = m1235b - this.f2948g;
            if (!this.f2946e) {
                this.f2946e = Math.sqrt((double) ((f5 * f5) + (f4 * f4))) >= ((double) this.f2949h);
            }
            if (this.f2946e) {
                ViewOnTouchListenerC1898j.a aVar2 = (ViewOnTouchListenerC1898j.a) this.f2951j;
                if (!ViewOnTouchListenerC1898j.this.f2969m.m1236c()) {
                    InterfaceC1896h interfaceC1896h = ViewOnTouchListenerC1898j.this.f2953A;
                    if (interfaceC1896h != null) {
                        interfaceC1896h.onDrag(f4, f5);
                    }
                    ViewOnTouchListenerC1898j.this.f2972p.postTranslate(f4, f5);
                    ViewOnTouchListenerC1898j.this.m1238a();
                    ViewParent parent = ViewOnTouchListenerC1898j.this.f2967k.getParent();
                    ViewOnTouchListenerC1898j viewOnTouchListenerC1898j5 = ViewOnTouchListenerC1898j.this;
                    if (viewOnTouchListenerC1898j5.f2965i && !viewOnTouchListenerC1898j5.f2969m.m1236c()) {
                        ViewOnTouchListenerC1898j viewOnTouchListenerC1898j6 = ViewOnTouchListenerC1898j.this;
                        if (!viewOnTouchListenerC1898j6.f2966j) {
                            int i9 = viewOnTouchListenerC1898j6.f2955C;
                            if ((i9 == 2 || ((i9 == 0 && f4 >= 1.0f) || ((i9 == 1 && f4 <= -1.0f) || (((i6 = viewOnTouchListenerC1898j6.f2956D) == 0 && f5 >= 1.0f) || (i6 == 1 && f5 <= -1.0f))))) && parent != null) {
                                parent.requestDisallowInterceptTouchEvent(false);
                            }
                        }
                    }
                    if (parent != null) {
                        parent.requestDisallowInterceptTouchEvent(true);
                    }
                }
                this.f2947f = m1234a;
                this.f2948g = m1235b;
                VelocityTracker velocityTracker2 = this.f2945d;
                if (velocityTracker2 != null) {
                    velocityTracker2.addMovement(motionEvent);
                }
            }
        } else if (action == 3) {
            this.f2942a = -1;
            VelocityTracker velocityTracker3 = this.f2945d;
            if (velocityTracker3 != null) {
                velocityTracker3.recycle();
                this.f2945d = null;
            }
        } else if (action == 6) {
            int action2 = (motionEvent.getAction() & 65280) >> 8;
            if (motionEvent.getPointerId(action2) == this.f2942a) {
                int i10 = action2 == 0 ? 1 : 0;
                this.f2942a = motionEvent.getPointerId(i10);
                this.f2947f = motionEvent.getX(i10);
                this.f2948g = motionEvent.getY(i10);
            }
        }
        int i11 = this.f2942a;
        this.f2943b = motionEvent.findPointerIndex(i11 != -1 ? i11 : 0);
        return true;
    }
}
