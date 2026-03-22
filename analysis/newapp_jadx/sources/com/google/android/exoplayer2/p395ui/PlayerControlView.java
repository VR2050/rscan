package com.google.android.exoplayer2.p395ui;

import android.content.Context;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.graphics.drawable.Drawable;
import android.os.Looper;
import android.os.SystemClock;
import android.util.AttributeSet;
import android.view.KeyEvent;
import android.view.LayoutInflater;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.annotation.Nullable;
import com.google.android.exoplayer2.p395ui.PlayerControlView;
import com.google.android.exoplayer2.source.TrackGroupArray;
import java.util.Formatter;
import java.util.Iterator;
import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;
import p005b.p199l.p200a.p201a.AbstractC2404x0;
import p005b.p199l.p200a.p201a.C1936b0;
import p005b.p199l.p200a.p201a.C1960e0;
import p005b.p199l.p200a.p201a.C2262n0;
import p005b.p199l.p200a.p201a.C2336p0;
import p005b.p199l.p200a.p201a.C2403x;
import p005b.p199l.p200a.p201a.InterfaceC2279o0;
import p005b.p199l.p200a.p201a.InterfaceC2368q0;
import p005b.p199l.p200a.p201a.InterfaceC2401w;
import p005b.p199l.p200a.p201a.p245m1.C2258g;
import p005b.p199l.p200a.p201a.p246n1.InterfaceC2268f;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* loaded from: classes.dex */
public class PlayerControlView extends FrameLayout {

    /* renamed from: c */
    public static final /* synthetic */ int f9616c = 0;

    /* renamed from: A */
    public final Drawable f9617A;

    /* renamed from: B */
    public final String f9618B;

    /* renamed from: C */
    public final String f9619C;

    /* renamed from: D */
    public final String f9620D;

    /* renamed from: E */
    public final Drawable f9621E;

    /* renamed from: F */
    public final Drawable f9622F;

    /* renamed from: G */
    public final float f9623G;

    /* renamed from: H */
    public final float f9624H;

    /* renamed from: I */
    public final String f9625I;

    /* renamed from: J */
    public final String f9626J;

    /* renamed from: K */
    @Nullable
    public InterfaceC2368q0 f9627K;

    /* renamed from: L */
    public InterfaceC2401w f9628L;

    /* renamed from: M */
    @Nullable
    public InterfaceC3318c f9629M;

    /* renamed from: N */
    @Nullable
    public InterfaceC2279o0 f9630N;

    /* renamed from: O */
    public boolean f9631O;

    /* renamed from: P */
    public boolean f9632P;

    /* renamed from: Q */
    public boolean f9633Q;

    /* renamed from: R */
    public boolean f9634R;

    /* renamed from: S */
    public int f9635S;

    /* renamed from: T */
    public int f9636T;

    /* renamed from: U */
    public int f9637U;

    /* renamed from: V */
    public int f9638V;

    /* renamed from: W */
    public int f9639W;

    /* renamed from: a0 */
    public boolean f9640a0;

    /* renamed from: b0 */
    public long f9641b0;

    /* renamed from: c0 */
    public long[] f9642c0;

    /* renamed from: d0 */
    public boolean[] f9643d0;

    /* renamed from: e */
    public final ViewOnClickListenerC3317b f9644e;

    /* renamed from: e0 */
    public long[] f9645e0;

    /* renamed from: f */
    public final CopyOnWriteArrayList<InterfaceC3319d> f9646f;

    /* renamed from: f0 */
    public boolean[] f9647f0;

    /* renamed from: g */
    @Nullable
    public final View f9648g;

    /* renamed from: g0 */
    public long f9649g0;

    /* renamed from: h */
    @Nullable
    public final View f9650h;

    /* renamed from: i */
    @Nullable
    public final View f9651i;

    /* renamed from: j */
    @Nullable
    public final View f9652j;

    /* renamed from: k */
    @Nullable
    public final View f9653k;

    /* renamed from: l */
    @Nullable
    public final View f9654l;

    /* renamed from: m */
    @Nullable
    public final ImageView f9655m;

    /* renamed from: n */
    @Nullable
    public final ImageView f9656n;

    /* renamed from: o */
    @Nullable
    public final View f9657o;

    /* renamed from: p */
    @Nullable
    public final TextView f9658p;

    /* renamed from: q */
    @Nullable
    public final TextView f9659q;

    /* renamed from: r */
    @Nullable
    public final InterfaceC2268f f9660r;

    /* renamed from: s */
    public final StringBuilder f9661s;

    /* renamed from: t */
    public final Formatter f9662t;

    /* renamed from: u */
    public final AbstractC2404x0.b f9663u;

    /* renamed from: v */
    public final AbstractC2404x0.c f9664v;

    /* renamed from: w */
    public final Runnable f9665w;

    /* renamed from: x */
    public final Runnable f9666x;

    /* renamed from: y */
    public final Drawable f9667y;

    /* renamed from: z */
    public final Drawable f9668z;

    /* renamed from: com.google.android.exoplayer2.ui.PlayerControlView$b */
    public final class ViewOnClickListenerC3317b implements InterfaceC2368q0.a, InterfaceC2268f.a, View.OnClickListener {
        public ViewOnClickListenerC3317b(C3316a c3316a) {
        }

        @Override // p005b.p199l.p200a.p201a.p246n1.InterfaceC2268f.a
        /* renamed from: a */
        public void mo2169a(InterfaceC2268f interfaceC2268f, long j2) {
            PlayerControlView playerControlView = PlayerControlView.this;
            TextView textView = playerControlView.f9659q;
            if (textView != null) {
                textView.setText(C2344d0.m2340r(playerControlView.f9661s, playerControlView.f9662t, j2));
            }
        }

        @Override // p005b.p199l.p200a.p201a.p246n1.InterfaceC2268f.a
        /* renamed from: b */
        public void mo2170b(InterfaceC2268f interfaceC2268f, long j2, boolean z) {
            InterfaceC2368q0 interfaceC2368q0;
            PlayerControlView playerControlView = PlayerControlView.this;
            int i2 = 0;
            playerControlView.f9634R = false;
            if (z || (interfaceC2368q0 = playerControlView.f9627K) == null) {
                return;
            }
            AbstractC2404x0 mo1375y = interfaceC2368q0.mo1375y();
            if (playerControlView.f9633Q && !mo1375y.m2691q()) {
                int mo1836p = mo1375y.mo1836p();
                while (true) {
                    long m2698a = mo1375y.m2690n(i2, playerControlView.f9664v).m2698a();
                    if (j2 < m2698a) {
                        break;
                    }
                    if (i2 == mo1836p - 1) {
                        j2 = m2698a;
                        break;
                    } else {
                        j2 -= m2698a;
                        i2++;
                    }
                }
            } else {
                i2 = interfaceC2368q0.mo1367o();
            }
            Objects.requireNonNull((C2403x) playerControlView.f9628L);
            interfaceC2368q0.mo1360g(i2, j2);
        }

        @Override // p005b.p199l.p200a.p201a.p246n1.InterfaceC2268f.a
        /* renamed from: c */
        public void mo2171c(InterfaceC2268f interfaceC2268f, long j2) {
            PlayerControlView playerControlView = PlayerControlView.this;
            playerControlView.f9634R = true;
            TextView textView = playerControlView.f9659q;
            if (textView != null) {
                textView.setText(C2344d0.m2340r(playerControlView.f9661s, playerControlView.f9662t, j2));
            }
        }

        /* JADX WARN: Removed duplicated region for block: B:62:0x00be A[LOOP:0: B:52:0x009f->B:62:0x00be, LOOP_END] */
        /* JADX WARN: Removed duplicated region for block: B:63:0x00bc A[SYNTHETIC] */
        @Override // android.view.View.OnClickListener
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public void onClick(android.view.View r9) {
            /*
                Method dump skipped, instructions count: 222
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: com.google.android.exoplayer2.p395ui.PlayerControlView.ViewOnClickListenerC3317b.onClick(android.view.View):void");
        }

        @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
        public void onIsPlayingChanged(boolean z) {
            PlayerControlView playerControlView = PlayerControlView.this;
            int i2 = PlayerControlView.f9616c;
            playerControlView.m4101n();
        }

        @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
        public /* synthetic */ void onLoadingChanged(boolean z) {
            C2336p0.m2286b(this, z);
        }

        @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
        public /* synthetic */ void onPlaybackParametersChanged(C2262n0 c2262n0) {
            C2336p0.m2287c(this, c2262n0);
        }

        @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
        public /* synthetic */ void onPlaybackSuppressionReasonChanged(int i2) {
            C2336p0.m2288d(this, i2);
        }

        @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
        public /* synthetic */ void onPlayerError(C1936b0 c1936b0) {
            C2336p0.m2289e(this, c1936b0);
        }

        @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
        public void onPlayerStateChanged(boolean z, int i2) {
            PlayerControlView playerControlView = PlayerControlView.this;
            int i3 = PlayerControlView.f9616c;
            playerControlView.m4100m();
            PlayerControlView.this.m4101n();
        }

        @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
        public void onPositionDiscontinuity(int i2) {
            PlayerControlView playerControlView = PlayerControlView.this;
            int i3 = PlayerControlView.f9616c;
            playerControlView.m4099l();
            PlayerControlView.this.m4104q();
        }

        @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
        public void onRepeatModeChanged(int i2) {
            PlayerControlView playerControlView = PlayerControlView.this;
            int i3 = PlayerControlView.f9616c;
            playerControlView.m4102o();
            PlayerControlView.this.m4099l();
        }

        @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
        public /* synthetic */ void onSeekProcessed() {
            C2336p0.m2292h(this);
        }

        @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
        public void onShuffleModeEnabledChanged(boolean z) {
            PlayerControlView playerControlView = PlayerControlView.this;
            int i2 = PlayerControlView.f9616c;
            playerControlView.m4103p();
            PlayerControlView.this.m4099l();
        }

        @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
        public void onTimelineChanged(AbstractC2404x0 abstractC2404x0, int i2) {
            PlayerControlView playerControlView = PlayerControlView.this;
            int i3 = PlayerControlView.f9616c;
            playerControlView.m4099l();
            PlayerControlView.this.m4104q();
        }

        @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
        public /* synthetic */ void onTimelineChanged(AbstractC2404x0 abstractC2404x0, Object obj, int i2) {
            C2336p0.m2295k(this, abstractC2404x0, obj, i2);
        }

        @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
        public /* synthetic */ void onTracksChanged(TrackGroupArray trackGroupArray, C2258g c2258g) {
            C2336p0.m2296l(this, trackGroupArray, c2258g);
        }
    }

    /* renamed from: com.google.android.exoplayer2.ui.PlayerControlView$c */
    public interface InterfaceC3318c {
        /* renamed from: a */
        void m4105a(long j2, long j3);
    }

    /* renamed from: com.google.android.exoplayer2.ui.PlayerControlView$d */
    public interface InterfaceC3319d {
        /* renamed from: a */
        void mo4106a(int i2);
    }

    static {
        C1960e0.m1454a("goog.exo.ui");
    }

    public PlayerControlView(Context context) {
        this(context, null);
    }

    /* renamed from: a */
    public boolean m4088a(KeyEvent keyEvent) {
        int i2;
        int i3;
        int keyCode = keyEvent.getKeyCode();
        InterfaceC2368q0 interfaceC2368q0 = this.f9627K;
        if (interfaceC2368q0 != null) {
            if (keyCode == 90 || keyCode == 89 || keyCode == 85 || keyCode == 126 || keyCode == 127 || keyCode == 87 || keyCode == 88) {
                if (keyEvent.getAction() == 0) {
                    if (keyCode == 90) {
                        if (interfaceC2368q0.mo2610k() && (i3 = this.f9636T) > 0) {
                            m4095h(interfaceC2368q0, i3);
                        }
                    } else if (keyCode == 89) {
                        if (interfaceC2368q0.mo2610k() && (i2 = this.f9635S) > 0) {
                            m4095h(interfaceC2368q0, -i2);
                        }
                    } else if (keyEvent.getRepeatCount() == 0) {
                        if (keyCode == 85) {
                            InterfaceC2401w interfaceC2401w = this.f9628L;
                            boolean z = !interfaceC2368q0.mo1361h();
                            Objects.requireNonNull((C2403x) interfaceC2401w);
                            interfaceC2368q0.mo1368p(z);
                        } else if (keyCode == 87) {
                            m4092e(interfaceC2368q0);
                        } else if (keyCode == 88) {
                            m4093f(interfaceC2368q0);
                        } else if (keyCode == 126) {
                            Objects.requireNonNull((C2403x) this.f9628L);
                            interfaceC2368q0.mo1368p(true);
                        } else if (keyCode == 127) {
                            Objects.requireNonNull((C2403x) this.f9628L);
                            interfaceC2368q0.mo1368p(false);
                        }
                    }
                }
                return true;
            }
        }
        return false;
    }

    /* renamed from: b */
    public void m4089b() {
        if (m4091d()) {
            setVisibility(8);
            Iterator<InterfaceC3319d> it = this.f9646f.iterator();
            while (it.hasNext()) {
                it.next().mo4106a(getVisibility());
            }
            removeCallbacks(this.f9665w);
            removeCallbacks(this.f9666x);
            this.f9641b0 = -9223372036854775807L;
        }
    }

    /* renamed from: c */
    public final void m4090c() {
        removeCallbacks(this.f9666x);
        if (this.f9637U <= 0) {
            this.f9641b0 = -9223372036854775807L;
            return;
        }
        long uptimeMillis = SystemClock.uptimeMillis();
        int i2 = this.f9637U;
        this.f9641b0 = uptimeMillis + i2;
        if (this.f9631O) {
            postDelayed(this.f9666x, i2);
        }
    }

    /* renamed from: d */
    public boolean m4091d() {
        return getVisibility() == 0;
    }

    @Override // android.view.ViewGroup, android.view.View
    public boolean dispatchKeyEvent(KeyEvent keyEvent) {
        return m4088a(keyEvent) || super.dispatchKeyEvent(keyEvent);
    }

    @Override // android.view.ViewGroup, android.view.View
    public final boolean dispatchTouchEvent(MotionEvent motionEvent) {
        if (motionEvent.getAction() == 0) {
            removeCallbacks(this.f9666x);
        } else if (motionEvent.getAction() == 1) {
            m4090c();
        }
        return super.dispatchTouchEvent(motionEvent);
    }

    /* renamed from: e */
    public final void m4092e(InterfaceC2368q0 interfaceC2368q0) {
        AbstractC2404x0 mo1375y = interfaceC2368q0.mo1375y();
        if (mo1375y.m2691q() || interfaceC2368q0.mo1356c()) {
            return;
        }
        int mo1367o = interfaceC2368q0.mo1367o();
        int mo2612v = interfaceC2368q0.mo2612v();
        if (mo2612v != -1) {
            Objects.requireNonNull((C2403x) this.f9628L);
            interfaceC2368q0.mo1360g(mo2612v, -9223372036854775807L);
        } else if (mo1375y.m2690n(mo1367o, this.f9664v).f6377f) {
            Objects.requireNonNull((C2403x) this.f9628L);
            interfaceC2368q0.mo1360g(mo1367o, -9223372036854775807L);
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:12:0x0033, code lost:
    
        if (r2.f6376e == false) goto L15;
     */
    /* renamed from: f */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void m4093f(p005b.p199l.p200a.p201a.InterfaceC2368q0 r8) {
        /*
            r7 = this;
            b.l.a.a.x0 r0 = r8.mo1375y()
            boolean r1 = r0.m2691q()
            if (r1 != 0) goto L51
            boolean r1 = r8.mo1356c()
            if (r1 == 0) goto L11
            goto L51
        L11:
            int r1 = r8.mo1367o()
            b.l.a.a.x0$c r2 = r7.f9664v
            r0.m2690n(r1, r2)
            int r0 = r8.mo2611s()
            r2 = -1
            if (r0 == r2) goto L45
            long r2 = r8.getCurrentPosition()
            r4 = 3000(0xbb8, double:1.482E-320)
            int r6 = (r2 > r4 ? 1 : (r2 == r4 ? 0 : -1))
            if (r6 <= 0) goto L35
            b.l.a.a.x0$c r2 = r7.f9664v
            boolean r3 = r2.f6377f
            if (r3 == 0) goto L45
            boolean r2 = r2.f6376e
            if (r2 != 0) goto L45
        L35:
            r1 = -9223372036854775807(0x8000000000000001, double:-4.9E-324)
            b.l.a.a.w r3 = r7.f9628L
            b.l.a.a.x r3 = (p005b.p199l.p200a.p201a.C2403x) r3
            java.util.Objects.requireNonNull(r3)
            r8.mo1360g(r0, r1)
            goto L51
        L45:
            r2 = 0
            b.l.a.a.w r0 = r7.f9628L
            b.l.a.a.x r0 = (p005b.p199l.p200a.p201a.C2403x) r0
            java.util.Objects.requireNonNull(r0)
            r8.mo1360g(r1, r2)
        L51:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.exoplayer2.p395ui.PlayerControlView.m4093f(b.l.a.a.q0):void");
    }

    /* renamed from: g */
    public final void m4094g() {
        View view;
        View view2;
        boolean m4097j = m4097j();
        if (!m4097j && (view2 = this.f9651i) != null) {
            view2.requestFocus();
        } else {
            if (!m4097j || (view = this.f9652j) == null) {
                return;
            }
            view.requestFocus();
        }
    }

    @Nullable
    public InterfaceC2368q0 getPlayer() {
        return this.f9627K;
    }

    public int getRepeatToggleModes() {
        return this.f9639W;
    }

    public boolean getShowShuffleButton() {
        return this.f9640a0;
    }

    public int getShowTimeoutMs() {
        return this.f9637U;
    }

    public boolean getShowVrButton() {
        View view = this.f9657o;
        return view != null && view.getVisibility() == 0;
    }

    /* renamed from: h */
    public final void m4095h(InterfaceC2368q0 interfaceC2368q0, long j2) {
        long currentPosition = interfaceC2368q0.getCurrentPosition() + j2;
        long duration = interfaceC2368q0.getDuration();
        if (duration != -9223372036854775807L) {
            currentPosition = Math.min(currentPosition, duration);
        }
        long max = Math.max(currentPosition, 0L);
        int mo1367o = interfaceC2368q0.mo1367o();
        Objects.requireNonNull((C2403x) this.f9628L);
        interfaceC2368q0.mo1360g(mo1367o, max);
    }

    /* renamed from: i */
    public final void m4096i(boolean z, @Nullable View view) {
        if (view == null) {
            return;
        }
        view.setEnabled(z);
        view.setAlpha(z ? this.f9623G : this.f9624H);
        view.setVisibility(0);
    }

    /* renamed from: j */
    public final boolean m4097j() {
        InterfaceC2368q0 interfaceC2368q0 = this.f9627K;
        return (interfaceC2368q0 == null || interfaceC2368q0.mo1354a() == 4 || this.f9627K.mo1354a() == 1 || !this.f9627K.mo1361h()) ? false : true;
    }

    /* renamed from: k */
    public final void m4098k() {
        m4100m();
        m4099l();
        m4102o();
        m4103p();
        m4104q();
    }

    /* JADX WARN: Removed duplicated region for block: B:33:0x007d  */
    /* JADX WARN: Removed duplicated region for block: B:36:? A[RETURN, SYNTHETIC] */
    /* renamed from: l */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void m4099l() {
        /*
            r8 = this;
            boolean r0 = r8.m4091d()
            if (r0 == 0) goto L80
            boolean r0 = r8.f9631O
            if (r0 != 0) goto Lc
            goto L80
        Lc:
            b.l.a.a.q0 r0 = r8.f9627K
            r1 = 0
            if (r0 == 0) goto L61
            b.l.a.a.x0 r2 = r0.mo1375y()
            boolean r3 = r2.m2691q()
            if (r3 != 0) goto L61
            boolean r3 = r0.mo1356c()
            if (r3 != 0) goto L61
            int r3 = r0.mo1367o()
            b.l.a.a.x0$c r4 = r8.f9664v
            r2.m2690n(r3, r4)
            b.l.a.a.x0$c r2 = r8.f9664v
            boolean r3 = r2.f6376e
            r4 = 1
            if (r3 != 0) goto L3e
            boolean r2 = r2.f6377f
            if (r2 == 0) goto L3e
            boolean r2 = r0.hasPrevious()
            if (r2 == 0) goto L3c
            goto L3e
        L3c:
            r2 = 0
            goto L3f
        L3e:
            r2 = 1
        L3f:
            if (r3 == 0) goto L47
            int r5 = r8.f9635S
            if (r5 <= 0) goto L47
            r5 = 1
            goto L48
        L47:
            r5 = 0
        L48:
            if (r3 == 0) goto L50
            int r6 = r8.f9636T
            if (r6 <= 0) goto L50
            r6 = 1
            goto L51
        L50:
            r6 = 0
        L51:
            b.l.a.a.x0$c r7 = r8.f9664v
            boolean r7 = r7.f6377f
            if (r7 != 0) goto L5d
            boolean r0 = r0.hasNext()
            if (r0 == 0) goto L5e
        L5d:
            r1 = 1
        L5e:
            r0 = r1
            r1 = r2
            goto L65
        L61:
            r0 = 0
            r3 = 0
            r5 = 0
            r6 = 0
        L65:
            android.view.View r2 = r8.f9648g
            r8.m4096i(r1, r2)
            android.view.View r1 = r8.f9654l
            r8.m4096i(r5, r1)
            android.view.View r1 = r8.f9653k
            r8.m4096i(r6, r1)
            android.view.View r1 = r8.f9650h
            r8.m4096i(r0, r1)
            b.l.a.a.n1.f r0 = r8.f9660r
            if (r0 == 0) goto L80
            r0.setEnabled(r3)
        L80:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.exoplayer2.p395ui.PlayerControlView.m4099l():void");
    }

    /* renamed from: m */
    public final void m4100m() {
        boolean z;
        if (m4091d() && this.f9631O) {
            boolean m4097j = m4097j();
            View view = this.f9651i;
            if (view != null) {
                z = (m4097j && view.isFocused()) | false;
                this.f9651i.setVisibility(m4097j ? 8 : 0);
            } else {
                z = false;
            }
            View view2 = this.f9652j;
            if (view2 != null) {
                z |= !m4097j && view2.isFocused();
                this.f9652j.setVisibility(m4097j ? 0 : 8);
            }
            if (z) {
                m4094g();
            }
        }
    }

    /* renamed from: n */
    public final void m4101n() {
        long j2;
        if (m4091d() && this.f9631O) {
            InterfaceC2368q0 interfaceC2368q0 = this.f9627K;
            long j3 = 0;
            if (interfaceC2368q0 != null) {
                j3 = this.f9649g0 + interfaceC2368q0.mo1370r();
                j2 = this.f9649g0 + interfaceC2368q0.mo1341B();
            } else {
                j2 = 0;
            }
            TextView textView = this.f9659q;
            if (textView != null && !this.f9634R) {
                textView.setText(C2344d0.m2340r(this.f9661s, this.f9662t, j3));
            }
            InterfaceC2268f interfaceC2268f = this.f9660r;
            if (interfaceC2268f != null) {
                interfaceC2268f.setPosition(j3);
                this.f9660r.setBufferedPosition(j2);
            }
            InterfaceC3318c interfaceC3318c = this.f9629M;
            if (interfaceC3318c != null) {
                interfaceC3318c.m4105a(j3, j2);
            }
            removeCallbacks(this.f9665w);
            int mo1354a = interfaceC2368q0 == null ? 1 : interfaceC2368q0.mo1354a();
            if (interfaceC2368q0 == null || !interfaceC2368q0.isPlaying()) {
                if (mo1354a == 4 || mo1354a == 1) {
                    return;
                }
                postDelayed(this.f9665w, 1000L);
                return;
            }
            InterfaceC2268f interfaceC2268f2 = this.f9660r;
            long min = Math.min(interfaceC2268f2 != null ? interfaceC2268f2.getPreferredUpdateDelay() : 1000L, 1000 - (j3 % 1000));
            float f2 = interfaceC2368q0.mo1355b().f5669b;
            postDelayed(this.f9665w, C2344d0.m2330h(f2 > 0.0f ? (long) (min / f2) : 1000L, this.f9638V, 1000L));
        }
    }

    /* renamed from: o */
    public final void m4102o() {
        ImageView imageView;
        if (m4091d() && this.f9631O && (imageView = this.f9655m) != null) {
            if (this.f9639W == 0) {
                imageView.setVisibility(8);
                return;
            }
            InterfaceC2368q0 interfaceC2368q0 = this.f9627K;
            if (interfaceC2368q0 == null) {
                m4096i(false, imageView);
                this.f9655m.setImageDrawable(this.f9667y);
                this.f9655m.setContentDescription(this.f9618B);
                return;
            }
            m4096i(true, imageView);
            int mo1358e = interfaceC2368q0.mo1358e();
            if (mo1358e == 0) {
                this.f9655m.setImageDrawable(this.f9667y);
                this.f9655m.setContentDescription(this.f9618B);
            } else if (mo1358e == 1) {
                this.f9655m.setImageDrawable(this.f9668z);
                this.f9655m.setContentDescription(this.f9619C);
            } else if (mo1358e == 2) {
                this.f9655m.setImageDrawable(this.f9617A);
                this.f9655m.setContentDescription(this.f9620D);
            }
            this.f9655m.setVisibility(0);
        }
    }

    @Override // android.view.ViewGroup, android.view.View
    public void onAttachedToWindow() {
        super.onAttachedToWindow();
        this.f9631O = true;
        long j2 = this.f9641b0;
        if (j2 != -9223372036854775807L) {
            long uptimeMillis = j2 - SystemClock.uptimeMillis();
            if (uptimeMillis <= 0) {
                m4089b();
            } else {
                postDelayed(this.f9666x, uptimeMillis);
            }
        } else if (m4091d()) {
            m4090c();
        }
        m4098k();
    }

    @Override // android.view.ViewGroup, android.view.View
    public void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        this.f9631O = false;
        removeCallbacks(this.f9665w);
        removeCallbacks(this.f9666x);
    }

    /* renamed from: p */
    public final void m4103p() {
        ImageView imageView;
        if (m4091d() && this.f9631O && (imageView = this.f9656n) != null) {
            InterfaceC2368q0 interfaceC2368q0 = this.f9627K;
            if (!this.f9640a0) {
                imageView.setVisibility(8);
                return;
            }
            if (interfaceC2368q0 == null) {
                m4096i(false, imageView);
                this.f9656n.setImageDrawable(this.f9622F);
                this.f9656n.setContentDescription(this.f9626J);
            } else {
                m4096i(true, imageView);
                this.f9656n.setImageDrawable(interfaceC2368q0.mo1340A() ? this.f9621E : this.f9622F);
                this.f9656n.setContentDescription(interfaceC2368q0.mo1340A() ? this.f9625I : this.f9626J);
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:18:0x0039  */
    /* JADX WARN: Removed duplicated region for block: B:21:0x004c  */
    /* JADX WARN: Removed duplicated region for block: B:66:0x0127  */
    /* JADX WARN: Removed duplicated region for block: B:69:0x0136  */
    /* JADX WARN: Removed duplicated region for block: B:78:0x011d  */
    /* renamed from: q */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void m4104q() {
        /*
            Method dump skipped, instructions count: 365
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.exoplayer2.p395ui.PlayerControlView.m4104q():void");
    }

    public void setControlDispatcher(@Nullable InterfaceC2401w interfaceC2401w) {
        if (interfaceC2401w == null) {
            interfaceC2401w = new C2403x();
        }
        this.f9628L = interfaceC2401w;
    }

    public void setFastForwardIncrementMs(int i2) {
        this.f9636T = i2;
        m4099l();
    }

    public void setPlaybackPreparer(@Nullable InterfaceC2279o0 interfaceC2279o0) {
        this.f9630N = interfaceC2279o0;
    }

    public void setPlayer(@Nullable InterfaceC2368q0 interfaceC2368q0) {
        boolean z = true;
        C4195m.m4771I(Looper.myLooper() == Looper.getMainLooper());
        if (interfaceC2368q0 != null && interfaceC2368q0.mo1376z() != Looper.getMainLooper()) {
            z = false;
        }
        C4195m.m4765F(z);
        InterfaceC2368q0 interfaceC2368q02 = this.f9627K;
        if (interfaceC2368q02 == interfaceC2368q0) {
            return;
        }
        if (interfaceC2368q02 != null) {
            interfaceC2368q02.mo1366n(this.f9644e);
        }
        this.f9627K = interfaceC2368q0;
        if (interfaceC2368q0 != null) {
            interfaceC2368q0.mo1364l(this.f9644e);
        }
        m4098k();
    }

    public void setProgressUpdateListener(@Nullable InterfaceC3318c interfaceC3318c) {
        this.f9629M = interfaceC3318c;
    }

    public void setRepeatToggleModes(int i2) {
        this.f9639W = i2;
        InterfaceC2368q0 interfaceC2368q0 = this.f9627K;
        if (interfaceC2368q0 != null) {
            int mo1358e = interfaceC2368q0.mo1358e();
            if (i2 == 0 && mo1358e != 0) {
                InterfaceC2401w interfaceC2401w = this.f9628L;
                InterfaceC2368q0 interfaceC2368q02 = this.f9627K;
                Objects.requireNonNull((C2403x) interfaceC2401w);
                interfaceC2368q02.mo1357d(0);
            } else if (i2 == 1 && mo1358e == 2) {
                InterfaceC2401w interfaceC2401w2 = this.f9628L;
                InterfaceC2368q0 interfaceC2368q03 = this.f9627K;
                Objects.requireNonNull((C2403x) interfaceC2401w2);
                interfaceC2368q03.mo1357d(1);
            } else if (i2 == 2 && mo1358e == 1) {
                InterfaceC2401w interfaceC2401w3 = this.f9628L;
                InterfaceC2368q0 interfaceC2368q04 = this.f9627K;
                Objects.requireNonNull((C2403x) interfaceC2401w3);
                interfaceC2368q04.mo1357d(2);
            }
        }
        m4102o();
    }

    public void setRewindIncrementMs(int i2) {
        this.f9635S = i2;
        m4099l();
    }

    public void setShowMultiWindowTimeBar(boolean z) {
        this.f9632P = z;
        m4104q();
    }

    public void setShowShuffleButton(boolean z) {
        this.f9640a0 = z;
        m4103p();
    }

    public void setShowTimeoutMs(int i2) {
        this.f9637U = i2;
        if (m4091d()) {
            m4090c();
        }
    }

    public void setShowVrButton(boolean z) {
        View view = this.f9657o;
        if (view != null) {
            view.setVisibility(z ? 0 : 8);
        }
    }

    public void setTimeBarMinUpdateInterval(int i2) {
        this.f9638V = C2344d0.m2329g(i2, 16, 1000);
    }

    public void setVrButtonListener(@Nullable View.OnClickListener onClickListener) {
        View view = this.f9657o;
        if (view != null) {
            view.setOnClickListener(onClickListener);
        }
    }

    public PlayerControlView(Context context, @Nullable AttributeSet attributeSet) {
        this(context, attributeSet, 0);
    }

    public PlayerControlView(Context context, @Nullable AttributeSet attributeSet, int i2) {
        this(context, attributeSet, i2, attributeSet);
    }

    public PlayerControlView(Context context, @Nullable AttributeSet attributeSet, int i2, @Nullable AttributeSet attributeSet2) {
        super(context, attributeSet, i2);
        int i3 = R$layout.exo_player_control_view;
        this.f9635S = 5000;
        this.f9636T = 15000;
        this.f9637U = 5000;
        this.f9639W = 0;
        this.f9638V = 200;
        this.f9641b0 = -9223372036854775807L;
        this.f9640a0 = false;
        if (attributeSet2 != null) {
            TypedArray obtainStyledAttributes = context.getTheme().obtainStyledAttributes(attributeSet2, R$styleable.PlayerControlView, 0, 0);
            try {
                this.f9635S = obtainStyledAttributes.getInt(R$styleable.PlayerControlView_rewind_increment, this.f9635S);
                this.f9636T = obtainStyledAttributes.getInt(R$styleable.PlayerControlView_fastforward_increment, this.f9636T);
                this.f9637U = obtainStyledAttributes.getInt(R$styleable.PlayerControlView_show_timeout, this.f9637U);
                i3 = obtainStyledAttributes.getResourceId(R$styleable.PlayerControlView_controller_layout_id, i3);
                this.f9639W = obtainStyledAttributes.getInt(R$styleable.PlayerControlView_repeat_toggle_modes, this.f9639W);
                this.f9640a0 = obtainStyledAttributes.getBoolean(R$styleable.PlayerControlView_show_shuffle_button, this.f9640a0);
                setTimeBarMinUpdateInterval(obtainStyledAttributes.getInt(R$styleable.PlayerControlView_time_bar_min_update_interval, this.f9638V));
            } finally {
                obtainStyledAttributes.recycle();
            }
        }
        this.f9646f = new CopyOnWriteArrayList<>();
        this.f9663u = new AbstractC2404x0.b();
        this.f9664v = new AbstractC2404x0.c();
        StringBuilder sb = new StringBuilder();
        this.f9661s = sb;
        this.f9662t = new Formatter(sb, Locale.getDefault());
        this.f9642c0 = new long[0];
        this.f9643d0 = new boolean[0];
        this.f9645e0 = new long[0];
        this.f9647f0 = new boolean[0];
        ViewOnClickListenerC3317b viewOnClickListenerC3317b = new ViewOnClickListenerC3317b(null);
        this.f9644e = viewOnClickListenerC3317b;
        this.f9628L = new C2403x();
        this.f9665w = new Runnable() { // from class: b.l.a.a.n1.c
            @Override // java.lang.Runnable
            public final void run() {
                PlayerControlView playerControlView = PlayerControlView.this;
                int i4 = PlayerControlView.f9616c;
                playerControlView.m4101n();
            }
        };
        this.f9666x = new Runnable() { // from class: b.l.a.a.n1.a
            @Override // java.lang.Runnable
            public final void run() {
                PlayerControlView.this.m4089b();
            }
        };
        LayoutInflater.from(context).inflate(i3, this);
        setDescendantFocusability(262144);
        int i4 = R$id.exo_progress;
        InterfaceC2268f interfaceC2268f = (InterfaceC2268f) findViewById(i4);
        View findViewById = findViewById(R$id.exo_progress_placeholder);
        if (interfaceC2268f != null) {
            this.f9660r = interfaceC2268f;
        } else if (findViewById != null) {
            DefaultTimeBar defaultTimeBar = new DefaultTimeBar(context, null, 0, attributeSet2);
            defaultTimeBar.setId(i4);
            defaultTimeBar.setLayoutParams(findViewById.getLayoutParams());
            ViewGroup viewGroup = (ViewGroup) findViewById.getParent();
            int indexOfChild = viewGroup.indexOfChild(findViewById);
            viewGroup.removeView(findViewById);
            viewGroup.addView(defaultTimeBar, indexOfChild);
            this.f9660r = defaultTimeBar;
        } else {
            this.f9660r = null;
        }
        this.f9658p = (TextView) findViewById(R$id.exo_duration);
        this.f9659q = (TextView) findViewById(R$id.exo_position);
        InterfaceC2268f interfaceC2268f2 = this.f9660r;
        if (interfaceC2268f2 != null) {
            interfaceC2268f2.addListener(viewOnClickListenerC3317b);
        }
        View findViewById2 = findViewById(R$id.exo_play);
        this.f9651i = findViewById2;
        if (findViewById2 != null) {
            findViewById2.setOnClickListener(viewOnClickListenerC3317b);
        }
        View findViewById3 = findViewById(R$id.exo_pause);
        this.f9652j = findViewById3;
        if (findViewById3 != null) {
            findViewById3.setOnClickListener(viewOnClickListenerC3317b);
        }
        View findViewById4 = findViewById(R$id.exo_prev);
        this.f9648g = findViewById4;
        if (findViewById4 != null) {
            findViewById4.setOnClickListener(viewOnClickListenerC3317b);
        }
        View findViewById5 = findViewById(R$id.exo_next);
        this.f9650h = findViewById5;
        if (findViewById5 != null) {
            findViewById5.setOnClickListener(viewOnClickListenerC3317b);
        }
        View findViewById6 = findViewById(R$id.exo_rew);
        this.f9654l = findViewById6;
        if (findViewById6 != null) {
            findViewById6.setOnClickListener(viewOnClickListenerC3317b);
        }
        View findViewById7 = findViewById(R$id.exo_ffwd);
        this.f9653k = findViewById7;
        if (findViewById7 != null) {
            findViewById7.setOnClickListener(viewOnClickListenerC3317b);
        }
        ImageView imageView = (ImageView) findViewById(R$id.exo_repeat_toggle);
        this.f9655m = imageView;
        if (imageView != null) {
            imageView.setOnClickListener(viewOnClickListenerC3317b);
        }
        ImageView imageView2 = (ImageView) findViewById(R$id.exo_shuffle);
        this.f9656n = imageView2;
        if (imageView2 != null) {
            imageView2.setOnClickListener(viewOnClickListenerC3317b);
        }
        this.f9657o = findViewById(R$id.exo_vr);
        setShowVrButton(false);
        Resources resources = context.getResources();
        this.f9623G = resources.getInteger(R$integer.exo_media_button_opacity_percentage_enabled) / 100.0f;
        this.f9624H = resources.getInteger(R$integer.exo_media_button_opacity_percentage_disabled) / 100.0f;
        this.f9667y = resources.getDrawable(R$drawable.exo_controls_repeat_off);
        this.f9668z = resources.getDrawable(R$drawable.exo_controls_repeat_one);
        this.f9617A = resources.getDrawable(R$drawable.exo_controls_repeat_all);
        this.f9621E = resources.getDrawable(R$drawable.exo_controls_shuffle_on);
        this.f9622F = resources.getDrawable(R$drawable.exo_controls_shuffle_off);
        this.f9618B = resources.getString(R$string.exo_controls_repeat_off_description);
        this.f9619C = resources.getString(R$string.exo_controls_repeat_one_description);
        this.f9620D = resources.getString(R$string.exo_controls_repeat_all_description);
        this.f9625I = resources.getString(R$string.exo_controls_shuffle_on_description);
        this.f9626J = resources.getString(R$string.exo_controls_shuffle_off_description);
    }
}
