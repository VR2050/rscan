package com.google.android.exoplayer2.p395ui;

import android.R;
import android.content.Context;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Matrix;
import android.graphics.RectF;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.Drawable;
import android.os.Looper;
import android.util.AttributeSet;
import android.view.KeyEvent;
import android.view.LayoutInflater;
import android.view.MotionEvent;
import android.view.SurfaceHolder;
import android.view.SurfaceView;
import android.view.TextureView;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.annotation.Nullable;
import androidx.core.content.ContextCompat;
import com.google.android.exoplayer2.metadata.Metadata;
import com.google.android.exoplayer2.metadata.flac.PictureFrame;
import com.google.android.exoplayer2.metadata.id3.ApicFrame;
import com.google.android.exoplayer2.p395ui.AspectRatioFrameLayout;
import com.google.android.exoplayer2.p395ui.PlayerControlView;
import com.google.android.exoplayer2.p395ui.spherical.SphericalGLSurfaceView;
import com.google.android.exoplayer2.source.TrackGroupArray;
import com.google.android.exoplayer2.video.VideoDecoderGLSurfaceView;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import org.checkerframework.checker.nullness.qual.EnsuresNonNullIf;
import org.checkerframework.checker.nullness.qual.RequiresNonNull;
import p005b.p199l.p200a.p201a.AbstractC2404x0;
import p005b.p199l.p200a.p201a.C1936b0;
import p005b.p199l.p200a.p201a.C2262n0;
import p005b.p199l.p200a.p201a.C2336p0;
import p005b.p199l.p200a.p201a.C2402w0;
import p005b.p199l.p200a.p201a.InterfaceC2279o0;
import p005b.p199l.p200a.p201a.InterfaceC2368q0;
import p005b.p199l.p200a.p201a.InterfaceC2401w;
import p005b.p199l.p200a.p201a.p236l1.C2207b;
import p005b.p199l.p200a.p201a.p236l1.InterfaceC2216k;
import p005b.p199l.p200a.p201a.p245m1.C2258g;
import p005b.p199l.p200a.p201a.p245m1.InterfaceC2257f;
import p005b.p199l.p200a.p201a.p246n1.p247h.InterfaceC2276g;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p005b.p199l.p200a.p201a.p250p1.InterfaceC2351k;
import p005b.p199l.p200a.p201a.p251q1.C2384p;
import p005b.p199l.p200a.p201a.p251q1.InterfaceC2380l;
import p005b.p199l.p200a.p201a.p251q1.InterfaceC2385q;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* loaded from: classes.dex */
public class PlayerView extends FrameLayout {

    /* renamed from: c */
    public static final /* synthetic */ int f9670c = 0;

    /* renamed from: A */
    public boolean f9671A;

    /* renamed from: B */
    public boolean f9672B;

    /* renamed from: C */
    public int f9673C;

    /* renamed from: D */
    public boolean f9674D;

    /* renamed from: e */
    public final ViewOnLayoutChangeListenerC3321b f9675e;

    /* renamed from: f */
    @Nullable
    public final AspectRatioFrameLayout f9676f;

    /* renamed from: g */
    @Nullable
    public final View f9677g;

    /* renamed from: h */
    @Nullable
    public final View f9678h;

    /* renamed from: i */
    @Nullable
    public final ImageView f9679i;

    /* renamed from: j */
    @Nullable
    public final SubtitleView f9680j;

    /* renamed from: k */
    @Nullable
    public final View f9681k;

    /* renamed from: l */
    @Nullable
    public final TextView f9682l;

    /* renamed from: m */
    @Nullable
    public final PlayerControlView f9683m;

    /* renamed from: n */
    @Nullable
    public final FrameLayout f9684n;

    /* renamed from: o */
    @Nullable
    public final FrameLayout f9685o;

    /* renamed from: p */
    @Nullable
    public InterfaceC2368q0 f9686p;

    /* renamed from: q */
    public boolean f9687q;

    /* renamed from: r */
    @Nullable
    public PlayerControlView.InterfaceC3319d f9688r;

    /* renamed from: s */
    public boolean f9689s;

    /* renamed from: t */
    @Nullable
    public Drawable f9690t;

    /* renamed from: u */
    public int f9691u;

    /* renamed from: v */
    public boolean f9692v;

    /* renamed from: w */
    @Nullable
    public InterfaceC2351k<? super C1936b0> f9693w;

    /* renamed from: x */
    @Nullable
    public CharSequence f9694x;

    /* renamed from: y */
    public int f9695y;

    /* renamed from: z */
    public boolean f9696z;

    /* renamed from: com.google.android.exoplayer2.ui.PlayerView$b */
    public final class ViewOnLayoutChangeListenerC3321b implements InterfaceC2368q0.a, InterfaceC2216k, InterfaceC2385q, View.OnLayoutChangeListener, InterfaceC2276g, PlayerControlView.InterfaceC3319d {
        public ViewOnLayoutChangeListenerC3321b(C3320a c3320a) {
        }

        @Override // com.google.android.exoplayer2.p395ui.PlayerControlView.InterfaceC3319d
        /* renamed from: a */
        public void mo4106a(int i2) {
            PlayerView playerView = PlayerView.this;
            int i3 = PlayerView.f9670c;
            playerView.m4118l();
        }

        @Override // p005b.p199l.p200a.p201a.p251q1.InterfaceC2385q
        /* renamed from: b */
        public void mo2640b() {
            View view = PlayerView.this.f9677g;
            if (view != null) {
                view.setVisibility(4);
            }
        }

        @Override // p005b.p199l.p200a.p201a.p251q1.InterfaceC2385q
        /* renamed from: c */
        public /* synthetic */ void mo2641c(int i2, int i3) {
            C2384p.m2639a(this, i2, i3);
        }

        @Override // p005b.p199l.p200a.p201a.p236l1.InterfaceC2216k
        public void onCues(List<C2207b> list) {
            SubtitleView subtitleView = PlayerView.this.f9680j;
            if (subtitleView != null) {
                subtitleView.setCues(list);
            }
        }

        @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
        public /* synthetic */ void onIsPlayingChanged(boolean z) {
            C2336p0.m2285a(this, z);
        }

        @Override // android.view.View.OnLayoutChangeListener
        public void onLayoutChange(View view, int i2, int i3, int i4, int i5, int i6, int i7, int i8, int i9) {
            PlayerView.m4107a((TextureView) view, PlayerView.this.f9673C);
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
            PlayerView playerView = PlayerView.this;
            int i3 = PlayerView.f9670c;
            playerView.m4117k();
            PlayerView.this.m4119m();
            if (PlayerView.this.m4111e()) {
                PlayerView playerView2 = PlayerView.this;
                if (playerView2.f9671A) {
                    playerView2.m4110d();
                    return;
                }
            }
            PlayerView.this.m4112f(false);
        }

        @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
        public void onPositionDiscontinuity(int i2) {
            PlayerView playerView = PlayerView.this;
            int i3 = PlayerView.f9670c;
            if (playerView.m4111e()) {
                PlayerView playerView2 = PlayerView.this;
                if (playerView2.f9671A) {
                    playerView2.m4110d();
                }
            }
        }

        @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
        public /* synthetic */ void onRepeatModeChanged(int i2) {
            C2336p0.m2291g(this, i2);
        }

        @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
        public /* synthetic */ void onSeekProcessed() {
            C2336p0.m2292h(this);
        }

        @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
        public /* synthetic */ void onShuffleModeEnabledChanged(boolean z) {
            C2336p0.m2293i(this, z);
        }

        @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
        public /* synthetic */ void onTimelineChanged(AbstractC2404x0 abstractC2404x0, int i2) {
            C2336p0.m2294j(this, abstractC2404x0, i2);
        }

        @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
        public /* synthetic */ void onTimelineChanged(AbstractC2404x0 abstractC2404x0, Object obj, int i2) {
            C2336p0.m2295k(this, abstractC2404x0, obj, i2);
        }

        @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
        public void onTracksChanged(TrackGroupArray trackGroupArray, C2258g c2258g) {
            PlayerView playerView = PlayerView.this;
            int i2 = PlayerView.f9670c;
            playerView.m4120n(false);
        }

        @Override // p005b.p199l.p200a.p201a.p251q1.InterfaceC2385q
        public void onVideoSizeChanged(int i2, int i3, int i4, float f2) {
            float f3 = (i3 == 0 || i2 == 0) ? 1.0f : (i2 * f2) / i3;
            PlayerView playerView = PlayerView.this;
            View view = playerView.f9678h;
            if (view instanceof TextureView) {
                if (i4 == 90 || i4 == 270) {
                    f3 = 1.0f / f3;
                }
                if (playerView.f9673C != 0) {
                    view.removeOnLayoutChangeListener(this);
                }
                PlayerView playerView2 = PlayerView.this;
                playerView2.f9673C = i4;
                if (i4 != 0) {
                    playerView2.f9678h.addOnLayoutChangeListener(this);
                }
                PlayerView playerView3 = PlayerView.this;
                PlayerView.m4107a((TextureView) playerView3.f9678h, playerView3.f9673C);
            }
            PlayerView playerView4 = PlayerView.this;
            AspectRatioFrameLayout aspectRatioFrameLayout = playerView4.f9676f;
            View view2 = playerView4.f9678h;
            if (aspectRatioFrameLayout != null) {
                if (view2 instanceof SphericalGLSurfaceView) {
                    f3 = 0.0f;
                }
                aspectRatioFrameLayout.setAspectRatio(f3);
            }
        }
    }

    public PlayerView(Context context) {
        this(context, null);
    }

    /* renamed from: a */
    public static void m4107a(TextureView textureView, int i2) {
        Matrix matrix = new Matrix();
        float width = textureView.getWidth();
        float height = textureView.getHeight();
        if (width != 0.0f && height != 0.0f && i2 != 0) {
            float f2 = width / 2.0f;
            float f3 = height / 2.0f;
            matrix.postRotate(i2, f2, f3);
            RectF rectF = new RectF(0.0f, 0.0f, width, height);
            RectF rectF2 = new RectF();
            matrix.mapRect(rectF2, rectF);
            matrix.postScale(width / rectF2.width(), height / rectF2.height(), f2, f3);
        }
        textureView.setTransform(matrix);
    }

    /* renamed from: b */
    public final void m4108b() {
        View view = this.f9677g;
        if (view != null) {
            view.setVisibility(0);
        }
    }

    /* renamed from: c */
    public final void m4109c() {
        ImageView imageView = this.f9679i;
        if (imageView != null) {
            imageView.setImageResource(R.color.transparent);
            this.f9679i.setVisibility(4);
        }
    }

    /* renamed from: d */
    public void m4110d() {
        PlayerControlView playerControlView = this.f9683m;
        if (playerControlView != null) {
            playerControlView.m4089b();
        }
    }

    @Override // android.view.ViewGroup, android.view.View
    public boolean dispatchKeyEvent(KeyEvent keyEvent) {
        InterfaceC2368q0 interfaceC2368q0 = this.f9686p;
        if (interfaceC2368q0 != null && interfaceC2368q0.mo1356c()) {
            return super.dispatchKeyEvent(keyEvent);
        }
        int keyCode = keyEvent.getKeyCode();
        boolean z = keyCode == 19 || keyCode == 270 || keyCode == 22 || keyCode == 271 || keyCode == 20 || keyCode == 269 || keyCode == 21 || keyCode == 268 || keyCode == 23;
        if (z && m4121o() && !this.f9683m.m4091d()) {
            m4112f(true);
        } else {
            if (!(m4121o() && this.f9683m.m4088a(keyEvent)) && !super.dispatchKeyEvent(keyEvent)) {
                if (!z || !m4121o()) {
                    return false;
                }
                m4112f(true);
                return false;
            }
            m4112f(true);
        }
        return true;
    }

    /* renamed from: e */
    public final boolean m4111e() {
        InterfaceC2368q0 interfaceC2368q0 = this.f9686p;
        return interfaceC2368q0 != null && interfaceC2368q0.mo1356c() && this.f9686p.mo1361h();
    }

    /* renamed from: f */
    public final void m4112f(boolean z) {
        if (!(m4111e() && this.f9671A) && m4121o()) {
            boolean z2 = this.f9683m.m4091d() && this.f9683m.getShowTimeoutMs() <= 0;
            boolean m4114h = m4114h();
            if (z || z2 || m4114h) {
                m4115i(m4114h);
            }
        }
    }

    @RequiresNonNull({"artworkView"})
    /* renamed from: g */
    public final boolean m4113g(@Nullable Drawable drawable) {
        if (drawable != null) {
            int intrinsicWidth = drawable.getIntrinsicWidth();
            int intrinsicHeight = drawable.getIntrinsicHeight();
            if (intrinsicWidth > 0 && intrinsicHeight > 0) {
                float f2 = intrinsicWidth / intrinsicHeight;
                AspectRatioFrameLayout aspectRatioFrameLayout = this.f9676f;
                ImageView imageView = this.f9679i;
                if (aspectRatioFrameLayout != null) {
                    if (imageView instanceof SphericalGLSurfaceView) {
                        f2 = 0.0f;
                    }
                    aspectRatioFrameLayout.setAspectRatio(f2);
                }
                this.f9679i.setImageDrawable(drawable);
                this.f9679i.setVisibility(0);
                return true;
            }
        }
        return false;
    }

    public View[] getAdOverlayViews() {
        ArrayList arrayList = new ArrayList();
        FrameLayout frameLayout = this.f9685o;
        if (frameLayout != null) {
            arrayList.add(frameLayout);
        }
        PlayerControlView playerControlView = this.f9683m;
        if (playerControlView != null) {
            arrayList.add(playerControlView);
        }
        return (View[]) arrayList.toArray(new View[0]);
    }

    public ViewGroup getAdViewGroup() {
        FrameLayout frameLayout = this.f9684n;
        if (frameLayout != null) {
            return frameLayout;
        }
        throw new IllegalStateException("exo_ad_overlay must be present for ad playback");
    }

    public boolean getControllerAutoShow() {
        return this.f9696z;
    }

    public boolean getControllerHideOnTouch() {
        return this.f9672B;
    }

    public int getControllerShowTimeoutMs() {
        return this.f9695y;
    }

    @Nullable
    public Drawable getDefaultArtwork() {
        return this.f9690t;
    }

    @Nullable
    public FrameLayout getOverlayFrameLayout() {
        return this.f9685o;
    }

    @Nullable
    public InterfaceC2368q0 getPlayer() {
        return this.f9686p;
    }

    public int getResizeMode() {
        C4195m.m4775K(this.f9676f);
        return this.f9676f.getResizeMode();
    }

    @Nullable
    public SubtitleView getSubtitleView() {
        return this.f9680j;
    }

    public boolean getUseArtwork() {
        return this.f9689s;
    }

    public boolean getUseController() {
        return this.f9687q;
    }

    @Nullable
    public View getVideoSurfaceView() {
        return this.f9678h;
    }

    /* renamed from: h */
    public final boolean m4114h() {
        InterfaceC2368q0 interfaceC2368q0 = this.f9686p;
        if (interfaceC2368q0 == null) {
            return true;
        }
        int mo1354a = interfaceC2368q0.mo1354a();
        return this.f9696z && (mo1354a == 1 || mo1354a == 4 || !this.f9686p.mo1361h());
    }

    /* renamed from: i */
    public final void m4115i(boolean z) {
        if (m4121o()) {
            this.f9683m.setShowTimeoutMs(z ? 0 : this.f9695y);
            PlayerControlView playerControlView = this.f9683m;
            if (!playerControlView.m4091d()) {
                playerControlView.setVisibility(0);
                Iterator<PlayerControlView.InterfaceC3319d> it = playerControlView.f9646f.iterator();
                while (it.hasNext()) {
                    it.next().mo4106a(playerControlView.getVisibility());
                }
                playerControlView.m4098k();
                playerControlView.m4094g();
            }
            playerControlView.m4090c();
        }
    }

    /* renamed from: j */
    public final boolean m4116j() {
        if (!m4121o() || this.f9686p == null) {
            return false;
        }
        if (!this.f9683m.m4091d()) {
            m4112f(true);
        } else if (this.f9672B) {
            this.f9683m.m4089b();
        }
        return true;
    }

    /* renamed from: k */
    public final void m4117k() {
        int i2;
        if (this.f9681k != null) {
            InterfaceC2368q0 interfaceC2368q0 = this.f9686p;
            boolean z = true;
            if (interfaceC2368q0 == null || interfaceC2368q0.mo1354a() != 2 || ((i2 = this.f9691u) != 2 && (i2 != 1 || !this.f9686p.mo1361h()))) {
                z = false;
            }
            this.f9681k.setVisibility(z ? 0 : 8);
        }
    }

    /* renamed from: l */
    public final void m4118l() {
        PlayerControlView playerControlView = this.f9683m;
        if (playerControlView == null || !this.f9687q) {
            setContentDescription(null);
        } else if (playerControlView.getVisibility() == 0) {
            setContentDescription(this.f9672B ? getResources().getString(R$string.exo_controls_hide) : null);
        } else {
            setContentDescription(getResources().getString(R$string.exo_controls_show));
        }
    }

    /* renamed from: m */
    public final void m4119m() {
        InterfaceC2351k<? super C1936b0> interfaceC2351k;
        TextView textView = this.f9682l;
        if (textView != null) {
            CharSequence charSequence = this.f9694x;
            if (charSequence != null) {
                textView.setText(charSequence);
                this.f9682l.setVisibility(0);
                return;
            }
            InterfaceC2368q0 interfaceC2368q0 = this.f9686p;
            C1936b0 mo1363j = interfaceC2368q0 != null ? interfaceC2368q0.mo1363j() : null;
            if (mo1363j == null || (interfaceC2351k = this.f9693w) == null) {
                this.f9682l.setVisibility(8);
            } else {
                this.f9682l.setText((CharSequence) interfaceC2351k.m2362a(mo1363j).second);
                this.f9682l.setVisibility(0);
            }
        }
    }

    /* renamed from: n */
    public final void m4120n(boolean z) {
        byte[] bArr;
        int i2;
        InterfaceC2368q0 interfaceC2368q0 = this.f9686p;
        if (interfaceC2368q0 != null) {
            boolean z2 = true;
            if (!(interfaceC2368q0.mo1374x().f9397e == 0)) {
                if (z && !this.f9692v) {
                    m4108b();
                }
                C2258g mo1342C = interfaceC2368q0.mo1342C();
                for (int i3 = 0; i3 < mo1342C.f5659a; i3++) {
                    if (interfaceC2368q0.mo1343D(i3) == 2 && mo1342C.f5660b[i3] != null) {
                        m4109c();
                        return;
                    }
                }
                m4108b();
                if (this.f9689s) {
                    C4195m.m4775K(this.f9679i);
                } else {
                    z2 = false;
                }
                if (z2) {
                    for (int i4 = 0; i4 < mo1342C.f5659a; i4++) {
                        InterfaceC2257f interfaceC2257f = mo1342C.f5660b[i4];
                        if (interfaceC2257f != null) {
                            for (int i5 = 0; i5 < interfaceC2257f.length(); i5++) {
                                Metadata metadata = interfaceC2257f.mo2152e(i5).f9243j;
                                if (metadata != null) {
                                    int i6 = 0;
                                    int i7 = -1;
                                    boolean z3 = false;
                                    while (true) {
                                        Metadata.Entry[] entryArr = metadata.f9273c;
                                        if (i6 >= entryArr.length) {
                                            break;
                                        }
                                        Metadata.Entry entry = entryArr[i6];
                                        if (entry instanceof ApicFrame) {
                                            ApicFrame apicFrame = (ApicFrame) entry;
                                            bArr = apicFrame.f9304h;
                                            i2 = apicFrame.f9303g;
                                        } else if (entry instanceof PictureFrame) {
                                            PictureFrame pictureFrame = (PictureFrame) entry;
                                            bArr = pictureFrame.f9289k;
                                            i2 = pictureFrame.f9282c;
                                        } else {
                                            continue;
                                            i6++;
                                        }
                                        if (i7 == -1 || i2 == 3) {
                                            z3 = m4113g(new BitmapDrawable(getResources(), BitmapFactory.decodeByteArray(bArr, 0, bArr.length)));
                                            if (i2 == 3) {
                                                break;
                                            } else {
                                                i7 = i2;
                                            }
                                        }
                                        i6++;
                                    }
                                    if (z3) {
                                        return;
                                    }
                                }
                            }
                        }
                    }
                    if (m4113g(this.f9690t)) {
                        return;
                    }
                }
                m4109c();
                return;
            }
        }
        if (this.f9692v) {
            return;
        }
        m4109c();
        m4108b();
    }

    @EnsuresNonNullIf(expression = {"controller"}, result = true)
    /* renamed from: o */
    public final boolean m4121o() {
        if (!this.f9687q) {
            return false;
        }
        C4195m.m4775K(this.f9683m);
        return true;
    }

    @Override // android.view.View
    public boolean onTouchEvent(MotionEvent motionEvent) {
        if (!m4121o() || this.f9686p == null) {
            return false;
        }
        int action = motionEvent.getAction();
        if (action == 0) {
            this.f9674D = true;
            return true;
        }
        if (action != 1 || !this.f9674D) {
            return false;
        }
        this.f9674D = false;
        performClick();
        return true;
    }

    @Override // android.view.View
    public boolean onTrackballEvent(MotionEvent motionEvent) {
        if (!m4121o() || this.f9686p == null) {
            return false;
        }
        m4112f(true);
        return true;
    }

    @Override // android.view.View
    public boolean performClick() {
        super.performClick();
        return m4116j();
    }

    public void setAspectRatioListener(@Nullable AspectRatioFrameLayout.InterfaceC3314b interfaceC3314b) {
        C4195m.m4775K(this.f9676f);
        this.f9676f.setAspectRatioListener(interfaceC3314b);
    }

    public void setControlDispatcher(@Nullable InterfaceC2401w interfaceC2401w) {
        C4195m.m4775K(this.f9683m);
        this.f9683m.setControlDispatcher(interfaceC2401w);
    }

    public void setControllerAutoShow(boolean z) {
        this.f9696z = z;
    }

    public void setControllerHideDuringAds(boolean z) {
        this.f9671A = z;
    }

    public void setControllerHideOnTouch(boolean z) {
        C4195m.m4775K(this.f9683m);
        this.f9672B = z;
        m4118l();
    }

    public void setControllerShowTimeoutMs(int i2) {
        C4195m.m4775K(this.f9683m);
        this.f9695y = i2;
        if (this.f9683m.m4091d()) {
            m4115i(m4114h());
        }
    }

    public void setControllerVisibilityListener(@Nullable PlayerControlView.InterfaceC3319d interfaceC3319d) {
        C4195m.m4775K(this.f9683m);
        PlayerControlView.InterfaceC3319d interfaceC3319d2 = this.f9688r;
        if (interfaceC3319d2 == interfaceC3319d) {
            return;
        }
        if (interfaceC3319d2 != null) {
            this.f9683m.f9646f.remove(interfaceC3319d2);
        }
        this.f9688r = interfaceC3319d;
        if (interfaceC3319d != null) {
            this.f9683m.f9646f.add(interfaceC3319d);
        }
    }

    public void setCustomErrorMessage(@Nullable CharSequence charSequence) {
        C4195m.m4771I(this.f9682l != null);
        this.f9694x = charSequence;
        m4119m();
    }

    @Deprecated
    public void setDefaultArtwork(@Nullable Bitmap bitmap) {
        setDefaultArtwork(bitmap == null ? null : new BitmapDrawable(getResources(), bitmap));
    }

    public void setErrorMessageProvider(@Nullable InterfaceC2351k<? super C1936b0> interfaceC2351k) {
        if (this.f9693w != interfaceC2351k) {
            this.f9693w = interfaceC2351k;
            m4119m();
        }
    }

    public void setFastForwardIncrementMs(int i2) {
        C4195m.m4775K(this.f9683m);
        this.f9683m.setFastForwardIncrementMs(i2);
    }

    public void setKeepContentOnPlayerReset(boolean z) {
        if (this.f9692v != z) {
            this.f9692v = z;
            m4120n(false);
        }
    }

    public void setPlaybackPreparer(@Nullable InterfaceC2279o0 interfaceC2279o0) {
        C4195m.m4775K(this.f9683m);
        this.f9683m.setPlaybackPreparer(interfaceC2279o0);
    }

    public void setPlayer(@Nullable InterfaceC2368q0 interfaceC2368q0) {
        C4195m.m4771I(Looper.myLooper() == Looper.getMainLooper());
        C4195m.m4765F(interfaceC2368q0 == null || interfaceC2368q0.mo1376z() == Looper.getMainLooper());
        InterfaceC2368q0 interfaceC2368q02 = this.f9686p;
        if (interfaceC2368q02 == interfaceC2368q0) {
            return;
        }
        if (interfaceC2368q02 != null) {
            interfaceC2368q02.mo1366n(this.f9675e);
            InterfaceC2368q0.c mo1369q = interfaceC2368q02.mo1369q();
            if (mo1369q != null) {
                C2402w0 c2402w0 = (C2402w0) mo1369q;
                c2402w0.f6344f.remove(this.f9675e);
                View view = this.f9678h;
                if (view instanceof TextureView) {
                    TextureView textureView = (TextureView) view;
                    c2402w0.m2684U();
                    if (textureView != null && textureView == c2402w0.f6358t) {
                        c2402w0.m2681R(null);
                    }
                } else if (view instanceof SphericalGLSurfaceView) {
                    ((SphericalGLSurfaceView) view).setVideoComponent(null);
                } else if (view instanceof VideoDecoderGLSurfaceView) {
                    c2402w0.m2684U();
                    c2402w0.m2677N(null);
                } else if (view instanceof SurfaceView) {
                    SurfaceView surfaceView = (SurfaceView) view;
                    SurfaceHolder holder = surfaceView == null ? null : surfaceView.getHolder();
                    c2402w0.m2684U();
                    if (holder != null && holder == c2402w0.f6357s) {
                        c2402w0.m2679P(null);
                    }
                }
            }
            InterfaceC2368q0.b mo1344E = interfaceC2368q02.mo1344E();
            if (mo1344E != null) {
                ((C2402w0) mo1344E).f6346h.remove(this.f9675e);
            }
        }
        this.f9686p = interfaceC2368q0;
        if (m4121o()) {
            this.f9683m.setPlayer(interfaceC2368q0);
        }
        SubtitleView subtitleView = this.f9680j;
        if (subtitleView != null) {
            subtitleView.setCues(null);
        }
        m4117k();
        m4119m();
        m4120n(true);
        if (interfaceC2368q0 == null) {
            m4110d();
            return;
        }
        InterfaceC2368q0.c mo1369q2 = interfaceC2368q0.mo1369q();
        if (mo1369q2 != null) {
            View view2 = this.f9678h;
            if (view2 instanceof TextureView) {
                ((C2402w0) mo1369q2).m2681R((TextureView) view2);
            } else if (view2 instanceof SphericalGLSurfaceView) {
                ((SphericalGLSurfaceView) view2).setVideoComponent(mo1369q2);
            } else if (view2 instanceof VideoDecoderGLSurfaceView) {
                InterfaceC2380l videoDecoderOutputBufferRenderer = ((VideoDecoderGLSurfaceView) view2).getVideoDecoderOutputBufferRenderer();
                C2402w0 c2402w02 = (C2402w0) mo1369q2;
                c2402w02.m2684U();
                if (videoDecoderOutputBufferRenderer != null) {
                    c2402w02.m2684U();
                    c2402w02.m2674K();
                    c2402w02.m2680Q(null, false);
                    c2402w02.m2672I(0, 0);
                }
                c2402w02.m2677N(videoDecoderOutputBufferRenderer);
            } else if (view2 instanceof SurfaceView) {
                SurfaceView surfaceView2 = (SurfaceView) view2;
                ((C2402w0) mo1369q2).m2679P(surfaceView2 != null ? surfaceView2.getHolder() : null);
            }
            ((C2402w0) mo1369q2).f6344f.add(this.f9675e);
        }
        InterfaceC2368q0.b mo1344E2 = interfaceC2368q0.mo1344E();
        if (mo1344E2 != null) {
            ViewOnLayoutChangeListenerC3321b viewOnLayoutChangeListenerC3321b = this.f9675e;
            C2402w0 c2402w03 = (C2402w0) mo1344E2;
            if (!c2402w03.f6364z.isEmpty()) {
                viewOnLayoutChangeListenerC3321b.onCues(c2402w03.f6364z);
            }
            c2402w03.f6346h.add(viewOnLayoutChangeListenerC3321b);
        }
        interfaceC2368q0.mo1364l(this.f9675e);
        m4112f(false);
    }

    public void setRepeatToggleModes(int i2) {
        C4195m.m4775K(this.f9683m);
        this.f9683m.setRepeatToggleModes(i2);
    }

    public void setResizeMode(int i2) {
        C4195m.m4775K(this.f9676f);
        this.f9676f.setResizeMode(i2);
    }

    public void setRewindIncrementMs(int i2) {
        C4195m.m4775K(this.f9683m);
        this.f9683m.setRewindIncrementMs(i2);
    }

    @Deprecated
    public void setShowBuffering(boolean z) {
        setShowBuffering(z ? 1 : 0);
    }

    public void setShowMultiWindowTimeBar(boolean z) {
        C4195m.m4775K(this.f9683m);
        this.f9683m.setShowMultiWindowTimeBar(z);
    }

    public void setShowShuffleButton(boolean z) {
        C4195m.m4775K(this.f9683m);
        this.f9683m.setShowShuffleButton(z);
    }

    public void setShutterBackgroundColor(int i2) {
        View view = this.f9677g;
        if (view != null) {
            view.setBackgroundColor(i2);
        }
    }

    public void setUseArtwork(boolean z) {
        C4195m.m4771I((z && this.f9679i == null) ? false : true);
        if (this.f9689s != z) {
            this.f9689s = z;
            m4120n(false);
        }
    }

    public void setUseController(boolean z) {
        C4195m.m4771I((z && this.f9683m == null) ? false : true);
        if (this.f9687q == z) {
            return;
        }
        this.f9687q = z;
        if (m4121o()) {
            this.f9683m.setPlayer(this.f9686p);
        } else {
            PlayerControlView playerControlView = this.f9683m;
            if (playerControlView != null) {
                playerControlView.m4089b();
                this.f9683m.setPlayer(null);
            }
        }
        m4118l();
    }

    @Override // android.view.View
    public void setVisibility(int i2) {
        super.setVisibility(i2);
        View view = this.f9678h;
        if (view instanceof SurfaceView) {
            view.setVisibility(i2);
        }
    }

    public PlayerView(Context context, @Nullable AttributeSet attributeSet) {
        this(context, attributeSet, 0);
    }

    public void setShowBuffering(int i2) {
        if (this.f9691u != i2) {
            this.f9691u = i2;
            m4117k();
        }
    }

    public PlayerView(Context context, @Nullable AttributeSet attributeSet, int i2) {
        super(context, attributeSet, i2);
        int i3;
        int i4;
        int i5;
        boolean z;
        int i6;
        boolean z2;
        boolean z3;
        int i7;
        boolean z4;
        boolean z5;
        int i8;
        boolean z6;
        int i9;
        ViewOnLayoutChangeListenerC3321b viewOnLayoutChangeListenerC3321b = new ViewOnLayoutChangeListenerC3321b(null);
        this.f9675e = viewOnLayoutChangeListenerC3321b;
        if (isInEditMode()) {
            this.f9676f = null;
            this.f9677g = null;
            this.f9678h = null;
            this.f9679i = null;
            this.f9680j = null;
            this.f9681k = null;
            this.f9682l = null;
            this.f9683m = null;
            this.f9684n = null;
            this.f9685o = null;
            ImageView imageView = new ImageView(context);
            if (C2344d0.f6035a >= 23) {
                Resources resources = getResources();
                imageView.setImageDrawable(resources.getDrawable(R$drawable.exo_edit_mode_logo, null));
                imageView.setBackgroundColor(resources.getColor(R$color.exo_edit_mode_background_color, null));
            } else {
                Resources resources2 = getResources();
                imageView.setImageDrawable(resources2.getDrawable(R$drawable.exo_edit_mode_logo));
                imageView.setBackgroundColor(resources2.getColor(R$color.exo_edit_mode_background_color));
            }
            addView(imageView);
            return;
        }
        int i10 = R$layout.exo_player_view;
        if (attributeSet != null) {
            TypedArray obtainStyledAttributes = context.getTheme().obtainStyledAttributes(attributeSet, R$styleable.PlayerView, 0, 0);
            try {
                int i11 = R$styleable.PlayerView_shutter_background_color;
                boolean hasValue = obtainStyledAttributes.hasValue(i11);
                int color = obtainStyledAttributes.getColor(i11, 0);
                int resourceId = obtainStyledAttributes.getResourceId(R$styleable.PlayerView_player_layout_id, i10);
                boolean z7 = obtainStyledAttributes.getBoolean(R$styleable.PlayerView_use_artwork, true);
                int resourceId2 = obtainStyledAttributes.getResourceId(R$styleable.PlayerView_default_artwork, 0);
                boolean z8 = obtainStyledAttributes.getBoolean(R$styleable.PlayerView_use_controller, true);
                int i12 = obtainStyledAttributes.getInt(R$styleable.PlayerView_surface_type, 1);
                int i13 = obtainStyledAttributes.getInt(R$styleable.PlayerView_resize_mode, 0);
                int i14 = obtainStyledAttributes.getInt(R$styleable.PlayerView_show_timeout, 5000);
                boolean z9 = obtainStyledAttributes.getBoolean(R$styleable.PlayerView_hide_on_touch, true);
                boolean z10 = obtainStyledAttributes.getBoolean(R$styleable.PlayerView_auto_show, true);
                i6 = obtainStyledAttributes.getInteger(R$styleable.PlayerView_show_buffering, 0);
                this.f9692v = obtainStyledAttributes.getBoolean(R$styleable.PlayerView_keep_content_on_player_reset, this.f9692v);
                boolean z11 = obtainStyledAttributes.getBoolean(R$styleable.PlayerView_hide_during_ads, true);
                obtainStyledAttributes.recycle();
                z2 = z11;
                i3 = i12;
                i5 = i13;
                i8 = resourceId2;
                z6 = z8;
                z4 = hasValue;
                z5 = z7;
                z3 = z9;
                i7 = color;
                i4 = resourceId;
                i9 = i14;
                z = z10;
            } catch (Throwable th) {
                obtainStyledAttributes.recycle();
                throw th;
            }
        } else {
            i3 = 1;
            i4 = i10;
            i5 = 0;
            z = true;
            i6 = 0;
            z2 = true;
            z3 = true;
            i7 = 0;
            z4 = false;
            z5 = true;
            i8 = 0;
            z6 = true;
            i9 = 5000;
        }
        LayoutInflater.from(context).inflate(i4, this);
        setDescendantFocusability(262144);
        AspectRatioFrameLayout aspectRatioFrameLayout = (AspectRatioFrameLayout) findViewById(R$id.exo_content_frame);
        this.f9676f = aspectRatioFrameLayout;
        if (aspectRatioFrameLayout != null) {
            aspectRatioFrameLayout.setResizeMode(i5);
        }
        View findViewById = findViewById(R$id.exo_shutter);
        this.f9677g = findViewById;
        if (findViewById != null && z4) {
            findViewById.setBackgroundColor(i7);
        }
        if (aspectRatioFrameLayout != null && i3 != 0) {
            ViewGroup.LayoutParams layoutParams = new ViewGroup.LayoutParams(-1, -1);
            if (i3 == 2) {
                this.f9678h = new TextureView(context);
            } else if (i3 == 3) {
                SphericalGLSurfaceView sphericalGLSurfaceView = new SphericalGLSurfaceView(context);
                sphericalGLSurfaceView.setSingleTapListener(viewOnLayoutChangeListenerC3321b);
                this.f9678h = sphericalGLSurfaceView;
            } else if (i3 != 4) {
                this.f9678h = new SurfaceView(context);
            } else {
                this.f9678h = new VideoDecoderGLSurfaceView(context);
            }
            this.f9678h.setLayoutParams(layoutParams);
            aspectRatioFrameLayout.addView(this.f9678h, 0);
        } else {
            this.f9678h = null;
        }
        this.f9684n = (FrameLayout) findViewById(R$id.exo_ad_overlay);
        this.f9685o = (FrameLayout) findViewById(R$id.exo_overlay);
        ImageView imageView2 = (ImageView) findViewById(R$id.exo_artwork);
        this.f9679i = imageView2;
        this.f9689s = z5 && imageView2 != null;
        if (i8 != 0) {
            this.f9690t = ContextCompat.getDrawable(getContext(), i8);
        }
        SubtitleView subtitleView = (SubtitleView) findViewById(R$id.exo_subtitles);
        this.f9680j = subtitleView;
        if (subtitleView != null) {
            subtitleView.m4123b();
            subtitleView.m4124c();
        }
        View findViewById2 = findViewById(R$id.exo_buffering);
        this.f9681k = findViewById2;
        if (findViewById2 != null) {
            findViewById2.setVisibility(8);
        }
        this.f9691u = i6;
        TextView textView = (TextView) findViewById(R$id.exo_error_message);
        this.f9682l = textView;
        if (textView != null) {
            textView.setVisibility(8);
        }
        int i15 = R$id.exo_controller;
        PlayerControlView playerControlView = (PlayerControlView) findViewById(i15);
        View findViewById3 = findViewById(R$id.exo_controller_placeholder);
        if (playerControlView != null) {
            this.f9683m = playerControlView;
        } else if (findViewById3 != null) {
            PlayerControlView playerControlView2 = new PlayerControlView(context, null, 0, attributeSet);
            this.f9683m = playerControlView2;
            playerControlView2.setId(i15);
            playerControlView2.setLayoutParams(findViewById3.getLayoutParams());
            ViewGroup viewGroup = (ViewGroup) findViewById3.getParent();
            int indexOfChild = viewGroup.indexOfChild(findViewById3);
            viewGroup.removeView(findViewById3);
            viewGroup.addView(playerControlView2, indexOfChild);
        } else {
            this.f9683m = null;
        }
        PlayerControlView playerControlView3 = this.f9683m;
        this.f9695y = playerControlView3 != null ? i9 : 0;
        this.f9672B = z3;
        this.f9696z = z;
        this.f9671A = z2;
        this.f9687q = z6 && playerControlView3 != null;
        m4110d();
        m4118l();
        PlayerControlView playerControlView4 = this.f9683m;
        if (playerControlView4 != null) {
            playerControlView4.f9646f.add(viewOnLayoutChangeListenerC3321b);
        }
    }

    public void setDefaultArtwork(@Nullable Drawable drawable) {
        if (this.f9690t != drawable) {
            this.f9690t = drawable;
            m4120n(false);
        }
    }
}
