package android.support.v4.media.session;

import android.app.PendingIntent;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.media.MediaMetadata;
import android.media.session.MediaSession;
import android.media.session.PlaybackState;
import android.net.Uri;
import android.os.BadParcelableException;
import android.os.Binder;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import android.os.Parcel;
import android.os.Parcelable;
import android.os.RemoteCallbackList;
import android.os.RemoteException;
import android.os.ResultReceiver;
import android.os.SystemClock;
import android.support.v4.media.MediaDescriptionCompat;
import android.support.v4.media.MediaMetadataCompat;
import android.support.v4.media.RatingCompat;
import android.support.v4.media.session.PlaybackStateCompat;
import android.text.TextUtils;
import android.util.TypedValue;
import android.view.KeyEvent;
import android.view.ViewConfiguration;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;
import androidx.annotation.RestrictTo;
import androidx.core.app.BundleCompat;
import androidx.media.MediaSessionManager;
import androidx.media.session.MediaButtonReceiver;
import java.lang.ref.WeakReference;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import p005b.p131d.p132a.p133a.C1499a;
import p403d.p404a.p405a.p407b.p408a.C4187e;
import p403d.p404a.p405a.p407b.p408a.C4188f;
import p403d.p404a.p405a.p407b.p408a.C4190h;
import p403d.p404a.p405a.p407b.p408a.C4192j;
import p403d.p404a.p405a.p407b.p408a.C4194l;
import p403d.p404a.p405a.p407b.p408a.InterfaceC4183a;
import p403d.p404a.p405a.p407b.p408a.InterfaceC4184b;
import p403d.p404a.p405a.p407b.p408a.InterfaceC4189g;
import p403d.p404a.p405a.p407b.p408a.InterfaceC4191i;
import p403d.p404a.p405a.p407b.p408a.InterfaceC4193k;

/* loaded from: classes.dex */
public class MediaSessionCompat {

    /* renamed from: a */
    public static int f49a;

    /* renamed from: b */
    public final InterfaceC0025b f50b;

    /* renamed from: c */
    public final MediaControllerCompat f51c;

    /* renamed from: d */
    public final ArrayList<InterfaceC0028e> f52d = new ArrayList<>();

    @RestrictTo({RestrictTo.Scope.LIBRARY})
    public static final class ResultReceiverWrapper implements Parcelable {
        public static final Parcelable.Creator<ResultReceiverWrapper> CREATOR = new C0022a();

        /* renamed from: c */
        public ResultReceiver f56c;

        /* renamed from: android.support.v4.media.session.MediaSessionCompat$ResultReceiverWrapper$a */
        public static class C0022a implements Parcelable.Creator<ResultReceiverWrapper> {
            @Override // android.os.Parcelable.Creator
            public ResultReceiverWrapper createFromParcel(Parcel parcel) {
                return new ResultReceiverWrapper(parcel);
            }

            @Override // android.os.Parcelable.Creator
            public ResultReceiverWrapper[] newArray(int i2) {
                return new ResultReceiverWrapper[i2];
            }
        }

        public ResultReceiverWrapper(Parcel parcel) {
            this.f56c = (ResultReceiver) ResultReceiver.CREATOR.createFromParcel(parcel);
        }

        @Override // android.os.Parcelable
        public int describeContents() {
            return 0;
        }

        @Override // android.os.Parcelable
        public void writeToParcel(Parcel parcel, int i2) {
            this.f56c.writeToParcel(parcel, i2);
        }
    }

    /* renamed from: android.support.v4.media.session.MediaSessionCompat$a */
    public static abstract class AbstractC0024a {

        /* renamed from: a */
        public final Object f60a;

        /* renamed from: b */
        public WeakReference<InterfaceC0025b> f61b;

        /* renamed from: c */
        public a f62c = null;

        /* renamed from: d */
        public boolean f63d;

        /* renamed from: android.support.v4.media.session.MediaSessionCompat$a$a */
        public class a extends Handler {
            public a(Looper looper) {
                super(looper);
            }

            @Override // android.os.Handler
            public void handleMessage(Message message) {
                if (message.what == 1) {
                    AbstractC0024a.this.m28a((MediaSessionManager.RemoteUserInfo) message.obj);
                }
            }
        }

        @RequiresApi(21)
        /* renamed from: android.support.v4.media.session.MediaSessionCompat$a$b */
        public class b implements InterfaceC4189g {
            public b() {
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4189g
            /* renamed from: a */
            public void mo37a() {
                AbstractC0024a.this.mo33f();
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4189g
            /* renamed from: b */
            public void mo38b() {
                Objects.requireNonNull(AbstractC0024a.this);
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4189g
            /* renamed from: c */
            public void mo39c() {
                AbstractC0024a.this.mo30c();
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4189g
            /* renamed from: d */
            public void mo40d(String str, Bundle bundle, ResultReceiver resultReceiver) {
                try {
                    if (str.equals("android.support.v4.media.session.command.GET_EXTRA_BINDER")) {
                        C0026c c0026c = (C0026c) AbstractC0024a.this.f61b.get();
                        if (c0026c != null) {
                            Bundle bundle2 = new Bundle();
                            Token token = c0026c.f69b;
                            InterfaceC4184b interfaceC4184b = token.f58e;
                            BundleCompat.putBinder(bundle2, "android.support.v4.media.session.EXTRA_BINDER", interfaceC4184b == null ? null : interfaceC4184b.asBinder());
                            bundle2.putBundle("android.support.v4.media.session.SESSION_TOKEN2_BUNDLE", token.f59f);
                            resultReceiver.send(0, bundle2);
                            return;
                        }
                        return;
                    }
                    if (str.equals("android.support.v4.media.session.command.ADD_QUEUE_ITEM")) {
                        AbstractC0024a abstractC0024a = AbstractC0024a.this;
                        Objects.requireNonNull(abstractC0024a);
                        return;
                    }
                    if (str.equals("android.support.v4.media.session.command.ADD_QUEUE_ITEM_AT")) {
                        AbstractC0024a abstractC0024a2 = AbstractC0024a.this;
                        bundle.getInt("android.support.v4.media.session.command.ARGUMENT_INDEX");
                        Objects.requireNonNull(abstractC0024a2);
                        return;
                    }
                    if (str.equals("android.support.v4.media.session.command.REMOVE_QUEUE_ITEM")) {
                        AbstractC0024a abstractC0024a3 = AbstractC0024a.this;
                        Objects.requireNonNull(abstractC0024a3);
                    } else if (str.equals("android.support.v4.media.session.command.REMOVE_QUEUE_ITEM_AT")) {
                    } else {
                        Objects.requireNonNull(AbstractC0024a.this);
                    }
                } catch (BadParcelableException unused) {
                }
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4189g
            /* renamed from: e */
            public void mo41e(long j2) {
                Objects.requireNonNull(AbstractC0024a.this);
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4189g
            /* renamed from: f */
            public void mo42f(Object obj) {
                AbstractC0024a abstractC0024a = AbstractC0024a.this;
                RatingCompat.m13b(obj);
                Objects.requireNonNull(abstractC0024a);
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4189g
            /* renamed from: g */
            public void mo43g() {
                AbstractC0024a.this.mo31d();
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4189g
            /* renamed from: i */
            public void mo44i() {
                AbstractC0024a.this.mo34g();
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4189g
            /* renamed from: j */
            public boolean mo45j(Intent intent) {
                return AbstractC0024a.this.m29b(intent);
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4189g
            /* renamed from: m */
            public void mo46m(String str, Bundle bundle) {
                Objects.requireNonNull(AbstractC0024a.this);
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4189g
            /* renamed from: n */
            public void mo47n(String str, Bundle bundle) {
                Objects.requireNonNull(AbstractC0024a.this);
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4189g
            /* renamed from: o */
            public void mo48o() {
                Objects.requireNonNull(AbstractC0024a.this);
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4189g
            public void onStop() {
                AbstractC0024a.this.mo35h();
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4189g
            /* renamed from: p */
            public void mo49p(long j2) {
                AbstractC0024a.this.mo32e(j2);
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4189g
            /* renamed from: q */
            public void mo50q(String str, Bundle bundle) {
                MediaSessionCompat.m23a(bundle.getBundle("android.support.v4.media.session.action.ARGUMENT_EXTRAS"));
                if (str.equals("android.support.v4.media.session.action.PLAY_FROM_URI")) {
                    Objects.requireNonNull(AbstractC0024a.this);
                    return;
                }
                if (str.equals("android.support.v4.media.session.action.PREPARE")) {
                    Objects.requireNonNull(AbstractC0024a.this);
                    return;
                }
                if (str.equals("android.support.v4.media.session.action.PREPARE_FROM_MEDIA_ID")) {
                    bundle.getString("android.support.v4.media.session.action.ARGUMENT_MEDIA_ID");
                    Objects.requireNonNull(AbstractC0024a.this);
                    return;
                }
                if (str.equals("android.support.v4.media.session.action.PREPARE_FROM_SEARCH")) {
                    bundle.getString("android.support.v4.media.session.action.ARGUMENT_QUERY");
                    Objects.requireNonNull(AbstractC0024a.this);
                    return;
                }
                if (str.equals("android.support.v4.media.session.action.PREPARE_FROM_URI")) {
                    Objects.requireNonNull(AbstractC0024a.this);
                    return;
                }
                if (str.equals("android.support.v4.media.session.action.SET_CAPTIONING_ENABLED")) {
                    bundle.getBoolean("android.support.v4.media.session.action.ARGUMENT_CAPTIONING_ENABLED");
                    Objects.requireNonNull(AbstractC0024a.this);
                    return;
                }
                if (str.equals("android.support.v4.media.session.action.SET_REPEAT_MODE")) {
                    bundle.getInt("android.support.v4.media.session.action.ARGUMENT_REPEAT_MODE");
                    Objects.requireNonNull(AbstractC0024a.this);
                } else if (str.equals("android.support.v4.media.session.action.SET_SHUFFLE_MODE")) {
                    bundle.getInt("android.support.v4.media.session.action.ARGUMENT_SHUFFLE_MODE");
                    Objects.requireNonNull(AbstractC0024a.this);
                } else if (!str.equals("android.support.v4.media.session.action.SET_RATING")) {
                    Objects.requireNonNull(AbstractC0024a.this);
                } else {
                    Objects.requireNonNull(AbstractC0024a.this);
                }
            }
        }

        @RequiresApi(23)
        /* renamed from: android.support.v4.media.session.MediaSessionCompat$a$c */
        public class c extends b implements InterfaceC4191i {
            public c() {
                super();
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4191i
            /* renamed from: s */
            public void mo51s(Uri uri, Bundle bundle) {
                Objects.requireNonNull(AbstractC0024a.this);
            }
        }

        @RequiresApi(24)
        /* renamed from: android.support.v4.media.session.MediaSessionCompat$a$d */
        public class d extends c implements InterfaceC4193k {
            public d() {
                super();
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4193k
            /* renamed from: h */
            public void mo52h(String str, Bundle bundle) {
                Objects.requireNonNull(AbstractC0024a.this);
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4193k
            /* renamed from: k */
            public void mo53k() {
                Objects.requireNonNull(AbstractC0024a.this);
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4193k
            /* renamed from: l */
            public void mo54l(Uri uri, Bundle bundle) {
                Objects.requireNonNull(AbstractC0024a.this);
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4193k
            /* renamed from: r */
            public void mo55r(String str, Bundle bundle) {
                Objects.requireNonNull(AbstractC0024a.this);
            }
        }

        public AbstractC0024a() {
            int i2 = Build.VERSION.SDK_INT;
            if (i2 >= 24) {
                this.f60a = new C4194l(new d());
            } else if (i2 >= 23) {
                this.f60a = new C4192j(new c());
            } else {
                this.f60a = new C4190h(new b());
            }
        }

        /* renamed from: a */
        public void m28a(MediaSessionManager.RemoteUserInfo remoteUserInfo) {
            if (this.f63d) {
                this.f63d = false;
                this.f62c.removeMessages(1);
                InterfaceC0025b interfaceC0025b = this.f61b.get();
                if (interfaceC0025b == null) {
                    return;
                }
                PlaybackStateCompat mo56a = interfaceC0025b.mo56a();
                long j2 = mo56a == null ? 0L : mo56a.f84h;
                boolean z = mo56a != null && mo56a.f80c == 3;
                boolean z2 = (516 & j2) != 0;
                boolean z3 = (j2 & 514) != 0;
                interfaceC0025b.mo62g(remoteUserInfo);
                if (z && z3) {
                    mo30c();
                } else if (!z && z2) {
                    mo31d();
                }
                interfaceC0025b.mo62g(null);
            }
        }

        /* renamed from: b */
        public boolean m29b(Intent intent) {
            InterfaceC0025b interfaceC0025b;
            KeyEvent keyEvent;
            if (Build.VERSION.SDK_INT >= 27 || (interfaceC0025b = this.f61b.get()) == null || this.f62c == null || (keyEvent = (KeyEvent) intent.getParcelableExtra("android.intent.extra.KEY_EVENT")) == null || keyEvent.getAction() != 0) {
                return false;
            }
            MediaSessionManager.RemoteUserInfo mo64i = interfaceC0025b.mo64i();
            int keyCode = keyEvent.getKeyCode();
            if (keyCode != 79 && keyCode != 85) {
                m28a(mo64i);
                return false;
            }
            if (keyEvent.getRepeatCount() > 0) {
                m28a(mo64i);
            } else if (this.f63d) {
                this.f62c.removeMessages(1);
                this.f63d = false;
                PlaybackStateCompat mo56a = interfaceC0025b.mo56a();
                if (((mo56a == null ? 0L : mo56a.f84h) & 32) != 0) {
                    mo33f();
                }
            } else {
                this.f63d = true;
                a aVar = this.f62c;
                aVar.sendMessageDelayed(aVar.obtainMessage(1, mo64i), ViewConfiguration.getDoubleTapTimeout());
            }
            return true;
        }

        /* renamed from: c */
        public void mo30c() {
        }

        /* renamed from: d */
        public void mo31d() {
        }

        /* renamed from: e */
        public void mo32e(long j2) {
        }

        /* renamed from: f */
        public void mo33f() {
        }

        /* renamed from: g */
        public void mo34g() {
        }

        /* renamed from: h */
        public void mo35h() {
        }

        /* renamed from: i */
        public void m36i(InterfaceC0025b interfaceC0025b, Handler handler) {
            this.f61b = new WeakReference<>(interfaceC0025b);
            a aVar = this.f62c;
            if (aVar != null) {
                aVar.removeCallbacksAndMessages(null);
            }
            this.f62c = new a(handler.getLooper());
        }
    }

    /* renamed from: android.support.v4.media.session.MediaSessionCompat$b */
    public interface InterfaceC0025b {
        /* renamed from: a */
        PlaybackStateCompat mo56a();

        /* renamed from: b */
        Token mo57b();

        /* renamed from: c */
        void mo58c(AbstractC0024a abstractC0024a, Handler handler);

        /* renamed from: d */
        void mo59d(MediaMetadataCompat mediaMetadataCompat);

        /* renamed from: e */
        void mo60e(int i2);

        /* renamed from: f */
        void mo61f(boolean z);

        /* renamed from: g */
        void mo62g(MediaSessionManager.RemoteUserInfo remoteUserInfo);

        /* renamed from: h */
        void mo63h(PlaybackStateCompat playbackStateCompat);

        /* renamed from: i */
        MediaSessionManager.RemoteUserInfo mo64i();

        void release();
    }

    @RequiresApi(21)
    /* renamed from: android.support.v4.media.session.MediaSessionCompat$c */
    public static class C0026c implements InterfaceC0025b {

        /* renamed from: a */
        public final Object f68a;

        /* renamed from: b */
        public final Token f69b;

        /* renamed from: c */
        public boolean f70c = false;

        /* renamed from: d */
        public final RemoteCallbackList<InterfaceC4183a> f71d = new RemoteCallbackList<>();

        /* renamed from: e */
        public PlaybackStateCompat f72e;

        /* renamed from: f */
        public MediaMetadataCompat f73f;

        /* renamed from: android.support.v4.media.session.MediaSessionCompat$c$a */
        public class a extends InterfaceC4184b.a {
            public a() {
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4184b
            /* renamed from: A */
            public void mo66A(Uri uri, Bundle bundle) {
                throw new AssertionError();
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4184b
            /* renamed from: B */
            public boolean mo67B(KeyEvent keyEvent) {
                throw new AssertionError();
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4184b
            /* renamed from: D */
            public void mo68D(int i2, int i3, String str) {
                throw new AssertionError();
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4184b
            /* renamed from: E */
            public void mo69E(RatingCompat ratingCompat, Bundle bundle) {
                throw new AssertionError();
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4184b
            /* renamed from: G */
            public void mo70G(MediaDescriptionCompat mediaDescriptionCompat, int i2) {
                throw new AssertionError();
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4184b
            /* renamed from: I */
            public void mo71I(boolean z) {
                throw new AssertionError();
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4184b
            /* renamed from: J */
            public int mo72J() {
                Objects.requireNonNull(C0026c.this);
                return 0;
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4184b
            /* renamed from: K */
            public void mo73K(int i2) {
                throw new AssertionError();
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4184b
            /* renamed from: L */
            public boolean mo74L() {
                Objects.requireNonNull(C0026c.this);
                return false;
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4184b
            /* renamed from: M */
            public void mo75M() {
                throw new AssertionError();
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4184b
            /* renamed from: N */
            public void mo76N(String str, Bundle bundle, ResultReceiverWrapper resultReceiverWrapper) {
                throw new AssertionError();
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4184b
            /* renamed from: O */
            public List<QueueItem> mo77O() {
                return null;
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4184b
            /* renamed from: P */
            public void mo78P() {
                throw new AssertionError();
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4184b
            /* renamed from: Q */
            public void mo79Q(long j2) {
                throw new AssertionError();
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4184b
            /* renamed from: R */
            public void mo80R(boolean z) {
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4184b
            /* renamed from: S */
            public ParcelableVolumeInfo mo81S() {
                throw new AssertionError();
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4184b
            /* renamed from: T */
            public void mo82T(int i2) {
                throw new AssertionError();
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4184b
            /* renamed from: a */
            public PlaybackStateCompat mo83a() {
                C0026c c0026c = C0026c.this;
                return MediaSessionCompat.m24b(c0026c.f72e, c0026c.f73f);
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4184b
            /* renamed from: b */
            public void mo84b() {
                throw new AssertionError();
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4184b
            /* renamed from: c */
            public String mo85c() {
                throw new AssertionError();
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4184b
            /* renamed from: d */
            public void mo86d(int i2) {
                throw new AssertionError();
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4184b
            /* renamed from: e */
            public int mo87e() {
                Objects.requireNonNull(C0026c.this);
                return 0;
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4184b
            /* renamed from: f */
            public void mo88f(String str, Bundle bundle) {
                throw new AssertionError();
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4184b
            /* renamed from: g */
            public void mo89g(InterfaceC4183a interfaceC4183a) {
                C0026c c0026c = C0026c.this;
                if (c0026c.f70c) {
                    return;
                }
                Objects.requireNonNull(c0026c);
                String str = null;
                if (Build.VERSION.SDK_INT >= 24) {
                    MediaSession mediaSession = (MediaSession) c0026c.f68a;
                    try {
                        str = (String) mediaSession.getClass().getMethod("getCallingPackage", new Class[0]).invoke(mediaSession, new Object[0]);
                    } catch (IllegalAccessException | NoSuchMethodException | InvocationTargetException unused) {
                    }
                }
                if (str == null) {
                    str = MediaSessionManager.RemoteUserInfo.LEGACY_CONTROLLER;
                }
                C0026c.this.f71d.register(interfaceC4183a, new MediaSessionManager.RemoteUserInfo(str, Binder.getCallingPid(), Binder.getCallingUid()));
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4184b
            public Bundle getExtras() {
                throw new AssertionError();
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4184b
            public long getFlags() {
                throw new AssertionError();
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4184b
            public String getPackageName() {
                throw new AssertionError();
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4184b
            /* renamed from: h */
            public boolean mo90h() {
                return false;
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4184b
            /* renamed from: i */
            public void mo91i(RatingCompat ratingCompat) {
                throw new AssertionError();
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4184b
            /* renamed from: j */
            public void mo92j(int i2, int i3, String str) {
                throw new AssertionError();
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4184b
            /* renamed from: k */
            public void mo93k(Uri uri, Bundle bundle) {
                throw new AssertionError();
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4184b
            /* renamed from: l */
            public void mo94l(MediaDescriptionCompat mediaDescriptionCompat) {
                throw new AssertionError();
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4184b
            /* renamed from: m */
            public boolean mo95m() {
                throw new AssertionError();
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4184b
            /* renamed from: n */
            public void mo96n(MediaDescriptionCompat mediaDescriptionCompat) {
                throw new AssertionError();
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4184b
            public void next() {
                throw new AssertionError();
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4184b
            /* renamed from: o */
            public PendingIntent mo97o() {
                throw new AssertionError();
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4184b
            /* renamed from: p */
            public int mo98p() {
                Objects.requireNonNull(C0026c.this);
                return 0;
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4184b
            public void pause() {
                throw new AssertionError();
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4184b
            public void previous() {
                throw new AssertionError();
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4184b
            /* renamed from: q */
            public void mo99q(String str, Bundle bundle) {
                throw new AssertionError();
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4184b
            public void seekTo(long j2) {
                throw new AssertionError();
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4184b
            public void stop() {
                throw new AssertionError();
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4184b
            /* renamed from: t */
            public CharSequence mo100t() {
                throw new AssertionError();
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4184b
            /* renamed from: u */
            public MediaMetadataCompat mo101u() {
                throw new AssertionError();
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4184b
            /* renamed from: v */
            public void mo102v(String str, Bundle bundle) {
                throw new AssertionError();
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4184b
            /* renamed from: w */
            public void mo103w(InterfaceC4183a interfaceC4183a) {
                C0026c.this.f71d.unregister(interfaceC4183a);
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4184b
            /* renamed from: x */
            public void mo104x(String str, Bundle bundle) {
                throw new AssertionError();
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4184b
            /* renamed from: y */
            public void mo105y(String str, Bundle bundle) {
                throw new AssertionError();
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4184b
            /* renamed from: z */
            public void mo106z() {
                throw new AssertionError();
            }
        }

        public C0026c(Context context, String str, Bundle bundle) {
            MediaSession mediaSession = new MediaSession(context, str);
            this.f68a = mediaSession;
            this.f69b = new Token(mediaSession.getSessionToken(), new a(), bundle);
        }

        @Override // android.support.v4.media.session.MediaSessionCompat.InterfaceC0025b
        /* renamed from: a */
        public PlaybackStateCompat mo56a() {
            return this.f72e;
        }

        @Override // android.support.v4.media.session.MediaSessionCompat.InterfaceC0025b
        /* renamed from: b */
        public Token mo57b() {
            return this.f69b;
        }

        @Override // android.support.v4.media.session.MediaSessionCompat.InterfaceC0025b
        /* renamed from: c */
        public void mo58c(AbstractC0024a abstractC0024a, Handler handler) {
            ((MediaSession) this.f68a).setCallback((MediaSession.Callback) (abstractC0024a == null ? null : abstractC0024a.f60a), handler);
            if (abstractC0024a != null) {
                abstractC0024a.m36i(this, handler);
            }
        }

        @Override // android.support.v4.media.session.MediaSessionCompat.InterfaceC0025b
        /* renamed from: d */
        public void mo59d(MediaMetadataCompat mediaMetadataCompat) {
            Object obj;
            this.f73f = mediaMetadataCompat;
            Object obj2 = this.f68a;
            if (mediaMetadataCompat == null) {
                obj = null;
            } else {
                if (mediaMetadataCompat.f33f == null) {
                    Parcel obtain = Parcel.obtain();
                    obtain.writeBundle(mediaMetadataCompat.f32e);
                    obtain.setDataPosition(0);
                    mediaMetadataCompat.f33f = MediaMetadata.CREATOR.createFromParcel(obtain);
                    obtain.recycle();
                }
                obj = mediaMetadataCompat.f33f;
            }
            ((MediaSession) obj2).setMetadata((MediaMetadata) obj);
        }

        @Override // android.support.v4.media.session.MediaSessionCompat.InterfaceC0025b
        /* renamed from: e */
        public void mo60e(int i2) {
            ((MediaSession) this.f68a).setFlags(i2);
        }

        @Override // android.support.v4.media.session.MediaSessionCompat.InterfaceC0025b
        /* renamed from: f */
        public void mo61f(boolean z) {
            ((MediaSession) this.f68a).setActive(z);
        }

        @Override // android.support.v4.media.session.MediaSessionCompat.InterfaceC0025b
        /* renamed from: g */
        public void mo62g(MediaSessionManager.RemoteUserInfo remoteUserInfo) {
        }

        @Override // android.support.v4.media.session.MediaSessionCompat.InterfaceC0025b
        /* renamed from: h */
        public void mo63h(PlaybackStateCompat playbackStateCompat) {
            Object obj;
            PlaybackStateCompat playbackStateCompat2 = playbackStateCompat;
            this.f72e = playbackStateCompat2;
            for (int beginBroadcast = this.f71d.beginBroadcast() - 1; beginBroadcast >= 0; beginBroadcast--) {
                try {
                    this.f71d.getBroadcastItem(beginBroadcast).mo22U(playbackStateCompat2);
                } catch (RemoteException unused) {
                }
            }
            this.f71d.finishBroadcast();
            Object obj2 = this.f68a;
            ArrayList arrayList = null;
            Object obj3 = null;
            if (playbackStateCompat2 == null) {
                obj = obj2;
            } else {
                if (playbackStateCompat2.f91o == null) {
                    if (playbackStateCompat2.f88l != null) {
                        arrayList = new ArrayList(playbackStateCompat2.f88l.size());
                        for (PlaybackStateCompat.CustomAction customAction : playbackStateCompat2.f88l) {
                            Object obj4 = customAction.f96h;
                            if (obj4 == null) {
                                String str = customAction.f92c;
                                CharSequence charSequence = customAction.f93e;
                                int i2 = customAction.f94f;
                                Bundle bundle = customAction.f95g;
                                PlaybackState.CustomAction.Builder builder = new PlaybackState.CustomAction.Builder(str, charSequence, i2);
                                builder.setExtras(bundle);
                                obj4 = builder.build();
                                customAction.f96h = obj4;
                            }
                            arrayList.add(obj4);
                        }
                    }
                    if (Build.VERSION.SDK_INT >= 22) {
                        int i3 = playbackStateCompat2.f80c;
                        long j2 = playbackStateCompat2.f81e;
                        long j3 = playbackStateCompat2.f82f;
                        float f2 = playbackStateCompat2.f83g;
                        long j4 = playbackStateCompat2.f84h;
                        CharSequence charSequence2 = playbackStateCompat2.f86j;
                        long j5 = playbackStateCompat2.f87k;
                        obj = obj2;
                        long j6 = playbackStateCompat2.f89m;
                        Bundle bundle2 = playbackStateCompat2.f90n;
                        PlaybackState.Builder builder2 = new PlaybackState.Builder();
                        builder2.setState(i3, j2, f2, j5);
                        builder2.setBufferedPosition(j3);
                        builder2.setActions(j4);
                        builder2.setErrorMessage(charSequence2);
                        Iterator it = arrayList.iterator();
                        while (it.hasNext()) {
                            builder2.addCustomAction((PlaybackState.CustomAction) it.next());
                        }
                        builder2.setActiveQueueItemId(j6);
                        builder2.setExtras(bundle2);
                        playbackStateCompat2 = playbackStateCompat;
                        playbackStateCompat2.f91o = builder2.build();
                    } else {
                        obj = obj2;
                        ArrayList arrayList2 = arrayList;
                        int i4 = playbackStateCompat2.f80c;
                        long j7 = playbackStateCompat2.f81e;
                        long j8 = playbackStateCompat2.f82f;
                        float f3 = playbackStateCompat2.f83g;
                        long j9 = playbackStateCompat2.f84h;
                        CharSequence charSequence3 = playbackStateCompat2.f86j;
                        long j10 = playbackStateCompat2.f87k;
                        long j11 = playbackStateCompat2.f89m;
                        PlaybackState.Builder builder3 = new PlaybackState.Builder();
                        builder3.setState(i4, j7, f3, j10);
                        builder3.setBufferedPosition(j8);
                        builder3.setActions(j9);
                        builder3.setErrorMessage(charSequence3);
                        Iterator it2 = arrayList2.iterator();
                        while (it2.hasNext()) {
                            builder3.addCustomAction((PlaybackState.CustomAction) it2.next());
                        }
                        builder3.setActiveQueueItemId(j11);
                        playbackStateCompat2.f91o = builder3.build();
                    }
                } else {
                    obj = obj2;
                }
                obj3 = playbackStateCompat2.f91o;
            }
            ((MediaSession) obj).setPlaybackState((PlaybackState) obj3);
        }

        @Override // android.support.v4.media.session.MediaSessionCompat.InterfaceC0025b
        /* renamed from: i */
        public MediaSessionManager.RemoteUserInfo mo64i() {
            return null;
        }

        /* renamed from: j */
        public void m65j(PendingIntent pendingIntent) {
            ((MediaSession) this.f68a).setMediaButtonReceiver(pendingIntent);
        }

        @Override // android.support.v4.media.session.MediaSessionCompat.InterfaceC0025b
        public void release() {
            this.f70c = true;
            ((MediaSession) this.f68a).release();
        }
    }

    @RequiresApi(28)
    /* renamed from: android.support.v4.media.session.MediaSessionCompat$d */
    public static class C0027d extends C0026c {
        public C0027d(Context context, String str, Bundle bundle) {
            super(context, str, bundle);
        }

        @Override // android.support.v4.media.session.MediaSessionCompat.C0026c, android.support.v4.media.session.MediaSessionCompat.InterfaceC0025b
        /* renamed from: g */
        public void mo62g(MediaSessionManager.RemoteUserInfo remoteUserInfo) {
        }

        @Override // android.support.v4.media.session.MediaSessionCompat.C0026c, android.support.v4.media.session.MediaSessionCompat.InterfaceC0025b
        @NonNull
        /* renamed from: i */
        public final MediaSessionManager.RemoteUserInfo mo64i() {
            return new MediaSessionManager.RemoteUserInfo(((MediaSession) this.f68a).getCurrentControllerInfo());
        }
    }

    /* renamed from: android.support.v4.media.session.MediaSessionCompat$e */
    public interface InterfaceC0028e {
        /* renamed from: a */
        void m107a();
    }

    public MediaSessionCompat(Context context, String str) {
        PendingIntent pendingIntent;
        if (context == null) {
            throw new IllegalArgumentException("context must not be null");
        }
        if (TextUtils.isEmpty(str)) {
            throw new IllegalArgumentException("tag must not be null or empty");
        }
        ComponentName mediaButtonReceiverComponent = MediaButtonReceiver.getMediaButtonReceiverComponent(context);
        if (mediaButtonReceiverComponent != null) {
            Intent intent = new Intent("android.intent.action.MEDIA_BUTTON");
            intent.setComponent(mediaButtonReceiverComponent);
            pendingIntent = PendingIntent.getBroadcast(context, 0, intent, 0);
        } else {
            pendingIntent = null;
        }
        if (Build.VERSION.SDK_INT >= 28) {
            C0027d c0027d = new C0027d(context, str, null);
            this.f50b = c0027d;
            m26d(new C4187e(this));
            c0027d.m65j(pendingIntent);
        } else {
            C0026c c0026c = new C0026c(context, str, null);
            this.f50b = c0026c;
            m26d(new C4188f(this));
            c0026c.m65j(pendingIntent);
        }
        this.f51c = new MediaControllerCompat(context, this);
        if (f49a == 0) {
            f49a = (int) (TypedValue.applyDimension(1, 320.0f, context.getResources().getDisplayMetrics()) + 0.5f);
        }
    }

    @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
    /* renamed from: a */
    public static void m23a(@Nullable Bundle bundle) {
        if (bundle != null) {
            bundle.setClassLoader(MediaSessionCompat.class.getClassLoader());
        }
    }

    /* renamed from: b */
    public static PlaybackStateCompat m24b(PlaybackStateCompat playbackStateCompat, MediaMetadataCompat mediaMetadataCompat) {
        if (playbackStateCompat == null) {
            return playbackStateCompat;
        }
        long j2 = -1;
        if (playbackStateCompat.f81e == -1) {
            return playbackStateCompat;
        }
        int i2 = playbackStateCompat.f80c;
        if (i2 != 3 && i2 != 4 && i2 != 5) {
            return playbackStateCompat;
        }
        if (playbackStateCompat.f87k <= 0) {
            return playbackStateCompat;
        }
        long elapsedRealtime = SystemClock.elapsedRealtime();
        long j3 = ((long) (playbackStateCompat.f83g * (elapsedRealtime - r2))) + playbackStateCompat.f81e;
        if (mediaMetadataCompat != null && mediaMetadataCompat.f32e.containsKey("android.media.metadata.DURATION")) {
            j2 = mediaMetadataCompat.f32e.getLong("android.media.metadata.DURATION", 0L);
        }
        long j4 = (j2 < 0 || j3 <= j2) ? j3 < 0 ? 0L : j3 : j2;
        ArrayList arrayList = new ArrayList();
        long j5 = playbackStateCompat.f82f;
        long j6 = playbackStateCompat.f84h;
        int i3 = playbackStateCompat.f85i;
        CharSequence charSequence = playbackStateCompat.f86j;
        List<PlaybackStateCompat.CustomAction> list = playbackStateCompat.f88l;
        if (list != null) {
            arrayList.addAll(list);
        }
        return new PlaybackStateCompat(playbackStateCompat.f80c, j4, j5, playbackStateCompat.f83g, j6, i3, charSequence, elapsedRealtime, arrayList, playbackStateCompat.f89m, playbackStateCompat.f90n);
    }

    public void addOnActiveChangeListener(InterfaceC0028e interfaceC0028e) {
        if (interfaceC0028e == null) {
            throw new IllegalArgumentException("Listener may not be null");
        }
        this.f52d.add(interfaceC0028e);
    }

    /* renamed from: c */
    public void m25c(boolean z) {
        this.f50b.mo61f(z);
        Iterator<InterfaceC0028e> it = this.f52d.iterator();
        while (it.hasNext()) {
            it.next().m107a();
        }
    }

    /* renamed from: d */
    public void m26d(AbstractC0024a abstractC0024a) {
        if (abstractC0024a == null) {
            this.f50b.mo58c(null, null);
        } else {
            this.f50b.mo58c(abstractC0024a, new Handler());
        }
    }

    public void removeOnActiveChangeListener(InterfaceC0028e interfaceC0028e) {
        if (interfaceC0028e == null) {
            throw new IllegalArgumentException("Listener may not be null");
        }
        this.f52d.remove(interfaceC0028e);
    }

    public static final class Token implements Parcelable {
        public static final Parcelable.Creator<Token> CREATOR = new C0023a();

        /* renamed from: c */
        public final Object f57c;

        /* renamed from: e */
        public InterfaceC4184b f58e;

        /* renamed from: f */
        public Bundle f59f;

        /* renamed from: android.support.v4.media.session.MediaSessionCompat$Token$a */
        public static class C0023a implements Parcelable.Creator<Token> {
            @Override // android.os.Parcelable.Creator
            public Token createFromParcel(Parcel parcel) {
                return new Token(parcel.readParcelable(null));
            }

            @Override // android.os.Parcelable.Creator
            public Token[] newArray(int i2) {
                return new Token[i2];
            }
        }

        public Token(Object obj) {
            this.f57c = obj;
            this.f58e = null;
            this.f59f = null;
        }

        @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
        /* renamed from: b */
        public static Token m27b(Object obj, InterfaceC4184b interfaceC4184b) {
            if (obj == null) {
                return null;
            }
            if (obj instanceof MediaSession.Token) {
                return new Token(obj, interfaceC4184b);
            }
            throw new IllegalArgumentException("token is not a valid MediaSession.Token object");
        }

        @Override // android.os.Parcelable
        public int describeContents() {
            return 0;
        }

        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof Token)) {
                return false;
            }
            Token token = (Token) obj;
            Object obj2 = this.f57c;
            if (obj2 == null) {
                return token.f57c == null;
            }
            Object obj3 = token.f57c;
            if (obj3 == null) {
                return false;
            }
            return obj2.equals(obj3);
        }

        public int hashCode() {
            Object obj = this.f57c;
            if (obj == null) {
                return 0;
            }
            return obj.hashCode();
        }

        @Override // android.os.Parcelable
        public void writeToParcel(Parcel parcel, int i2) {
            parcel.writeParcelable((Parcelable) this.f57c, i2);
        }

        public Token(Object obj, InterfaceC4184b interfaceC4184b) {
            this.f57c = obj;
            this.f58e = interfaceC4184b;
            this.f59f = null;
        }

        public Token(Object obj, InterfaceC4184b interfaceC4184b, Bundle bundle) {
            this.f57c = obj;
            this.f58e = interfaceC4184b;
            this.f59f = bundle;
        }
    }

    public static final class QueueItem implements Parcelable {
        public static final Parcelable.Creator<QueueItem> CREATOR = new C0021a();

        /* renamed from: c */
        public final MediaDescriptionCompat f53c;

        /* renamed from: e */
        public final long f54e;

        /* renamed from: f */
        public Object f55f;

        /* renamed from: android.support.v4.media.session.MediaSessionCompat$QueueItem$a */
        public static class C0021a implements Parcelable.Creator<QueueItem> {
            @Override // android.os.Parcelable.Creator
            public QueueItem createFromParcel(Parcel parcel) {
                return new QueueItem(parcel);
            }

            @Override // android.os.Parcelable.Creator
            public QueueItem[] newArray(int i2) {
                return new QueueItem[i2];
            }
        }

        public QueueItem(Object obj, MediaDescriptionCompat mediaDescriptionCompat, long j2) {
            if (mediaDescriptionCompat == null) {
                throw new IllegalArgumentException("Description cannot be null.");
            }
            if (j2 == -1) {
                throw new IllegalArgumentException("Id cannot be QueueItem.UNKNOWN_ID");
            }
            this.f53c = mediaDescriptionCompat;
            this.f54e = j2;
            this.f55f = obj;
        }

        @Override // android.os.Parcelable
        public int describeContents() {
            return 0;
        }

        public String toString() {
            StringBuilder m586H = C1499a.m586H("MediaSession.QueueItem {Description=");
            m586H.append(this.f53c);
            m586H.append(", Id=");
            m586H.append(this.f54e);
            m586H.append(" }");
            return m586H.toString();
        }

        @Override // android.os.Parcelable
        public void writeToParcel(Parcel parcel, int i2) {
            this.f53c.writeToParcel(parcel, i2);
            parcel.writeLong(this.f54e);
        }

        public QueueItem(Parcel parcel) {
            this.f53c = MediaDescriptionCompat.CREATOR.createFromParcel(parcel);
            this.f54e = parcel.readLong();
        }
    }
}
