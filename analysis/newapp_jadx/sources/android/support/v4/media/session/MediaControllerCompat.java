package android.support.v4.media.session;

import android.content.Context;
import android.media.session.MediaController;
import android.media.session.MediaSession;
import android.os.Build;
import android.os.Bundle;
import android.os.IBinder;
import android.os.RemoteException;
import android.os.ResultReceiver;
import android.support.v4.media.MediaMetadataCompat;
import android.support.v4.media.session.MediaSessionCompat;
import android.view.KeyEvent;
import androidx.annotation.GuardedBy;
import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;
import androidx.core.app.BundleCompat;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import p403d.p404a.p405a.p407b.p408a.C4186d;
import p403d.p404a.p405a.p407b.p408a.InterfaceC4183a;
import p403d.p404a.p405a.p407b.p408a.InterfaceC4184b;
import p403d.p404a.p405a.p407b.p408a.InterfaceC4185c;

/* loaded from: classes.dex */
public final class MediaControllerCompat {

    /* renamed from: a */
    public final InterfaceC0018b f38a;

    /* renamed from: b */
    public final MediaSessionCompat.Token f39b;

    @RequiresApi(21)
    public static class MediaControllerImplApi21 implements InterfaceC0018b {

        /* renamed from: a */
        public final Object f40a;

        /* renamed from: b */
        public final Object f41b = new Object();

        /* renamed from: c */
        @GuardedBy("mLock")
        public final List<AbstractC0017a> f42c = new ArrayList();

        /* renamed from: d */
        public HashMap<AbstractC0017a, BinderC0016a> f43d = new HashMap<>();

        /* renamed from: e */
        public final MediaSessionCompat.Token f44e;

        public static class ExtraBinderRequestResultReceiver extends ResultReceiver {

            /* renamed from: c */
            public WeakReference<MediaControllerImplApi21> f45c;

            public ExtraBinderRequestResultReceiver(MediaControllerImplApi21 mediaControllerImplApi21) {
                super(null);
                this.f45c = new WeakReference<>(mediaControllerImplApi21);
            }

            @Override // android.os.ResultReceiver
            public void onReceiveResult(int i2, Bundle bundle) {
                MediaControllerImplApi21 mediaControllerImplApi21 = this.f45c.get();
                if (mediaControllerImplApi21 == null || bundle == null) {
                    return;
                }
                synchronized (mediaControllerImplApi21.f41b) {
                    mediaControllerImplApi21.f44e.f58e = InterfaceC4184b.a.m4754X(BundleCompat.getBinder(bundle, "android.support.v4.media.session.EXTRA_BINDER"));
                    mediaControllerImplApi21.f44e.f59f = bundle.getBundle("android.support.v4.media.session.SESSION_TOKEN2_BUNDLE");
                    mediaControllerImplApi21.m15a();
                }
            }
        }

        /* renamed from: android.support.v4.media.session.MediaControllerCompat$MediaControllerImplApi21$a */
        public static class BinderC0016a extends AbstractC0017a.b {
            public BinderC0016a(AbstractC0017a abstractC0017a) {
                super(abstractC0017a);
            }

            @Override // android.support.v4.media.session.MediaControllerCompat.AbstractC0017a.b, p403d.p404a.p405a.p407b.p408a.InterfaceC4183a
            /* renamed from: C */
            public void mo16C(CharSequence charSequence) {
                throw new AssertionError();
            }

            @Override // android.support.v4.media.session.MediaControllerCompat.AbstractC0017a.b, p403d.p404a.p405a.p407b.p408a.InterfaceC4183a
            /* renamed from: F */
            public void mo17F() {
                throw new AssertionError();
            }

            @Override // android.support.v4.media.session.MediaControllerCompat.AbstractC0017a.b, p403d.p404a.p405a.p407b.p408a.InterfaceC4183a
            /* renamed from: H */
            public void mo18H(MediaMetadataCompat mediaMetadataCompat) {
                throw new AssertionError();
            }

            @Override // android.support.v4.media.session.MediaControllerCompat.AbstractC0017a.b, p403d.p404a.p405a.p407b.p408a.InterfaceC4183a
            /* renamed from: W */
            public void mo19W(ParcelableVolumeInfo parcelableVolumeInfo) {
                throw new AssertionError();
            }

            @Override // android.support.v4.media.session.MediaControllerCompat.AbstractC0017a.b, p403d.p404a.p405a.p407b.p408a.InterfaceC4183a
            /* renamed from: r */
            public void mo20r(Bundle bundle) {
                throw new AssertionError();
            }

            @Override // android.support.v4.media.session.MediaControllerCompat.AbstractC0017a.b, p403d.p404a.p405a.p407b.p408a.InterfaceC4183a
            /* renamed from: s */
            public void mo21s(List<MediaSessionCompat.QueueItem> list) {
                throw new AssertionError();
            }
        }

        public MediaControllerImplApi21(Context context, MediaSessionCompat.Token token) {
            this.f44e = token;
            MediaController mediaController = new MediaController(context, (MediaSession.Token) token.f57c);
            this.f40a = mediaController;
            if (mediaController == null) {
                throw new RemoteException();
            }
            if (token.f58e == null) {
                mediaController.sendCommand("android.support.v4.media.session.command.GET_EXTRA_BINDER", null, new ExtraBinderRequestResultReceiver(this));
            }
        }

        @GuardedBy("mLock")
        /* renamed from: a */
        public void m15a() {
            if (this.f44e.f58e == null) {
                return;
            }
            for (AbstractC0017a abstractC0017a : this.f42c) {
                BinderC0016a binderC0016a = new BinderC0016a(abstractC0017a);
                this.f43d.put(abstractC0017a, binderC0016a);
                abstractC0017a.f46a = binderC0016a;
                try {
                    this.f44e.f58e.mo89g(binderC0016a);
                } catch (RemoteException unused) {
                }
            }
            this.f42c.clear();
        }
    }

    /* renamed from: android.support.v4.media.session.MediaControllerCompat$a */
    public static abstract class AbstractC0017a implements IBinder.DeathRecipient {

        /* renamed from: a */
        public InterfaceC4183a f46a;

        /* renamed from: android.support.v4.media.session.MediaControllerCompat$a$a */
        public static class a implements InterfaceC4185c {

            /* renamed from: a */
            public final WeakReference<AbstractC0017a> f47a;

            public a(AbstractC0017a abstractC0017a) {
                this.f47a = new WeakReference<>(abstractC0017a);
            }
        }

        /* renamed from: android.support.v4.media.session.MediaControllerCompat$a$b */
        public static class b extends InterfaceC4183a.a {

            /* renamed from: a */
            public final WeakReference<AbstractC0017a> f48a;

            public b(AbstractC0017a abstractC0017a) {
                this.f48a = new WeakReference<>(abstractC0017a);
            }

            /* renamed from: C */
            public void mo16C(CharSequence charSequence) {
                this.f48a.get();
            }

            /* renamed from: F */
            public void mo17F() {
                this.f48a.get();
            }

            /* renamed from: H */
            public void mo18H(MediaMetadataCompat mediaMetadataCompat) {
                this.f48a.get();
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4183a
            /* renamed from: U */
            public void mo22U(PlaybackStateCompat playbackStateCompat) {
                this.f48a.get();
            }

            /* renamed from: W */
            public void mo19W(ParcelableVolumeInfo parcelableVolumeInfo) {
                this.f48a.get();
            }

            /* renamed from: r */
            public void mo20r(Bundle bundle) {
                this.f48a.get();
            }

            /* renamed from: s */
            public void mo21s(List<MediaSessionCompat.QueueItem> list) {
                this.f48a.get();
            }
        }

        public AbstractC0017a() {
            new C4186d(new a(this));
        }

        @Override // android.os.IBinder.DeathRecipient
        public void binderDied() {
        }
    }

    /* renamed from: android.support.v4.media.session.MediaControllerCompat$b */
    public interface InterfaceC0018b {
    }

    @RequiresApi(23)
    /* renamed from: android.support.v4.media.session.MediaControllerCompat$c */
    public static class C0019c extends MediaControllerImplApi21 {
        public C0019c(Context context, MediaSessionCompat.Token token) {
            super(context, token);
        }
    }

    @RequiresApi(24)
    /* renamed from: android.support.v4.media.session.MediaControllerCompat$d */
    public static class C0020d extends C0019c {
        public C0020d(Context context, MediaSessionCompat.Token token) {
            super(context, token);
        }
    }

    public MediaControllerCompat(Context context, @NonNull MediaSessionCompat mediaSessionCompat) {
        new HashSet();
        MediaSessionCompat.Token mo57b = mediaSessionCompat.f50b.mo57b();
        this.f39b = mo57b;
        InterfaceC0018b interfaceC0018b = null;
        try {
            int i2 = Build.VERSION.SDK_INT;
            interfaceC0018b = i2 >= 24 ? new C0020d(context, mo57b) : i2 >= 23 ? new C0019c(context, mo57b) : new MediaControllerImplApi21(context, mo57b);
        } catch (RemoteException unused) {
        }
        this.f38a = interfaceC0018b;
    }

    /* renamed from: a */
    public boolean m14a(KeyEvent keyEvent) {
        if (keyEvent != null) {
            return ((MediaController) ((MediaControllerImplApi21) this.f38a).f40a).dispatchMediaButtonEvent(keyEvent);
        }
        throw new IllegalArgumentException("KeyEvent may not be null");
    }
}
