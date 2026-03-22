package android.support.v4.media;

import android.content.ComponentName;
import android.content.Context;
import android.media.browse.MediaBrowser;
import android.os.BadParcelableException;
import android.os.Binder;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Message;
import android.os.Messenger;
import android.os.Parcel;
import android.os.Parcelable;
import android.os.RemoteException;
import android.support.v4.media.session.MediaSessionCompat;
import android.support.v4.os.ResultReceiver;
import android.text.TextUtils;
import android.util.Log;
import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;
import androidx.collection.ArrayMap;
import androidx.core.app.BundleCompat;
import androidx.media.MediaBrowserCompatUtils;
import androidx.media.MediaBrowserProtocol;
import androidx.media.MediaBrowserServiceCompat;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import p403d.p404a.p405a.p407b.p408a.InterfaceC4184b;

/* loaded from: classes.dex */
public final class MediaBrowserCompat {

    /* renamed from: a */
    public static final boolean f0a = Log.isLoggable("MediaBrowserCompat", 3);

    /* renamed from: b */
    public final InterfaceC0004c f1b;

    public static class CustomActionResultReceiver extends ResultReceiver {
        @Override // android.support.v4.os.ResultReceiver
        /* renamed from: b */
        public void mo2b(int i2, Bundle bundle) {
        }
    }

    public static class ItemReceiver extends ResultReceiver {
        @Override // android.support.v4.os.ResultReceiver
        /* renamed from: b */
        public void mo2b(int i2, Bundle bundle) {
            MediaSessionCompat.m23a(bundle);
            if (i2 != 0) {
                throw null;
            }
            if (bundle == null) {
                throw null;
            }
            if (!bundle.containsKey(MediaBrowserServiceCompat.KEY_MEDIA_ITEM)) {
                throw null;
            }
            Parcelable parcelable = bundle.getParcelable(MediaBrowserServiceCompat.KEY_MEDIA_ITEM);
            if (parcelable != null && !(parcelable instanceof MediaItem)) {
                throw null;
            }
            throw null;
        }
    }

    public static class SearchResultReceiver extends ResultReceiver {
        @Override // android.support.v4.os.ResultReceiver
        /* renamed from: b */
        public void mo2b(int i2, Bundle bundle) {
            MediaSessionCompat.m23a(bundle);
            if (i2 != 0) {
                throw null;
            }
            if (bundle == null) {
                throw null;
            }
            if (!bundle.containsKey(MediaBrowserServiceCompat.KEY_SEARCH_RESULTS)) {
                throw null;
            }
            Parcelable[] parcelableArray = bundle.getParcelableArray(MediaBrowserServiceCompat.KEY_SEARCH_RESULTS);
            if (parcelableArray == null) {
                throw null;
            }
            ArrayList arrayList = new ArrayList();
            for (Parcelable parcelable : parcelableArray) {
                arrayList.add((MediaItem) parcelable);
            }
            throw null;
        }
    }

    /* renamed from: android.support.v4.media.MediaBrowserCompat$a */
    public static class HandlerC0002a extends Handler {

        /* renamed from: a */
        public final WeakReference<InterfaceC0008g> f4a;

        /* renamed from: b */
        public WeakReference<Messenger> f5b;

        public HandlerC0002a(InterfaceC0008g interfaceC0008g) {
            this.f4a = new WeakReference<>(interfaceC0008g);
        }

        /* renamed from: a */
        public void m4a(Messenger messenger) {
            this.f5b = new WeakReference<>(messenger);
        }

        @Override // android.os.Handler
        public void handleMessage(Message message) {
            WeakReference<Messenger> weakReference = this.f5b;
            if (weakReference == null || weakReference.get() == null || this.f4a.get() == null) {
                return;
            }
            Bundle data = message.getData();
            MediaSessionCompat.m23a(data);
            InterfaceC0008g interfaceC0008g = this.f4a.get();
            Messenger messenger = this.f5b.get();
            try {
                int i2 = message.what;
                if (i2 == 1) {
                    Bundle bundle = data.getBundle(MediaBrowserProtocol.DATA_ROOT_HINTS);
                    MediaSessionCompat.m23a(bundle);
                    interfaceC0008g.mo5a(messenger, data.getString(MediaBrowserProtocol.DATA_MEDIA_ITEM_ID), (MediaSessionCompat.Token) data.getParcelable(MediaBrowserProtocol.DATA_MEDIA_SESSION_TOKEN), bundle);
                } else if (i2 == 2) {
                    interfaceC0008g.mo7c(messenger);
                } else if (i2 != 3) {
                    String str = "Unhandled message: " + message + "\n  Client version: 1\n  Service version: " + message.arg1;
                } else {
                    Bundle bundle2 = data.getBundle(MediaBrowserProtocol.DATA_OPTIONS);
                    MediaSessionCompat.m23a(bundle2);
                    Bundle bundle3 = data.getBundle(MediaBrowserProtocol.DATA_NOTIFY_CHILDREN_CHANGED_OPTIONS);
                    MediaSessionCompat.m23a(bundle3);
                    interfaceC0008g.mo6b(messenger, data.getString(MediaBrowserProtocol.DATA_MEDIA_ITEM_ID), data.getParcelableArrayList(MediaBrowserProtocol.DATA_MEDIA_ITEM_LIST), bundle2, bundle3);
                }
            } catch (BadParcelableException unused) {
                if (message.what == 1) {
                    interfaceC0008g.mo7c(messenger);
                }
            }
        }
    }

    /* renamed from: android.support.v4.media.MediaBrowserCompat$b */
    public static class C0003b {
        public final MediaBrowser.ConnectionCallback mConnectionCallbackFwk = new a();
        public b mConnectionCallbackInternal;

        @RequiresApi(21)
        /* renamed from: android.support.v4.media.MediaBrowserCompat$b$a */
        public class a extends MediaBrowser.ConnectionCallback {
            public a() {
            }

            @Override // android.media.browse.MediaBrowser.ConnectionCallback
            public void onConnected() {
                b bVar = C0003b.this.mConnectionCallbackInternal;
                if (bVar != null) {
                    C0005d c0005d = (C0005d) bVar;
                    Objects.requireNonNull(c0005d);
                    try {
                        Bundle extras = c0005d.f8b.getExtras();
                        if (extras != null) {
                            extras.getInt(MediaBrowserProtocol.EXTRA_SERVICE_VERSION, 0);
                            IBinder binder = BundleCompat.getBinder(extras, MediaBrowserProtocol.EXTRA_MESSENGER_BINDER);
                            if (binder != null) {
                                c0005d.f12f = new C0009h(binder, c0005d.f9c);
                                Messenger messenger = new Messenger(c0005d.f10d);
                                c0005d.f13g = messenger;
                                c0005d.f10d.m4a(messenger);
                                try {
                                    C0009h c0009h = c0005d.f12f;
                                    Context context = c0005d.f7a;
                                    Messenger messenger2 = c0005d.f13g;
                                    Objects.requireNonNull(c0009h);
                                    Bundle bundle = new Bundle();
                                    bundle.putString(MediaBrowserProtocol.DATA_PACKAGE_NAME, context.getPackageName());
                                    bundle.putBundle(MediaBrowserProtocol.DATA_ROOT_HINTS, c0009h.f16b);
                                    c0009h.m8a(6, bundle, messenger2);
                                } catch (RemoteException unused) {
                                }
                            }
                            InterfaceC4184b m4754X = InterfaceC4184b.a.m4754X(BundleCompat.getBinder(extras, MediaBrowserProtocol.EXTRA_SESSION_BINDER));
                            if (m4754X != null) {
                                c0005d.f14h = MediaSessionCompat.Token.m27b(c0005d.f8b.getSessionToken(), m4754X);
                            }
                        }
                    } catch (IllegalStateException unused2) {
                    }
                }
                C0003b.this.onConnected();
            }

            @Override // android.media.browse.MediaBrowser.ConnectionCallback
            public void onConnectionFailed() {
                b bVar = C0003b.this.mConnectionCallbackInternal;
                if (bVar != null) {
                    Objects.requireNonNull((C0005d) bVar);
                }
                C0003b.this.onConnectionFailed();
            }

            @Override // android.media.browse.MediaBrowser.ConnectionCallback
            public void onConnectionSuspended() {
                b bVar = C0003b.this.mConnectionCallbackInternal;
                if (bVar != null) {
                    C0005d c0005d = (C0005d) bVar;
                    c0005d.f12f = null;
                    c0005d.f13g = null;
                    c0005d.f14h = null;
                    c0005d.f10d.m4a(null);
                }
                C0003b.this.onConnectionSuspended();
            }
        }

        /* renamed from: android.support.v4.media.MediaBrowserCompat$b$b */
        public interface b {
        }

        public void onConnected() {
            throw null;
        }

        public void onConnectionFailed() {
            throw null;
        }

        public void onConnectionSuspended() {
            throw null;
        }

        public void setInternalConnectionCallback(b bVar) {
            this.mConnectionCallbackInternal = bVar;
        }
    }

    /* renamed from: android.support.v4.media.MediaBrowserCompat$c */
    public interface InterfaceC0004c {
    }

    @RequiresApi(21)
    /* renamed from: android.support.v4.media.MediaBrowserCompat$d */
    public static class C0005d implements InterfaceC0004c, InterfaceC0008g, C0003b.b {

        /* renamed from: a */
        public final Context f7a;

        /* renamed from: b */
        public final MediaBrowser f8b;

        /* renamed from: c */
        public final Bundle f9c;

        /* renamed from: d */
        public final HandlerC0002a f10d = new HandlerC0002a(this);

        /* renamed from: e */
        public final ArrayMap<String, C0010i> f11e = new ArrayMap<>();

        /* renamed from: f */
        public C0009h f12f;

        /* renamed from: g */
        public Messenger f13g;

        /* renamed from: h */
        public MediaSessionCompat.Token f14h;

        public C0005d(Context context, ComponentName componentName, C0003b c0003b, Bundle bundle) {
            this.f7a = context;
            Bundle bundle2 = bundle != null ? new Bundle(bundle) : new Bundle();
            this.f9c = bundle2;
            bundle2.putInt(MediaBrowserProtocol.EXTRA_CLIENT_VERSION, 1);
            c0003b.setInternalConnectionCallback(this);
            this.f8b = new MediaBrowser(context, componentName, c0003b.mConnectionCallbackFwk, bundle2);
        }

        @Override // android.support.v4.media.MediaBrowserCompat.InterfaceC0008g
        /* renamed from: a */
        public void mo5a(Messenger messenger, String str, MediaSessionCompat.Token token, Bundle bundle) {
        }

        @Override // android.support.v4.media.MediaBrowserCompat.InterfaceC0008g
        /* renamed from: b */
        public void mo6b(Messenger messenger, String str, List list, Bundle bundle, Bundle bundle2) {
            if (this.f13g != messenger) {
                return;
            }
            C0010i c0010i = this.f11e.get(str);
            if (c0010i == null) {
                boolean z = MediaBrowserCompat.f0a;
            } else {
                c0010i.m9a(bundle);
            }
        }

        @Override // android.support.v4.media.MediaBrowserCompat.InterfaceC0008g
        /* renamed from: c */
        public void mo7c(Messenger messenger) {
        }
    }

    @RequiresApi(23)
    /* renamed from: android.support.v4.media.MediaBrowserCompat$e */
    public static class C0006e extends C0005d {
        public C0006e(Context context, ComponentName componentName, C0003b c0003b, Bundle bundle) {
            super(context, componentName, c0003b, bundle);
        }
    }

    @RequiresApi(26)
    /* renamed from: android.support.v4.media.MediaBrowserCompat$f */
    public static class C0007f extends C0006e {
        public C0007f(Context context, ComponentName componentName, C0003b c0003b, Bundle bundle) {
            super(context, componentName, c0003b, bundle);
        }
    }

    /* renamed from: android.support.v4.media.MediaBrowserCompat$g */
    public interface InterfaceC0008g {
        /* renamed from: a */
        void mo5a(Messenger messenger, String str, MediaSessionCompat.Token token, Bundle bundle);

        /* renamed from: b */
        void mo6b(Messenger messenger, String str, List list, Bundle bundle, Bundle bundle2);

        /* renamed from: c */
        void mo7c(Messenger messenger);
    }

    /* renamed from: android.support.v4.media.MediaBrowserCompat$h */
    public static class C0009h {

        /* renamed from: a */
        public Messenger f15a;

        /* renamed from: b */
        public Bundle f16b;

        public C0009h(IBinder iBinder, Bundle bundle) {
            this.f15a = new Messenger(iBinder);
            this.f16b = bundle;
        }

        /* renamed from: a */
        public final void m8a(int i2, Bundle bundle, Messenger messenger) {
            Message obtain = Message.obtain();
            obtain.what = i2;
            obtain.arg1 = 1;
            obtain.setData(bundle);
            obtain.replyTo = messenger;
            this.f15a.send(obtain);
        }
    }

    /* renamed from: android.support.v4.media.MediaBrowserCompat$i */
    public static class C0010i {

        /* renamed from: a */
        public final List<AbstractC0011j> f17a = new ArrayList();

        /* renamed from: b */
        public final List<Bundle> f18b = new ArrayList();

        /* renamed from: a */
        public AbstractC0011j m9a(Bundle bundle) {
            for (int i2 = 0; i2 < this.f18b.size(); i2++) {
                if (MediaBrowserCompatUtils.areSameOptions(this.f18b.get(i2), bundle)) {
                    return this.f17a.get(i2);
                }
            }
            return null;
        }
    }

    /* renamed from: android.support.v4.media.MediaBrowserCompat$j */
    public static abstract class AbstractC0011j {

        /* renamed from: a */
        public final IBinder f19a = new Binder();

        @RequiresApi(21)
        /* renamed from: android.support.v4.media.MediaBrowserCompat$j$a */
        public class a extends MediaBrowser.SubscriptionCallback {
            public a() {
            }

            @Override // android.media.browse.MediaBrowser.SubscriptionCallback
            public void onChildrenLoaded(@NonNull String str, List<MediaBrowser.MediaItem> list) {
                Objects.requireNonNull(AbstractC0011j.this);
                AbstractC0011j abstractC0011j = AbstractC0011j.this;
                MediaItem.m3b(list);
                Objects.requireNonNull(abstractC0011j);
            }

            @Override // android.media.browse.MediaBrowser.SubscriptionCallback
            public void onError(@NonNull String str) {
                Objects.requireNonNull(AbstractC0011j.this);
            }
        }

        @RequiresApi(26)
        /* renamed from: android.support.v4.media.MediaBrowserCompat$j$b */
        public class b extends a {
            public b() {
                super();
            }

            @Override // android.media.browse.MediaBrowser.SubscriptionCallback
            public void onChildrenLoaded(@NonNull String str, List<MediaBrowser.MediaItem> list, @NonNull Bundle bundle) {
                MediaSessionCompat.m23a(bundle);
                AbstractC0011j abstractC0011j = AbstractC0011j.this;
                MediaItem.m3b(list);
                Objects.requireNonNull(abstractC0011j);
            }

            @Override // android.media.browse.MediaBrowser.SubscriptionCallback
            public void onError(@NonNull String str, @NonNull Bundle bundle) {
                MediaSessionCompat.m23a(bundle);
                Objects.requireNonNull(AbstractC0011j.this);
            }
        }

        public AbstractC0011j() {
            if (Build.VERSION.SDK_INT >= 26) {
                new b();
            } else {
                new a();
            }
        }
    }

    public MediaBrowserCompat(Context context, ComponentName componentName, C0003b c0003b, Bundle bundle) {
        int i2 = Build.VERSION.SDK_INT;
        if (i2 >= 26) {
            this.f1b = new C0007f(context, componentName, c0003b, null);
        } else if (i2 >= 23) {
            this.f1b = new C0006e(context, componentName, c0003b, null);
        } else {
            this.f1b = new C0005d(context, componentName, c0003b, null);
        }
    }

    public static class MediaItem implements Parcelable {
        public static final Parcelable.Creator<MediaItem> CREATOR = new C0001a();

        /* renamed from: c */
        public final int f2c;

        /* renamed from: e */
        public final MediaDescriptionCompat f3e;

        /* renamed from: android.support.v4.media.MediaBrowserCompat$MediaItem$a */
        public static class C0001a implements Parcelable.Creator<MediaItem> {
            @Override // android.os.Parcelable.Creator
            public MediaItem createFromParcel(Parcel parcel) {
                return new MediaItem(parcel);
            }

            @Override // android.os.Parcelable.Creator
            public MediaItem[] newArray(int i2) {
                return new MediaItem[i2];
            }
        }

        public MediaItem(@NonNull MediaDescriptionCompat mediaDescriptionCompat, int i2) {
            if (mediaDescriptionCompat == null) {
                throw new IllegalArgumentException("description cannot be null");
            }
            if (TextUtils.isEmpty(mediaDescriptionCompat.f22c)) {
                throw new IllegalArgumentException("description must have a non-empty media id");
            }
            this.f2c = i2;
            this.f3e = mediaDescriptionCompat;
        }

        /* renamed from: b */
        public static List<MediaItem> m3b(List<?> list) {
            MediaItem mediaItem;
            if (list == null) {
                return null;
            }
            ArrayList arrayList = new ArrayList(list.size());
            for (Object obj : list) {
                if (obj != null) {
                    MediaBrowser.MediaItem mediaItem2 = (MediaBrowser.MediaItem) obj;
                    mediaItem = new MediaItem(MediaDescriptionCompat.m10b(mediaItem2.getDescription()), mediaItem2.getFlags());
                } else {
                    mediaItem = null;
                }
                arrayList.add(mediaItem);
            }
            return arrayList;
        }

        @Override // android.os.Parcelable
        public int describeContents() {
            return 0;
        }

        public String toString() {
            return "MediaItem{mFlags=" + this.f2c + ", mDescription=" + this.f3e + '}';
        }

        @Override // android.os.Parcelable
        public void writeToParcel(Parcel parcel, int i2) {
            parcel.writeInt(this.f2c);
            this.f3e.writeToParcel(parcel, i2);
        }

        public MediaItem(Parcel parcel) {
            this.f2c = parcel.readInt();
            this.f3e = MediaDescriptionCompat.CREATOR.createFromParcel(parcel);
        }
    }
}
