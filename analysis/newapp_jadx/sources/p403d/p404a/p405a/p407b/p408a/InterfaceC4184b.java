package p403d.p404a.p405a.p407b.p408a;

import android.app.PendingIntent;
import android.net.Uri;
import android.os.Binder;
import android.os.Bundle;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.support.v4.media.MediaDescriptionCompat;
import android.support.v4.media.MediaMetadataCompat;
import android.support.v4.media.RatingCompat;
import android.support.v4.media.session.MediaSessionCompat;
import android.support.v4.media.session.ParcelableVolumeInfo;
import android.support.v4.media.session.PlaybackStateCompat;
import android.text.TextUtils;
import android.view.KeyEvent;
import java.util.List;
import p403d.p404a.p405a.p407b.p408a.InterfaceC4183a;

/* renamed from: d.a.a.b.a.b */
/* loaded from: classes.dex */
public interface InterfaceC4184b extends IInterface {

    /* renamed from: d.a.a.b.a.b$a */
    public static abstract class a extends Binder implements InterfaceC4184b {

        /* renamed from: d.a.a.b.a.b$a$a, reason: collision with other inner class name */
        public static class C5130a implements InterfaceC4184b {

            /* renamed from: a */
            public IBinder f10930a;

            public C5130a(IBinder iBinder) {
                this.f10930a = iBinder;
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4184b
            /* renamed from: B */
            public boolean mo67B(KeyEvent keyEvent) {
                Parcel obtain = Parcel.obtain();
                Parcel obtain2 = Parcel.obtain();
                try {
                    obtain.writeInterfaceToken("android.support.v4.media.session.IMediaSession");
                    if (keyEvent != null) {
                        obtain.writeInt(1);
                        keyEvent.writeToParcel(obtain, 0);
                    } else {
                        obtain.writeInt(0);
                    }
                    this.f10930a.transact(2, obtain, obtain2, 0);
                    obtain2.readException();
                    return obtain2.readInt() != 0;
                } finally {
                    obtain2.recycle();
                    obtain.recycle();
                }
            }

            @Override // android.os.IInterface
            public IBinder asBinder() {
                return this.f10930a;
            }

            @Override // p403d.p404a.p405a.p407b.p408a.InterfaceC4184b
            /* renamed from: g */
            public void mo89g(InterfaceC4183a interfaceC4183a) {
                Parcel obtain = Parcel.obtain();
                Parcel obtain2 = Parcel.obtain();
                try {
                    obtain.writeInterfaceToken("android.support.v4.media.session.IMediaSession");
                    obtain.writeStrongBinder((InterfaceC4183a.a) interfaceC4183a);
                    this.f10930a.transact(3, obtain, obtain2, 0);
                    obtain2.readException();
                } finally {
                    obtain2.recycle();
                    obtain.recycle();
                }
            }
        }

        public a() {
            attachInterface(this, "android.support.v4.media.session.IMediaSession");
        }

        /* renamed from: X */
        public static InterfaceC4184b m4754X(IBinder iBinder) {
            if (iBinder == null) {
                return null;
            }
            IInterface queryLocalInterface = iBinder.queryLocalInterface("android.support.v4.media.session.IMediaSession");
            return (queryLocalInterface == null || !(queryLocalInterface instanceof InterfaceC4184b)) ? new C5130a(iBinder) : (InterfaceC4184b) queryLocalInterface;
        }

        @Override // android.os.IInterface
        public IBinder asBinder() {
            return this;
        }

        @Override // android.os.Binder
        public boolean onTransact(int i2, Parcel parcel, Parcel parcel2, int i3) {
            if (i2 == 51) {
                parcel.enforceInterface("android.support.v4.media.session.IMediaSession");
                mo69E(parcel.readInt() != 0 ? RatingCompat.CREATOR.createFromParcel(parcel) : null, parcel.readInt() != 0 ? (Bundle) Bundle.CREATOR.createFromParcel(parcel) : null);
                parcel2.writeNoException();
                return true;
            }
            if (i2 == 1598968902) {
                parcel2.writeString("android.support.v4.media.session.IMediaSession");
                return true;
            }
            switch (i2) {
                case 1:
                    parcel.enforceInterface("android.support.v4.media.session.IMediaSession");
                    mo76N(parcel.readString(), parcel.readInt() != 0 ? (Bundle) Bundle.CREATOR.createFromParcel(parcel) : null, parcel.readInt() != 0 ? MediaSessionCompat.ResultReceiverWrapper.CREATOR.createFromParcel(parcel) : null);
                    parcel2.writeNoException();
                    return true;
                case 2:
                    parcel.enforceInterface("android.support.v4.media.session.IMediaSession");
                    boolean mo67B = mo67B(parcel.readInt() != 0 ? (KeyEvent) KeyEvent.CREATOR.createFromParcel(parcel) : null);
                    parcel2.writeNoException();
                    parcel2.writeInt(mo67B ? 1 : 0);
                    return true;
                case 3:
                    parcel.enforceInterface("android.support.v4.media.session.IMediaSession");
                    mo89g(InterfaceC4183a.a.m4753X(parcel.readStrongBinder()));
                    parcel2.writeNoException();
                    return true;
                case 4:
                    parcel.enforceInterface("android.support.v4.media.session.IMediaSession");
                    mo103w(InterfaceC4183a.a.m4753X(parcel.readStrongBinder()));
                    parcel2.writeNoException();
                    return true;
                case 5:
                    parcel.enforceInterface("android.support.v4.media.session.IMediaSession");
                    boolean mo95m = mo95m();
                    parcel2.writeNoException();
                    parcel2.writeInt(mo95m ? 1 : 0);
                    return true;
                case 6:
                    parcel.enforceInterface("android.support.v4.media.session.IMediaSession");
                    String packageName = getPackageName();
                    parcel2.writeNoException();
                    parcel2.writeString(packageName);
                    return true;
                case 7:
                    parcel.enforceInterface("android.support.v4.media.session.IMediaSession");
                    String mo85c = mo85c();
                    parcel2.writeNoException();
                    parcel2.writeString(mo85c);
                    return true;
                case 8:
                    parcel.enforceInterface("android.support.v4.media.session.IMediaSession");
                    PendingIntent mo97o = mo97o();
                    parcel2.writeNoException();
                    if (mo97o != null) {
                        parcel2.writeInt(1);
                        mo97o.writeToParcel(parcel2, 1);
                    } else {
                        parcel2.writeInt(0);
                    }
                    return true;
                case 9:
                    parcel.enforceInterface("android.support.v4.media.session.IMediaSession");
                    long flags = getFlags();
                    parcel2.writeNoException();
                    parcel2.writeLong(flags);
                    return true;
                case 10:
                    parcel.enforceInterface("android.support.v4.media.session.IMediaSession");
                    ParcelableVolumeInfo mo81S = mo81S();
                    parcel2.writeNoException();
                    if (mo81S != null) {
                        parcel2.writeInt(1);
                        mo81S.writeToParcel(parcel2, 1);
                    } else {
                        parcel2.writeInt(0);
                    }
                    return true;
                case 11:
                    parcel.enforceInterface("android.support.v4.media.session.IMediaSession");
                    mo68D(parcel.readInt(), parcel.readInt(), parcel.readString());
                    parcel2.writeNoException();
                    return true;
                case 12:
                    parcel.enforceInterface("android.support.v4.media.session.IMediaSession");
                    mo92j(parcel.readInt(), parcel.readInt(), parcel.readString());
                    parcel2.writeNoException();
                    return true;
                case 13:
                    parcel.enforceInterface("android.support.v4.media.session.IMediaSession");
                    mo75M();
                    parcel2.writeNoException();
                    return true;
                case 14:
                    parcel.enforceInterface("android.support.v4.media.session.IMediaSession");
                    mo104x(parcel.readString(), parcel.readInt() != 0 ? (Bundle) Bundle.CREATOR.createFromParcel(parcel) : null);
                    parcel2.writeNoException();
                    return true;
                case 15:
                    parcel.enforceInterface("android.support.v4.media.session.IMediaSession");
                    mo105y(parcel.readString(), parcel.readInt() != 0 ? (Bundle) Bundle.CREATOR.createFromParcel(parcel) : null);
                    parcel2.writeNoException();
                    return true;
                case 16:
                    parcel.enforceInterface("android.support.v4.media.session.IMediaSession");
                    mo66A(parcel.readInt() != 0 ? (Uri) Uri.CREATOR.createFromParcel(parcel) : null, parcel.readInt() != 0 ? (Bundle) Bundle.CREATOR.createFromParcel(parcel) : null);
                    parcel2.writeNoException();
                    return true;
                case 17:
                    parcel.enforceInterface("android.support.v4.media.session.IMediaSession");
                    mo79Q(parcel.readLong());
                    parcel2.writeNoException();
                    return true;
                case 18:
                    parcel.enforceInterface("android.support.v4.media.session.IMediaSession");
                    pause();
                    parcel2.writeNoException();
                    return true;
                case 19:
                    parcel.enforceInterface("android.support.v4.media.session.IMediaSession");
                    stop();
                    parcel2.writeNoException();
                    return true;
                case 20:
                    parcel.enforceInterface("android.support.v4.media.session.IMediaSession");
                    next();
                    parcel2.writeNoException();
                    return true;
                case 21:
                    parcel.enforceInterface("android.support.v4.media.session.IMediaSession");
                    previous();
                    parcel2.writeNoException();
                    return true;
                case 22:
                    parcel.enforceInterface("android.support.v4.media.session.IMediaSession");
                    mo106z();
                    parcel2.writeNoException();
                    return true;
                case 23:
                    parcel.enforceInterface("android.support.v4.media.session.IMediaSession");
                    mo78P();
                    parcel2.writeNoException();
                    return true;
                case 24:
                    parcel.enforceInterface("android.support.v4.media.session.IMediaSession");
                    seekTo(parcel.readLong());
                    parcel2.writeNoException();
                    return true;
                case 25:
                    parcel.enforceInterface("android.support.v4.media.session.IMediaSession");
                    mo91i(parcel.readInt() != 0 ? RatingCompat.CREATOR.createFromParcel(parcel) : null);
                    parcel2.writeNoException();
                    return true;
                case 26:
                    parcel.enforceInterface("android.support.v4.media.session.IMediaSession");
                    mo88f(parcel.readString(), parcel.readInt() != 0 ? (Bundle) Bundle.CREATOR.createFromParcel(parcel) : null);
                    parcel2.writeNoException();
                    return true;
                case 27:
                    parcel.enforceInterface("android.support.v4.media.session.IMediaSession");
                    MediaMetadataCompat mo101u = mo101u();
                    parcel2.writeNoException();
                    if (mo101u != null) {
                        parcel2.writeInt(1);
                        parcel2.writeBundle(mo101u.f32e);
                    } else {
                        parcel2.writeInt(0);
                    }
                    return true;
                case 28:
                    parcel.enforceInterface("android.support.v4.media.session.IMediaSession");
                    PlaybackStateCompat mo83a = mo83a();
                    parcel2.writeNoException();
                    if (mo83a != null) {
                        parcel2.writeInt(1);
                        mo83a.writeToParcel(parcel2, 1);
                    } else {
                        parcel2.writeInt(0);
                    }
                    return true;
                case 29:
                    parcel.enforceInterface("android.support.v4.media.session.IMediaSession");
                    List<MediaSessionCompat.QueueItem> mo77O = mo77O();
                    parcel2.writeNoException();
                    parcel2.writeTypedList(mo77O);
                    return true;
                case 30:
                    parcel.enforceInterface("android.support.v4.media.session.IMediaSession");
                    CharSequence mo100t = mo100t();
                    parcel2.writeNoException();
                    if (mo100t != null) {
                        parcel2.writeInt(1);
                        TextUtils.writeToParcel(mo100t, parcel2, 1);
                    } else {
                        parcel2.writeInt(0);
                    }
                    return true;
                case 31:
                    parcel.enforceInterface("android.support.v4.media.session.IMediaSession");
                    Bundle extras = getExtras();
                    parcel2.writeNoException();
                    if (extras != null) {
                        parcel2.writeInt(1);
                        extras.writeToParcel(parcel2, 1);
                    } else {
                        parcel2.writeInt(0);
                    }
                    return true;
                case 32:
                    parcel.enforceInterface("android.support.v4.media.session.IMediaSession");
                    int mo98p = mo98p();
                    parcel2.writeNoException();
                    parcel2.writeInt(mo98p);
                    return true;
                case 33:
                    parcel.enforceInterface("android.support.v4.media.session.IMediaSession");
                    mo84b();
                    parcel2.writeNoException();
                    return true;
                case 34:
                    parcel.enforceInterface("android.support.v4.media.session.IMediaSession");
                    mo102v(parcel.readString(), parcel.readInt() != 0 ? (Bundle) Bundle.CREATOR.createFromParcel(parcel) : null);
                    parcel2.writeNoException();
                    return true;
                case 35:
                    parcel.enforceInterface("android.support.v4.media.session.IMediaSession");
                    mo99q(parcel.readString(), parcel.readInt() != 0 ? (Bundle) Bundle.CREATOR.createFromParcel(parcel) : null);
                    parcel2.writeNoException();
                    return true;
                case 36:
                    parcel.enforceInterface("android.support.v4.media.session.IMediaSession");
                    mo93k(parcel.readInt() != 0 ? (Uri) Uri.CREATOR.createFromParcel(parcel) : null, parcel.readInt() != 0 ? (Bundle) Bundle.CREATOR.createFromParcel(parcel) : null);
                    parcel2.writeNoException();
                    return true;
                case 37:
                    parcel.enforceInterface("android.support.v4.media.session.IMediaSession");
                    int mo87e = mo87e();
                    parcel2.writeNoException();
                    parcel2.writeInt(mo87e);
                    return true;
                case 38:
                    parcel.enforceInterface("android.support.v4.media.session.IMediaSession");
                    boolean mo90h = mo90h();
                    parcel2.writeNoException();
                    parcel2.writeInt(mo90h ? 1 : 0);
                    return true;
                case 39:
                    parcel.enforceInterface("android.support.v4.media.session.IMediaSession");
                    mo86d(parcel.readInt());
                    parcel2.writeNoException();
                    return true;
                case 40:
                    parcel.enforceInterface("android.support.v4.media.session.IMediaSession");
                    mo80R(parcel.readInt() != 0);
                    parcel2.writeNoException();
                    return true;
                case 41:
                    parcel.enforceInterface("android.support.v4.media.session.IMediaSession");
                    mo96n(parcel.readInt() != 0 ? MediaDescriptionCompat.CREATOR.createFromParcel(parcel) : null);
                    parcel2.writeNoException();
                    return true;
                case 42:
                    parcel.enforceInterface("android.support.v4.media.session.IMediaSession");
                    mo70G(parcel.readInt() != 0 ? MediaDescriptionCompat.CREATOR.createFromParcel(parcel) : null, parcel.readInt());
                    parcel2.writeNoException();
                    return true;
                case 43:
                    parcel.enforceInterface("android.support.v4.media.session.IMediaSession");
                    mo94l(parcel.readInt() != 0 ? MediaDescriptionCompat.CREATOR.createFromParcel(parcel) : null);
                    parcel2.writeNoException();
                    return true;
                case 44:
                    parcel.enforceInterface("android.support.v4.media.session.IMediaSession");
                    mo73K(parcel.readInt());
                    parcel2.writeNoException();
                    return true;
                case 45:
                    parcel.enforceInterface("android.support.v4.media.session.IMediaSession");
                    boolean mo74L = mo74L();
                    parcel2.writeNoException();
                    parcel2.writeInt(mo74L ? 1 : 0);
                    return true;
                case 46:
                    parcel.enforceInterface("android.support.v4.media.session.IMediaSession");
                    mo71I(parcel.readInt() != 0);
                    parcel2.writeNoException();
                    return true;
                case 47:
                    parcel.enforceInterface("android.support.v4.media.session.IMediaSession");
                    int mo72J = mo72J();
                    parcel2.writeNoException();
                    parcel2.writeInt(mo72J);
                    return true;
                case 48:
                    parcel.enforceInterface("android.support.v4.media.session.IMediaSession");
                    mo82T(parcel.readInt());
                    parcel2.writeNoException();
                    return true;
                default:
                    return super.onTransact(i2, parcel, parcel2, i3);
            }
        }
    }

    /* renamed from: A */
    void mo66A(Uri uri, Bundle bundle);

    /* renamed from: B */
    boolean mo67B(KeyEvent keyEvent);

    /* renamed from: D */
    void mo68D(int i2, int i3, String str);

    /* renamed from: E */
    void mo69E(RatingCompat ratingCompat, Bundle bundle);

    /* renamed from: G */
    void mo70G(MediaDescriptionCompat mediaDescriptionCompat, int i2);

    /* renamed from: I */
    void mo71I(boolean z);

    /* renamed from: J */
    int mo72J();

    /* renamed from: K */
    void mo73K(int i2);

    /* renamed from: L */
    boolean mo74L();

    /* renamed from: M */
    void mo75M();

    /* renamed from: N */
    void mo76N(String str, Bundle bundle, MediaSessionCompat.ResultReceiverWrapper resultReceiverWrapper);

    /* renamed from: O */
    List<MediaSessionCompat.QueueItem> mo77O();

    /* renamed from: P */
    void mo78P();

    /* renamed from: Q */
    void mo79Q(long j2);

    /* renamed from: R */
    void mo80R(boolean z);

    /* renamed from: S */
    ParcelableVolumeInfo mo81S();

    /* renamed from: T */
    void mo82T(int i2);

    /* renamed from: a */
    PlaybackStateCompat mo83a();

    /* renamed from: b */
    void mo84b();

    /* renamed from: c */
    String mo85c();

    /* renamed from: d */
    void mo86d(int i2);

    /* renamed from: e */
    int mo87e();

    /* renamed from: f */
    void mo88f(String str, Bundle bundle);

    /* renamed from: g */
    void mo89g(InterfaceC4183a interfaceC4183a);

    Bundle getExtras();

    long getFlags();

    String getPackageName();

    /* renamed from: h */
    boolean mo90h();

    /* renamed from: i */
    void mo91i(RatingCompat ratingCompat);

    /* renamed from: j */
    void mo92j(int i2, int i3, String str);

    /* renamed from: k */
    void mo93k(Uri uri, Bundle bundle);

    /* renamed from: l */
    void mo94l(MediaDescriptionCompat mediaDescriptionCompat);

    /* renamed from: m */
    boolean mo95m();

    /* renamed from: n */
    void mo96n(MediaDescriptionCompat mediaDescriptionCompat);

    void next();

    /* renamed from: o */
    PendingIntent mo97o();

    /* renamed from: p */
    int mo98p();

    void pause();

    void previous();

    /* renamed from: q */
    void mo99q(String str, Bundle bundle);

    void seekTo(long j2);

    void stop();

    /* renamed from: t */
    CharSequence mo100t();

    /* renamed from: u */
    MediaMetadataCompat mo101u();

    /* renamed from: v */
    void mo102v(String str, Bundle bundle);

    /* renamed from: w */
    void mo103w(InterfaceC4183a interfaceC4183a);

    /* renamed from: x */
    void mo104x(String str, Bundle bundle);

    /* renamed from: y */
    void mo105y(String str, Bundle bundle);

    /* renamed from: z */
    void mo106z();
}
