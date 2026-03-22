package p403d.p404a.p405a.p407b.p408a;

import android.net.Uri;
import android.os.Bundle;
import android.support.v4.media.session.MediaSessionCompat;
import p403d.p404a.p405a.p407b.p408a.InterfaceC4193k;

/* renamed from: d.a.a.b.a.l */
/* loaded from: classes.dex */
public class C4194l<T extends InterfaceC4193k> extends C4192j<T> {
    public C4194l(T t) {
        super(t);
    }

    @Override // android.media.session.MediaSession.Callback
    public void onPrepare() {
        ((InterfaceC4193k) this.f10932a).mo53k();
    }

    @Override // android.media.session.MediaSession.Callback
    public void onPrepareFromMediaId(String str, Bundle bundle) {
        MediaSessionCompat.m23a(bundle);
        ((InterfaceC4193k) this.f10932a).mo52h(str, bundle);
    }

    @Override // android.media.session.MediaSession.Callback
    public void onPrepareFromSearch(String str, Bundle bundle) {
        MediaSessionCompat.m23a(bundle);
        ((InterfaceC4193k) this.f10932a).mo55r(str, bundle);
    }

    @Override // android.media.session.MediaSession.Callback
    public void onPrepareFromUri(Uri uri, Bundle bundle) {
        MediaSessionCompat.m23a(bundle);
        ((InterfaceC4193k) this.f10932a).mo54l(uri, bundle);
    }
}
