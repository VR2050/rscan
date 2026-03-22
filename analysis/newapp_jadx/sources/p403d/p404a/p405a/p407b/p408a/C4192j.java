package p403d.p404a.p405a.p407b.p408a;

import android.net.Uri;
import android.os.Bundle;
import android.support.v4.media.session.MediaSessionCompat;
import p403d.p404a.p405a.p407b.p408a.InterfaceC4191i;

/* renamed from: d.a.a.b.a.j */
/* loaded from: classes.dex */
public class C4192j<T extends InterfaceC4191i> extends C4190h<T> {
    public C4192j(T t) {
        super(t);
    }

    @Override // android.media.session.MediaSession.Callback
    public void onPlayFromUri(Uri uri, Bundle bundle) {
        MediaSessionCompat.m23a(bundle);
        ((InterfaceC4191i) this.f10932a).mo51s(uri, bundle);
    }
}
