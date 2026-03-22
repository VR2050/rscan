package p403d.p404a.p405a.p407b.p408a;

import android.content.Intent;
import android.media.Rating;
import android.media.session.MediaSession;
import android.os.Bundle;
import android.os.ResultReceiver;
import android.support.v4.media.session.MediaSessionCompat;
import p403d.p404a.p405a.p407b.p408a.InterfaceC4189g;

/* renamed from: d.a.a.b.a.h */
/* loaded from: classes.dex */
public class C4190h<T extends InterfaceC4189g> extends MediaSession.Callback {

    /* renamed from: a */
    public final T f10932a;

    public C4190h(T t) {
        this.f10932a = t;
    }

    @Override // android.media.session.MediaSession.Callback
    public void onCommand(String str, Bundle bundle, ResultReceiver resultReceiver) {
        MediaSessionCompat.m23a(bundle);
        this.f10932a.mo40d(str, bundle, resultReceiver);
    }

    @Override // android.media.session.MediaSession.Callback
    public void onCustomAction(String str, Bundle bundle) {
        MediaSessionCompat.m23a(bundle);
        this.f10932a.mo50q(str, bundle);
    }

    @Override // android.media.session.MediaSession.Callback
    public void onFastForward() {
        this.f10932a.mo48o();
    }

    @Override // android.media.session.MediaSession.Callback
    public boolean onMediaButtonEvent(Intent intent) {
        return this.f10932a.mo45j(intent) || super.onMediaButtonEvent(intent);
    }

    @Override // android.media.session.MediaSession.Callback
    public void onPause() {
        this.f10932a.mo39c();
    }

    @Override // android.media.session.MediaSession.Callback
    public void onPlay() {
        this.f10932a.mo43g();
    }

    @Override // android.media.session.MediaSession.Callback
    public void onPlayFromMediaId(String str, Bundle bundle) {
        MediaSessionCompat.m23a(bundle);
        this.f10932a.mo47n(str, bundle);
    }

    @Override // android.media.session.MediaSession.Callback
    public void onPlayFromSearch(String str, Bundle bundle) {
        MediaSessionCompat.m23a(bundle);
        this.f10932a.mo46m(str, bundle);
    }

    @Override // android.media.session.MediaSession.Callback
    public void onRewind() {
        this.f10932a.mo38b();
    }

    @Override // android.media.session.MediaSession.Callback
    public void onSeekTo(long j2) {
        this.f10932a.mo49p(j2);
    }

    @Override // android.media.session.MediaSession.Callback
    public void onSetRating(Rating rating) {
        this.f10932a.mo42f(rating);
    }

    @Override // android.media.session.MediaSession.Callback
    public void onSkipToNext() {
        this.f10932a.mo37a();
    }

    @Override // android.media.session.MediaSession.Callback
    public void onSkipToPrevious() {
        this.f10932a.mo44i();
    }

    @Override // android.media.session.MediaSession.Callback
    public void onSkipToQueueItem(long j2) {
        this.f10932a.mo41e(j2);
    }

    @Override // android.media.session.MediaSession.Callback
    public void onStop() {
        this.f10932a.onStop();
    }
}
