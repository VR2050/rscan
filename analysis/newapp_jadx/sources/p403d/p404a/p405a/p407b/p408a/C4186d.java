package p403d.p404a.p405a.p407b.p408a;

import android.media.AudioAttributes;
import android.media.MediaMetadata;
import android.media.session.MediaController;
import android.media.session.MediaSession;
import android.media.session.PlaybackState;
import android.os.Build;
import android.os.Bundle;
import android.os.Parcel;
import android.support.v4.media.MediaDescriptionCompat;
import android.support.v4.media.MediaMetadataCompat;
import android.support.v4.media.session.MediaControllerCompat;
import android.support.v4.media.session.MediaSessionCompat;
import android.support.v4.media.session.PlaybackStateCompat;
import androidx.collection.ArrayMap;
import java.util.ArrayList;
import java.util.List;
import p403d.p404a.p405a.p407b.p408a.InterfaceC4185c;

/* renamed from: d.a.a.b.a.d */
/* loaded from: classes.dex */
public class C4186d<T extends InterfaceC4185c> extends MediaController.Callback {

    /* renamed from: a */
    public final T f10931a;

    public C4186d(T t) {
        this.f10931a = t;
    }

    @Override // android.media.session.MediaController.Callback
    public void onAudioInfoChanged(MediaController.PlaybackInfo playbackInfo) {
        T t = this.f10931a;
        playbackInfo.getPlaybackType();
        AudioAttributes audioAttributes = playbackInfo.getAudioAttributes();
        if ((audioAttributes.getFlags() & 1) != 1 && (audioAttributes.getFlags() & 4) != 4) {
            audioAttributes.getUsage();
        }
        playbackInfo.getVolumeControl();
        playbackInfo.getMaxVolume();
        playbackInfo.getCurrentVolume();
        ((MediaControllerCompat.AbstractC0017a.a) t).f47a.get();
    }

    @Override // android.media.session.MediaController.Callback
    public void onExtrasChanged(Bundle bundle) {
        MediaSessionCompat.m23a(bundle);
        ((MediaControllerCompat.AbstractC0017a.a) this.f10931a).f47a.get();
    }

    @Override // android.media.session.MediaController.Callback
    public void onMetadataChanged(MediaMetadata mediaMetadata) {
        if (((MediaControllerCompat.AbstractC0017a.a) this.f10931a).f47a.get() != null) {
            ArrayMap<String, Integer> arrayMap = MediaMetadataCompat.f31c;
            if (mediaMetadata != null) {
                Parcel obtain = Parcel.obtain();
                mediaMetadata.writeToParcel(obtain, 0);
                obtain.setDataPosition(0);
                MediaMetadataCompat createFromParcel = MediaMetadataCompat.CREATOR.createFromParcel(obtain);
                obtain.recycle();
                createFromParcel.f33f = mediaMetadata;
            }
        }
    }

    @Override // android.media.session.MediaController.Callback
    public void onPlaybackStateChanged(PlaybackState playbackState) {
        ArrayList arrayList;
        PlaybackStateCompat.CustomAction customAction;
        MediaControllerCompat.AbstractC0017a abstractC0017a = ((MediaControllerCompat.AbstractC0017a.a) this.f10931a).f47a.get();
        if (abstractC0017a == null || abstractC0017a.f46a != null) {
            return;
        }
        if (playbackState != null) {
            List<PlaybackState.CustomAction> customActions = playbackState.getCustomActions();
            if (customActions != null) {
                ArrayList arrayList2 = new ArrayList(customActions.size());
                for (PlaybackState.CustomAction customAction2 : customActions) {
                    if (customAction2 != null) {
                        PlaybackState.CustomAction customAction3 = customAction2;
                        customAction = new PlaybackStateCompat.CustomAction(customAction3.getAction(), customAction3.getName(), customAction3.getIcon(), customAction3.getExtras());
                        customAction.f96h = customAction2;
                    } else {
                        customAction = null;
                    }
                    arrayList2.add(customAction);
                }
                arrayList = arrayList2;
            } else {
                arrayList = null;
            }
            new PlaybackStateCompat(playbackState.getState(), playbackState.getPosition(), playbackState.getBufferedPosition(), playbackState.getPlaybackSpeed(), playbackState.getActions(), 0, playbackState.getErrorMessage(), playbackState.getLastPositionUpdateTime(), arrayList, playbackState.getActiveQueueItemId(), Build.VERSION.SDK_INT >= 22 ? playbackState.getExtras() : null).f91o = playbackState;
        }
    }

    @Override // android.media.session.MediaController.Callback
    public void onQueueChanged(List<MediaSession.QueueItem> list) {
        MediaSessionCompat.QueueItem queueItem;
        if (((MediaControllerCompat.AbstractC0017a.a) this.f10931a).f47a.get() == null || list == null) {
            return;
        }
        ArrayList arrayList = new ArrayList();
        for (MediaSession.QueueItem queueItem2 : list) {
            if (queueItem2 != null) {
                MediaSession.QueueItem queueItem3 = queueItem2;
                queueItem = new MediaSessionCompat.QueueItem(queueItem2, MediaDescriptionCompat.m10b(queueItem3.getDescription()), queueItem3.getQueueId());
            } else {
                queueItem = null;
            }
            arrayList.add(queueItem);
        }
    }

    @Override // android.media.session.MediaController.Callback
    public void onQueueTitleChanged(CharSequence charSequence) {
        ((MediaControllerCompat.AbstractC0017a.a) this.f10931a).f47a.get();
    }

    @Override // android.media.session.MediaController.Callback
    public void onSessionDestroyed() {
        ((MediaControllerCompat.AbstractC0017a.a) this.f10931a).f47a.get();
    }

    @Override // android.media.session.MediaController.Callback
    public void onSessionEvent(String str, Bundle bundle) {
        MediaSessionCompat.m23a(bundle);
        MediaControllerCompat.AbstractC0017a abstractC0017a = ((MediaControllerCompat.AbstractC0017a.a) this.f10931a).f47a.get();
        if (abstractC0017a != null) {
            InterfaceC4183a interfaceC4183a = abstractC0017a.f46a;
        }
    }
}
