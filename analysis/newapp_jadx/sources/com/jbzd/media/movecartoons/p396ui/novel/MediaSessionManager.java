package com.jbzd.media.movecartoons.p396ui.novel;

import android.content.Context;
import android.support.v4.media.session.MediaSessionCompat;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0007\bÆ\u0002\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\t\u0010\nJ\u0015\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0005\u0010\u0006R\u0018\u0010\u0007\u001a\u0004\u0018\u00010\u00048\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0007\u0010\b¨\u0006\u000b"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/novel/MediaSessionManager;", "", "Landroid/content/Context;", "context", "Landroid/support/v4/media/session/MediaSessionCompat;", "getMediaSession", "(Landroid/content/Context;)Landroid/support/v4/media/session/MediaSessionCompat;", "mediaSession", "Landroid/support/v4/media/session/MediaSessionCompat;", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class MediaSessionManager {

    @NotNull
    public static final MediaSessionManager INSTANCE = new MediaSessionManager();

    @Nullable
    private static MediaSessionCompat mediaSession;

    private MediaSessionManager() {
    }

    @NotNull
    public final MediaSessionCompat getMediaSession(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        if (mediaSession == null) {
            mediaSession = new MediaSessionCompat(context, "AudioPlayerService");
        }
        MediaSessionCompat mediaSessionCompat = mediaSession;
        Intrinsics.checkNotNull(mediaSessionCompat);
        return mediaSessionCompat;
    }
}
