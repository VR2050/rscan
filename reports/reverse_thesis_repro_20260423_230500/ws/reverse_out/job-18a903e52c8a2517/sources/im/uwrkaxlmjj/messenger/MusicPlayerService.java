package im.uwrkaxlmjj.messenger;

import android.app.Notification;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.Drawable;
import android.media.AudioManager;
import android.media.MediaMetadata;
import android.media.RemoteControlClient;
import android.media.session.MediaSession;
import android.media.session.PlaybackState;
import android.os.Build;
import android.os.IBinder;
import android.text.TextUtils;
import android.widget.RemoteViews;
import androidx.core.app.NotificationCompat;
import com.google.android.exoplayer2.C;
import com.google.android.exoplayer2.extractor.ts.PsExtractor;
import im.uwrkaxlmjj.messenger.ImageReceiver;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.audioinfo.AudioInfo;
import im.uwrkaxlmjj.ui.LaunchActivity;
import java.io.File;

/* JADX INFO: loaded from: classes2.dex */
public class MusicPlayerService extends Service implements NotificationCenter.NotificationCenterDelegate {
    private static final int ID_NOTIFICATION = 5;
    public static final String NOTIFY_CLOSE = "im.uwrkaxlmjj.android.musicplayer.close";
    public static final String NOTIFY_NEXT = "im.uwrkaxlmjj.android.musicplayer.next";
    public static final String NOTIFY_PAUSE = "im.uwrkaxlmjj.android.musicplayer.pause";
    public static final String NOTIFY_PLAY = "im.uwrkaxlmjj.android.musicplayer.play";
    public static final String NOTIFY_PREVIOUS = "im.uwrkaxlmjj.android.musicplayer.previous";
    public static final String NOTIFY_SEEK = "im.uwrkaxlmjj.android.musicplayer.seek";
    private static boolean supportBigNotifications;
    private static boolean supportLockScreenControls;
    private Bitmap albumArtPlaceholder;
    private AudioManager audioManager;
    private BroadcastReceiver headsetPlugReceiver = new BroadcastReceiver() { // from class: im.uwrkaxlmjj.messenger.MusicPlayerService.1
        @Override // android.content.BroadcastReceiver
        public void onReceive(Context context, Intent intent) {
            if ("android.media.AUDIO_BECOMING_NOISY".equals(intent.getAction())) {
                MediaController.getInstance().lambda$startAudioAgain$5$MediaController(MediaController.getInstance().getPlayingMessageObject());
            }
        }
    };
    private ImageReceiver imageReceiver;
    private String loadingFilePath;
    private MediaSession mediaSession;
    private int notificationMessageID;
    private PlaybackState.Builder playbackState;
    private RemoteControlClient remoteControlClient;

    static {
        boolean z = true;
        supportBigNotifications = Build.VERSION.SDK_INT >= 16;
        if (Build.VERSION.SDK_INT >= 21 && TextUtils.isEmpty(AndroidUtilities.getSystemProperty("ro.miui.ui.version.code"))) {
            z = false;
        }
        supportLockScreenControls = z;
    }

    @Override // android.app.Service
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override // android.app.Service
    public void onCreate() {
        this.audioManager = (AudioManager) getSystemService("audio");
        for (int a = 0; a < 3; a++) {
            NotificationCenter.getInstance(a).addObserver(this, NotificationCenter.messagePlayingDidSeek);
            NotificationCenter.getInstance(a).addObserver(this, NotificationCenter.messagePlayingPlayStateChanged);
            NotificationCenter.getInstance(a).addObserver(this, NotificationCenter.httpFileDidLoad);
            NotificationCenter.getInstance(a).addObserver(this, NotificationCenter.fileDidLoad);
        }
        ImageReceiver imageReceiver = new ImageReceiver(null);
        this.imageReceiver = imageReceiver;
        imageReceiver.setDelegate(new ImageReceiver.ImageReceiverDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MusicPlayerService$ZCkRAQWnklalf2JPusbhw0z2bp4
            @Override // im.uwrkaxlmjj.messenger.ImageReceiver.ImageReceiverDelegate
            public final void didSetImage(ImageReceiver imageReceiver2, boolean z, boolean z2) {
                this.f$0.lambda$onCreate$0$MusicPlayerService(imageReceiver2, z, z2);
            }

            @Override // im.uwrkaxlmjj.messenger.ImageReceiver.ImageReceiverDelegate
            public /* synthetic */ void onAnimationReady(ImageReceiver imageReceiver2) {
                ImageReceiver.ImageReceiverDelegate.CC.$default$onAnimationReady(this, imageReceiver2);
            }
        });
        if (Build.VERSION.SDK_INT >= 21) {
            this.mediaSession = new MediaSession(this, "AppAudioPlayer");
            this.playbackState = new PlaybackState.Builder();
            this.albumArtPlaceholder = Bitmap.createBitmap(AndroidUtilities.dp(102.0f), AndroidUtilities.dp(102.0f), Bitmap.Config.ARGB_8888);
            Drawable placeholder = getResources().getDrawable(mpEIGo.juqQQs.esbSDO.R.drawable.nocover_big);
            placeholder.setBounds(0, 0, this.albumArtPlaceholder.getWidth(), this.albumArtPlaceholder.getHeight());
            placeholder.draw(new Canvas(this.albumArtPlaceholder));
            this.mediaSession.setCallback(new MediaSession.Callback() { // from class: im.uwrkaxlmjj.messenger.MusicPlayerService.2
                @Override // android.media.session.MediaSession.Callback
                public void onPlay() {
                    MediaController.getInstance().playMessage(MediaController.getInstance().getPlayingMessageObject());
                }

                @Override // android.media.session.MediaSession.Callback
                public void onPause() {
                    MediaController.getInstance().lambda$startAudioAgain$5$MediaController(MediaController.getInstance().getPlayingMessageObject());
                }

                @Override // android.media.session.MediaSession.Callback
                public void onSkipToNext() {
                    MediaController.getInstance().playNextMessage();
                }

                @Override // android.media.session.MediaSession.Callback
                public void onSkipToPrevious() {
                    MediaController.getInstance().playPreviousMessage();
                }

                @Override // android.media.session.MediaSession.Callback
                public void onSeekTo(long pos) {
                    MessageObject object = MediaController.getInstance().getPlayingMessageObject();
                    if (object != null) {
                        MediaController.getInstance().seekToProgress(object, (pos / 1000) / object.getDuration());
                        MusicPlayerService.this.updatePlaybackState(pos);
                    }
                }

                @Override // android.media.session.MediaSession.Callback
                public void onStop() {
                }
            });
            this.mediaSession.setActive(true);
        }
        registerReceiver(this.headsetPlugReceiver, new IntentFilter("android.media.AUDIO_BECOMING_NOISY"));
        super.onCreate();
    }

    public /* synthetic */ void lambda$onCreate$0$MusicPlayerService(ImageReceiver imageReceiver, boolean set, boolean thumb) {
        if (set && !TextUtils.isEmpty(this.loadingFilePath)) {
            MessageObject messageObject = MediaController.getInstance().getPlayingMessageObject();
            if (messageObject != null) {
                createNotification(messageObject, true);
            }
            this.loadingFilePath = null;
        }
    }

    @Override // android.app.Service
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null) {
            try {
                if ((getPackageName() + ".STOP_PLAYER").equals(intent.getAction())) {
                    MediaController.getInstance().cleanupPlayer(true, true);
                    return 2;
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        MessageObject messageObject = MediaController.getInstance().getPlayingMessageObject();
        if (messageObject == null) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$DiLN8vzbogzTdaYeF-4xBVhD8Zs
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.stopSelf();
                }
            });
            return 1;
        }
        if (supportLockScreenControls) {
            ComponentName remoteComponentName = new ComponentName(getApplicationContext(), MusicPlayerReceiver.class.getName());
            try {
                if (this.remoteControlClient == null) {
                    this.audioManager.registerMediaButtonEventReceiver(remoteComponentName);
                    Intent mediaButtonIntent = new Intent("android.intent.action.MEDIA_BUTTON");
                    mediaButtonIntent.setComponent(remoteComponentName);
                    PendingIntent mediaPendingIntent = PendingIntent.getBroadcast(this, 0, mediaButtonIntent, 0);
                    RemoteControlClient remoteControlClient = new RemoteControlClient(mediaPendingIntent);
                    this.remoteControlClient = remoteControlClient;
                    this.audioManager.registerRemoteControlClient(remoteControlClient);
                }
                this.remoteControlClient.setTransportControlFlags(PsExtractor.PRIVATE_STREAM_1);
            } catch (Exception e2) {
                FileLog.e(e2);
            }
        }
        createNotification(messageObject, false);
        return 1;
    }

    private Bitmap loadArtworkFromUrl(String artworkUrl, boolean big, boolean tryLoad) {
        ImageLoader.getHttpFileName(artworkUrl);
        File path = ImageLoader.getHttpFilePath(artworkUrl, "jpg");
        if (path.exists()) {
            return ImageLoader.loadBitmap(path.getAbsolutePath(), null, big ? 600.0f : 100.0f, big ? 600.0f : 100.0f, false);
        }
        if (tryLoad) {
            this.loadingFilePath = path.getAbsolutePath();
            if (!big) {
                this.imageReceiver.setImage(artworkUrl, "48_48", null, null, 0);
            }
        } else {
            this.loadingFilePath = null;
        }
        return null;
    }

    private void createNotification(MessageObject messageObject, boolean forBitmap) {
        AudioInfo audioInfo;
        int i;
        int i2;
        Bitmap albumArt;
        Bitmap albumArt2;
        String songName = messageObject.getMusicTitle();
        String authorName = messageObject.getMusicAuthor();
        AudioInfo audioInfo2 = MediaController.getInstance().getAudioInfo();
        Intent intent = new Intent(ApplicationLoader.applicationContext, (Class<?>) LaunchActivity.class);
        intent.setAction("com.tmessages.openplayer");
        intent.addCategory("android.intent.category.LAUNCHER");
        PendingIntent contentIntent = PendingIntent.getActivity(ApplicationLoader.applicationContext, 0, intent, 0);
        String artworkUrl = messageObject.getArtworkUrl(true);
        String artworkUrlBig = messageObject.getArtworkUrl(false);
        long duration = messageObject.getDuration() * 1000;
        Bitmap albumArt3 = audioInfo2 != null ? audioInfo2.getSmallCover() : null;
        Bitmap fullAlbumArt = audioInfo2 != null ? audioInfo2.getCover() : null;
        this.loadingFilePath = null;
        this.imageReceiver.setImageBitmap((BitmapDrawable) null);
        if (albumArt3 != null || TextUtils.isEmpty(artworkUrl)) {
            this.loadingFilePath = FileLoader.getPathToAttach(messageObject.getDocument()).getAbsolutePath();
        } else {
            fullAlbumArt = loadArtworkFromUrl(artworkUrlBig, true, !forBitmap);
            if (fullAlbumArt == null) {
                Bitmap bitmapLoadArtworkFromUrl = loadArtworkFromUrl(artworkUrl, false, !forBitmap);
                albumArt3 = bitmapLoadArtworkFromUrl;
                fullAlbumArt = bitmapLoadArtworkFromUrl;
            } else {
                albumArt3 = loadArtworkFromUrl(artworkUrlBig, false, !forBitmap);
            }
        }
        Bitmap albumArt4 = albumArt3;
        String album = "";
        if (Build.VERSION.SDK_INT >= 21) {
            boolean isPlaying = !MediaController.getInstance().isMessagePaused();
            PendingIntent pendingPrev = PendingIntent.getBroadcast(getApplicationContext(), 0, new Intent(NOTIFY_PREVIOUS).setComponent(new ComponentName(this, (Class<?>) MusicPlayerReceiver.class)), C.ENCODING_PCM_MU_LAW);
            PendingIntent pendingStop = PendingIntent.getService(getApplicationContext(), 0, new Intent(this, getClass()).setAction(getPackageName() + ".STOP_PLAYER"), C.ENCODING_PCM_MU_LAW);
            PendingIntent pendingPlaypause = PendingIntent.getBroadcast(getApplicationContext(), 0, new Intent(isPlaying ? NOTIFY_PAUSE : NOTIFY_PLAY).setComponent(new ComponentName(this, (Class<?>) MusicPlayerReceiver.class)), C.ENCODING_PCM_MU_LAW);
            PendingIntent pendingNext = PendingIntent.getBroadcast(getApplicationContext(), 0, new Intent(NOTIFY_NEXT).setComponent(new ComponentName(this, (Class<?>) MusicPlayerReceiver.class)), C.ENCODING_PCM_MU_LAW);
            PendingIntent.getBroadcast(getApplicationContext(), 0, new Intent(NOTIFY_SEEK).setComponent(new ComponentName(this, (Class<?>) MusicPlayerReceiver.class)), C.ENCODING_PCM_MU_LAW);
            Notification.Builder bldr = new Notification.Builder(this);
            bldr.setSmallIcon(mpEIGo.juqQQs.esbSDO.R.drawable.player).setOngoing(isPlaying).setContentTitle(songName).setContentText(authorName).setSubText(audioInfo2 != null ? audioInfo2.getAlbum() : null).setContentIntent(contentIntent).setDeleteIntent(pendingStop).setShowWhen(false).setCategory(NotificationCompat.CATEGORY_TRANSPORT).setPriority(2).setStyle(new Notification.MediaStyle().setMediaSession(this.mediaSession.getSessionToken()).setShowActionsInCompactView(0, 1, 2));
            if (Build.VERSION.SDK_INT >= 26) {
                NotificationsController.checkOtherNotificationsChannel();
                bldr.setChannelId(NotificationsController.OTHER_NOTIFICATIONS_CHANNEL);
            }
            if (albumArt4 != null) {
                albumArt = albumArt4;
                bldr.setLargeIcon(albumArt);
            } else {
                albumArt = albumArt4;
                bldr.setLargeIcon(this.albumArtPlaceholder);
            }
            if (MediaController.getInstance().isDownloadingCurrentMessage()) {
                audioInfo = audioInfo2;
                albumArt2 = albumArt;
                this.playbackState.setState(6, 0L, 1.0f).setActions(0L);
                bldr.addAction(new Notification.Action.Builder(mpEIGo.juqQQs.esbSDO.R.drawable.ic_action_previous, "", pendingPrev).build()).addAction(new Notification.Action.Builder(mpEIGo.juqQQs.esbSDO.R.drawable.loading_animation2, "", (PendingIntent) null).build()).addAction(new Notification.Action.Builder(mpEIGo.juqQQs.esbSDO.R.drawable.ic_action_next, "", pendingNext).build());
            } else {
                audioInfo = audioInfo2;
                albumArt2 = albumArt;
                this.playbackState.setState(isPlaying ? 3 : 2, ((long) MediaController.getInstance().getPlayingMessageObject().audioProgressSec) * 1000, isPlaying ? 1.0f : 0.0f).setActions(822L);
                bldr.addAction(new Notification.Action.Builder(mpEIGo.juqQQs.esbSDO.R.drawable.ic_action_previous, "", pendingPrev).build()).addAction(new Notification.Action.Builder(isPlaying ? mpEIGo.juqQQs.esbSDO.R.drawable.ic_action_pause : mpEIGo.juqQQs.esbSDO.R.drawable.ic_action_play, "", pendingPlaypause).build()).addAction(new Notification.Action.Builder(mpEIGo.juqQQs.esbSDO.R.drawable.ic_action_next, "", pendingNext).build());
            }
            this.mediaSession.setPlaybackState(this.playbackState.build());
            MediaMetadata.Builder meta = new MediaMetadata.Builder().putBitmap("android.media.metadata.ALBUM_ART", fullAlbumArt).putString("android.media.metadata.ALBUM_ARTIST", authorName).putLong("android.media.metadata.DURATION", duration).putString("android.media.metadata.TITLE", songName).putString("android.media.metadata.ALBUM", audioInfo != null ? audioInfo.getAlbum() : null);
            this.mediaSession.setMetadata(meta.build());
            bldr.setVisibility(1);
            Notification notification = bldr.build();
            if (isPlaying) {
                startForeground(5, notification);
            } else {
                stopForeground(false);
                NotificationManager nm = (NotificationManager) getSystemService("notification");
                nm.notify(5, notification);
            }
        } else {
            audioInfo = audioInfo2;
            RemoteViews simpleContentView = new RemoteViews(getApplicationContext().getPackageName(), mpEIGo.juqQQs.esbSDO.R.layout.player_small_notification);
            RemoteViews expandedView = null;
            if (supportBigNotifications) {
                expandedView = new RemoteViews(getApplicationContext().getPackageName(), mpEIGo.juqQQs.esbSDO.R.layout.player_big_notification);
            }
            Notification notification2 = new NotificationCompat.Builder(getApplicationContext()).setSmallIcon(mpEIGo.juqQQs.esbSDO.R.drawable.player).setContentIntent(contentIntent).setChannelId(NotificationsController.OTHER_NOTIFICATIONS_CHANNEL).setContentTitle(songName).build();
            notification2.contentView = simpleContentView;
            if (supportBigNotifications) {
                notification2.bigContentView = expandedView;
            }
            setListeners(simpleContentView);
            if (supportBigNotifications) {
                setListeners(expandedView);
            }
            if (albumArt4 != null) {
                notification2.contentView.setImageViewBitmap(mpEIGo.juqQQs.esbSDO.R.attr.player_album_art, albumArt4);
                if (supportBigNotifications) {
                    notification2.bigContentView.setImageViewBitmap(mpEIGo.juqQQs.esbSDO.R.attr.player_album_art, albumArt4);
                }
            } else {
                notification2.contentView.setImageViewResource(mpEIGo.juqQQs.esbSDO.R.attr.player_album_art, mpEIGo.juqQQs.esbSDO.R.drawable.nocover_small);
                if (supportBigNotifications) {
                    notification2.bigContentView.setImageViewResource(mpEIGo.juqQQs.esbSDO.R.attr.player_album_art, mpEIGo.juqQQs.esbSDO.R.drawable.nocover_big);
                }
            }
            if (MediaController.getInstance().isDownloadingCurrentMessage()) {
                notification2.contentView.setViewVisibility(mpEIGo.juqQQs.esbSDO.R.attr.player_pause, 8);
                notification2.contentView.setViewVisibility(mpEIGo.juqQQs.esbSDO.R.attr.player_play, 8);
                notification2.contentView.setViewVisibility(mpEIGo.juqQQs.esbSDO.R.attr.player_next, 8);
                notification2.contentView.setViewVisibility(mpEIGo.juqQQs.esbSDO.R.attr.player_previous, 8);
                notification2.contentView.setViewVisibility(mpEIGo.juqQQs.esbSDO.R.attr.player_progress_bar, 0);
                if (supportBigNotifications) {
                    notification2.bigContentView.setViewVisibility(mpEIGo.juqQQs.esbSDO.R.attr.player_pause, 8);
                    notification2.bigContentView.setViewVisibility(mpEIGo.juqQQs.esbSDO.R.attr.player_play, 8);
                    notification2.bigContentView.setViewVisibility(mpEIGo.juqQQs.esbSDO.R.attr.player_next, 8);
                    notification2.bigContentView.setViewVisibility(mpEIGo.juqQQs.esbSDO.R.attr.player_previous, 8);
                    notification2.bigContentView.setViewVisibility(mpEIGo.juqQQs.esbSDO.R.attr.player_progress_bar, 0);
                }
            } else {
                notification2.contentView.setViewVisibility(mpEIGo.juqQQs.esbSDO.R.attr.player_progress_bar, 8);
                notification2.contentView.setViewVisibility(mpEIGo.juqQQs.esbSDO.R.attr.player_next, 0);
                notification2.contentView.setViewVisibility(mpEIGo.juqQQs.esbSDO.R.attr.player_previous, 0);
                if (!supportBigNotifications) {
                    i = 8;
                } else {
                    notification2.bigContentView.setViewVisibility(mpEIGo.juqQQs.esbSDO.R.attr.player_next, 0);
                    notification2.bigContentView.setViewVisibility(mpEIGo.juqQQs.esbSDO.R.attr.player_previous, 0);
                    i = 8;
                    notification2.bigContentView.setViewVisibility(mpEIGo.juqQQs.esbSDO.R.attr.player_progress_bar, 8);
                }
                if (MediaController.getInstance().isMessagePaused()) {
                    notification2.contentView.setViewVisibility(mpEIGo.juqQQs.esbSDO.R.attr.player_pause, i);
                    notification2.contentView.setViewVisibility(mpEIGo.juqQQs.esbSDO.R.attr.player_play, 0);
                    if (supportBigNotifications) {
                        notification2.bigContentView.setViewVisibility(mpEIGo.juqQQs.esbSDO.R.attr.player_pause, i);
                        notification2.bigContentView.setViewVisibility(mpEIGo.juqQQs.esbSDO.R.attr.player_play, 0);
                    }
                } else {
                    notification2.contentView.setViewVisibility(mpEIGo.juqQQs.esbSDO.R.attr.player_pause, 0);
                    notification2.contentView.setViewVisibility(mpEIGo.juqQQs.esbSDO.R.attr.player_play, 8);
                    if (supportBigNotifications) {
                        notification2.bigContentView.setViewVisibility(mpEIGo.juqQQs.esbSDO.R.attr.player_pause, 0);
                        notification2.bigContentView.setViewVisibility(mpEIGo.juqQQs.esbSDO.R.attr.player_play, 8);
                    }
                }
            }
            notification2.contentView.setTextViewText(mpEIGo.juqQQs.esbSDO.R.attr.player_song_name, songName);
            notification2.contentView.setTextViewText(mpEIGo.juqQQs.esbSDO.R.attr.player_author_name, authorName);
            if (supportBigNotifications) {
                notification2.bigContentView.setTextViewText(mpEIGo.juqQQs.esbSDO.R.attr.player_song_name, songName);
                notification2.bigContentView.setTextViewText(mpEIGo.juqQQs.esbSDO.R.attr.player_author_name, authorName);
                RemoteViews remoteViews = notification2.bigContentView;
                if (audioInfo != null && !TextUtils.isEmpty(audioInfo.getAlbum())) {
                    album = audioInfo.getAlbum();
                }
                remoteViews.setTextViewText(mpEIGo.juqQQs.esbSDO.R.attr.player_album_title, album);
            }
            notification2.flags |= 2;
            startForeground(5, notification2);
        }
        if (this.remoteControlClient != null) {
            int currentID = MediaController.getInstance().getPlayingMessageObject().getId();
            if (this.notificationMessageID == currentID) {
                i2 = 2;
            } else {
                this.notificationMessageID = currentID;
                RemoteControlClient.MetadataEditor metadataEditor = this.remoteControlClient.editMetadata(true);
                i2 = 2;
                metadataEditor.putString(2, authorName);
                metadataEditor.putString(7, songName);
                if (audioInfo != null && !TextUtils.isEmpty(audioInfo.getAlbum())) {
                    metadataEditor.putString(1, audioInfo.getAlbum());
                }
                metadataEditor.putLong(9, ((long) MediaController.getInstance().getPlayingMessageObject().audioPlayerDuration) * 1000);
                if (fullAlbumArt != null) {
                    try {
                        metadataEditor.putBitmap(100, fullAlbumArt);
                    } catch (Throwable e) {
                        FileLog.e(e);
                    }
                }
                metadataEditor.apply();
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.MusicPlayerService.3
                    @Override // java.lang.Runnable
                    public void run() {
                        if (MusicPlayerService.this.remoteControlClient == null || MediaController.getInstance().getPlayingMessageObject() == null) {
                            return;
                        }
                        if (MediaController.getInstance().getPlayingMessageObject().audioPlayerDuration != C.TIME_UNSET) {
                            RemoteControlClient.MetadataEditor metadataEditor2 = MusicPlayerService.this.remoteControlClient.editMetadata(false);
                            metadataEditor2.putLong(9, ((long) MediaController.getInstance().getPlayingMessageObject().audioPlayerDuration) * 1000);
                            metadataEditor2.apply();
                            if (Build.VERSION.SDK_INT < 18) {
                                MusicPlayerService.this.remoteControlClient.setPlaybackState(MediaController.getInstance().isMessagePaused() ? 2 : 3);
                                return;
                            } else {
                                MusicPlayerService.this.remoteControlClient.setPlaybackState(MediaController.getInstance().isMessagePaused() ? 2 : 3, Math.max(((long) MediaController.getInstance().getPlayingMessageObject().audioProgressSec) * 1000, 100L), MediaController.getInstance().isMessagePaused() ? 0.0f : 1.0f);
                                return;
                            }
                        }
                        AndroidUtilities.runOnUIThread(this, 500L);
                    }
                }, 1000L);
            }
            if (MediaController.getInstance().isDownloadingCurrentMessage()) {
                this.remoteControlClient.setPlaybackState(8);
                return;
            }
            RemoteControlClient.MetadataEditor metadataEditor2 = this.remoteControlClient.editMetadata(false);
            metadataEditor2.putLong(9, ((long) MediaController.getInstance().getPlayingMessageObject().audioPlayerDuration) * 1000);
            metadataEditor2.apply();
            if (Build.VERSION.SDK_INT < 18) {
                RemoteControlClient remoteControlClient = this.remoteControlClient;
                if (!MediaController.getInstance().isMessagePaused()) {
                    i2 = 3;
                }
                remoteControlClient.setPlaybackState(i2);
                return;
            }
            RemoteControlClient remoteControlClient2 = this.remoteControlClient;
            if (!MediaController.getInstance().isMessagePaused()) {
                i2 = 3;
            }
            remoteControlClient2.setPlaybackState(i2, Math.max(((long) MediaController.getInstance().getPlayingMessageObject().audioProgressSec) * 1000, 100L), MediaController.getInstance().isMessagePaused() ? 0.0f : 1.0f);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updatePlaybackState(long seekTo) {
        if (Build.VERSION.SDK_INT < 21) {
            return;
        }
        boolean isPlaying = !MediaController.getInstance().isMessagePaused();
        if (MediaController.getInstance().isDownloadingCurrentMessage()) {
            this.playbackState.setState(6, 0L, 1.0f).setActions(0L);
        } else {
            this.playbackState.setState(isPlaying ? 3 : 2, seekTo, isPlaying ? 1.0f : 0.0f).setActions(822L);
        }
        this.mediaSession.setPlaybackState(this.playbackState.build());
    }

    public void setListeners(RemoteViews view) {
        PendingIntent pendingIntent = PendingIntent.getBroadcast(getApplicationContext(), 0, new Intent(NOTIFY_PREVIOUS), 134217728);
        view.setOnClickPendingIntent(mpEIGo.juqQQs.esbSDO.R.attr.player_previous, pendingIntent);
        PendingIntent pendingIntent2 = PendingIntent.getBroadcast(getApplicationContext(), 0, new Intent(NOTIFY_CLOSE), 134217728);
        view.setOnClickPendingIntent(mpEIGo.juqQQs.esbSDO.R.attr.player_close, pendingIntent2);
        PendingIntent pendingIntent3 = PendingIntent.getBroadcast(getApplicationContext(), 0, new Intent(NOTIFY_PAUSE), 134217728);
        view.setOnClickPendingIntent(mpEIGo.juqQQs.esbSDO.R.attr.player_pause, pendingIntent3);
        PendingIntent pendingIntent4 = PendingIntent.getBroadcast(getApplicationContext(), 0, new Intent(NOTIFY_NEXT), 134217728);
        view.setOnClickPendingIntent(mpEIGo.juqQQs.esbSDO.R.attr.player_next, pendingIntent4);
        PendingIntent pendingIntent5 = PendingIntent.getBroadcast(getApplicationContext(), 0, new Intent(NOTIFY_PLAY), 134217728);
        view.setOnClickPendingIntent(mpEIGo.juqQQs.esbSDO.R.attr.player_play, pendingIntent5);
    }

    @Override // android.app.Service
    public void onDestroy() {
        unregisterReceiver(this.headsetPlugReceiver);
        super.onDestroy();
        RemoteControlClient remoteControlClient = this.remoteControlClient;
        if (remoteControlClient != null) {
            RemoteControlClient.MetadataEditor metadataEditor = remoteControlClient.editMetadata(true);
            metadataEditor.clear();
            metadataEditor.apply();
            this.audioManager.unregisterRemoteControlClient(this.remoteControlClient);
        }
        if (Build.VERSION.SDK_INT >= 21) {
            this.mediaSession.release();
        }
        for (int a = 0; a < 3; a++) {
            NotificationCenter.getInstance(a).removeObserver(this, NotificationCenter.messagePlayingDidSeek);
            NotificationCenter.getInstance(a).removeObserver(this, NotificationCenter.messagePlayingPlayStateChanged);
            NotificationCenter.getInstance(a).removeObserver(this, NotificationCenter.httpFileDidLoad);
            NotificationCenter.getInstance(a).removeObserver(this, NotificationCenter.fileDidLoad);
        }
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        String str;
        String str2;
        if (id == NotificationCenter.messagePlayingPlayStateChanged) {
            MessageObject messageObject = MediaController.getInstance().getPlayingMessageObject();
            if (messageObject != null) {
                createNotification(messageObject, false);
                return;
            } else {
                stopSelf();
                return;
            }
        }
        if (id == NotificationCenter.messagePlayingDidSeek) {
            MessageObject messageObject2 = MediaController.getInstance().getPlayingMessageObject();
            if (this.remoteControlClient != null && Build.VERSION.SDK_INT >= 18) {
                long progress = ((long) Math.round(messageObject2.audioPlayerDuration * ((Float) args[1]).floatValue())) * 1000;
                this.remoteControlClient.setPlaybackState(MediaController.getInstance().isMessagePaused() ? 2 : 3, progress, MediaController.getInstance().isMessagePaused() ? 0.0f : 1.0f);
                return;
            }
            return;
        }
        if (id == NotificationCenter.httpFileDidLoad) {
            String path = (String) args[0];
            MessageObject messageObject3 = MediaController.getInstance().getPlayingMessageObject();
            if (messageObject3 != null && (str2 = this.loadingFilePath) != null && str2.equals(path)) {
                createNotification(messageObject3, false);
                return;
            }
            return;
        }
        if (id == NotificationCenter.fileDidLoad) {
            String path2 = (String) args[0];
            MessageObject messageObject4 = MediaController.getInstance().getPlayingMessageObject();
            if (messageObject4 != null && (str = this.loadingFilePath) != null && str.equals(path2)) {
                createNotification(messageObject4, false);
            }
        }
    }
}
