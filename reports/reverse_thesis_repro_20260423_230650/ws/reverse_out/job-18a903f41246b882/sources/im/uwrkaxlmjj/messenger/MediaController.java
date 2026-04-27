package im.uwrkaxlmjj.messenger;

import android.app.Activity;
import android.content.ContentResolver;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.database.ContentObserver;
import android.database.Cursor;
import android.graphics.SurfaceTexture;
import android.hardware.Sensor;
import android.hardware.SensorEvent;
import android.hardware.SensorEventListener;
import android.hardware.SensorManager;
import android.media.AudioManager;
import android.media.AudioRecord;
import android.media.MediaCodecInfo;
import android.media.MediaCodecList;
import android.media.MediaExtractor;
import android.media.MediaFormat;
import android.net.Uri;
import android.os.Build;
import android.os.PowerManager;
import android.provider.MediaStore;
import android.telephony.PhoneStateListener;
import android.telephony.TelephonyManager;
import android.text.TextUtils;
import android.util.SparseArray;
import android.view.TextureView;
import android.view.View;
import android.widget.FrameLayout;
import com.google.android.exoplayer2.C;
import com.google.android.exoplayer2.DefaultRenderersFactory;
import com.google.android.exoplayer2.trackselection.AdaptiveTrackSelection;
import com.google.android.exoplayer2.ui.AspectRatioFrameLayout;
import im.uwrkaxlmjj.messenger.MediaController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.audioinfo.AudioInfo;
import im.uwrkaxlmjj.messenger.voip.VoIPService;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.ChatActivity;
import im.uwrkaxlmjj.ui.PhotoViewer;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.components.EmbedBottomSheet;
import im.uwrkaxlmjj.ui.components.PhotoFilterView;
import im.uwrkaxlmjj.ui.components.PipRoundVideoView;
import im.uwrkaxlmjj.ui.components.Point;
import im.uwrkaxlmjj.ui.components.VideoPlayer;
import im.uwrkaxlmjj.ui.hui.visualcall.PermissionUtils;
import im.uwrkaxlmjj.ui.utils.translate.common.AudioEditConstant;
import java.io.File;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Timer;
import java.util.TimerTask;

/* JADX INFO: loaded from: classes2.dex */
public class MediaController implements AudioManager.OnAudioFocusChangeListener, NotificationCenter.NotificationCenterDelegate, SensorEventListener {
    private static final int AUDIO_FOCUSED = 2;
    private static final int AUDIO_NO_FOCUS_CAN_DUCK = 1;
    private static final int AUDIO_NO_FOCUS_NO_DUCK = 0;
    private static volatile MediaController Instance = null;
    public static final String MIME_TYPE = "video/avc";
    private static final int PROCESSOR_TYPE_INTEL = 2;
    private static final int PROCESSOR_TYPE_MTK = 3;
    private static final int PROCESSOR_TYPE_OTHER = 0;
    private static final int PROCESSOR_TYPE_QCOM = 1;
    private static final int PROCESSOR_TYPE_SEC = 4;
    private static final int PROCESSOR_TYPE_TI = 5;
    private static final float VOLUME_DUCK = 0.2f;
    private static final float VOLUME_NORMAL = 1.0f;
    public static AlbumEntry allMediaAlbumEntry;
    public static ArrayList<AlbumEntry> allMediaAlbums;
    public static ArrayList<AlbumEntry> allPhotoAlbums;
    public static AlbumEntry allPhotosAlbumEntry;
    public static AlbumEntry allVideosAlbumEntry;
    private static Runnable broadcastPhotosRunnable;
    private static final String[] projectionPhotos;
    private static final String[] projectionVideo;
    private static Runnable refreshGalleryRunnable;
    private Sensor accelerometerSensor;
    private boolean accelerometerVertical;
    private boolean allowStartRecord;
    private AudioInfo audioInfo;
    private AudioRecord audioRecorder;
    private Activity baseActivity;
    private boolean callInProgress;
    private int countLess;
    private AspectRatioFrameLayout currentAspectRatioFrameLayout;
    private float currentAspectRatioFrameLayoutRatio;
    private boolean currentAspectRatioFrameLayoutReady;
    private int currentAspectRatioFrameLayoutRotation;
    private int currentPlaylistNum;
    private TextureView currentTextureView;
    private FrameLayout currentTextureViewContainer;
    private boolean downloadingCurrentMessage;
    private ExternalObserver externalObserver;
    private View feedbackView;
    private ByteBuffer fileBuffer;
    private DispatchQueue fileEncodingQueue;
    private BaseFragment flagSecureFragment;
    private boolean forceLoopCurrentPlaylist;
    private MessageObject goingToShowMessageObject;
    private Sensor gravitySensor;
    private int hasAudioFocus;
    private boolean ignoreOnPause;
    private boolean ignoreProximity;
    private boolean inputFieldHasText;
    private InternalObserver internalObserver;
    private boolean isDrawingWasReady;
    private int lastChatAccount;
    private long lastChatEnterTime;
    private long lastChatLeaveTime;
    private ArrayList<Long> lastChatVisibleMessages;
    private long lastMediaCheckTime;
    private int lastMessageId;
    private TLRPC.EncryptedChat lastSecretChat;
    private TLRPC.User lastUser;
    private Sensor linearSensor;
    private String[] mediaProjections;
    private PipRoundVideoView pipRoundVideoView;
    private int pipSwitchingState;
    private boolean playMusicAgain;
    private boolean playerWasReady;
    private MessageObject playingMessageObject;
    private float previousAccValue;
    private boolean proximityHasDifferentValues;
    private Sensor proximitySensor;
    private boolean proximityTouched;
    private PowerManager.WakeLock proximityWakeLock;
    private ChatActivity raiseChat;
    private boolean raiseToEarRecord;
    private int raisedToBack;
    private int raisedToTop;
    private int raisedToTopSign;
    private long recordDialogId;
    private DispatchQueue recordQueue;
    private MessageObject recordReplyingMessageObject;
    private Runnable recordStartRunnable;
    private long recordStartTime;
    private long recordTimeCount;
    private TLRPC.TL_document recordingAudio;
    private File recordingAudioFile;
    private int recordingCurrentAccount;
    private boolean resumeAudioOnFocusGain;
    private long samplesCount;
    private float seekToProgressPending;
    private int sendAfterDone;
    private boolean sendAfterDoneNotify;
    private int sendAfterDoneScheduleDate;
    private SensorManager sensorManager;
    private boolean sensorsStarted;
    private int startObserverToken;
    private StopMediaObserverRunnable stopMediaObserverRunnable;
    private long timeSinceRaise;
    private boolean useFrontSpeaker;
    private VideoPlayer videoPlayer;
    private ArrayList<MessageObject> voiceMessagesPlaylist;
    private SparseArray<MessageObject> voiceMessagesPlaylistMap;
    private boolean voiceMessagesPlaylistUnread;
    private final Object videoConvertSync = new Object();
    private long lastTimestamp = 0;
    private float lastProximityValue = -100.0f;
    private float[] gravity = new float[3];
    private float[] gravityFast = new float[3];
    private float[] linearAcceleration = new float[3];
    private int audioFocus = 0;
    private ArrayList<MessageObject> videoConvertQueue = new ArrayList<>();
    private final Object videoQueueSync = new Object();
    private boolean cancelCurrentVideoConversion = false;
    private boolean videoConvertFirstWrite = true;
    private HashMap<String, MessageObject> generatingWaveform = new HashMap<>();
    private boolean isPaused = false;
    private VideoPlayer audioPlayer = null;
    private float currentPlaybackSpeed = 1.0f;
    private long lastProgress = 0;
    private Timer progressTimer = null;
    private final Object progressTimerSync = new Object();
    private ArrayList<MessageObject> playlist = new ArrayList<>();
    private ArrayList<MessageObject> shuffledPlaylist = new ArrayList<>();
    private Runnable setLoadingRunnable = new Runnable() { // from class: im.uwrkaxlmjj.messenger.MediaController.1
        @Override // java.lang.Runnable
        public void run() {
            if (MediaController.this.playingMessageObject != null) {
                FileLoader.getInstance(MediaController.this.playingMessageObject.currentAccount).setLoadingVideo(MediaController.this.playingMessageObject.getDocument(), true, false);
            }
        }
    };
    private int recordingGuid = -1;
    private short[] recordSamples = new short[1024];
    private final Object sync = new Object();
    private ArrayList<ByteBuffer> recordBuffers = new ArrayList<>();
    private int recordBufferSize = 1280;
    private Runnable recordRunnable = new AnonymousClass2();

    public static class AudioEntry {
        public String author;
        public int duration;
        public String genre;
        public long id;
        public MessageObject messageObject;
        public String path;
        public String title;
    }

    public static class SavedFilterState {
        public float blurAngle;
        public float blurExcludeBlurSize;
        public Point blurExcludePoint;
        public float blurExcludeSize;
        public int blurType;
        public float contrastValue;
        public PhotoFilterView.CurvesToolValue curvesToolValue = new PhotoFilterView.CurvesToolValue();
        public float enhanceValue;
        public float exposureValue;
        public float fadeValue;
        public float grainValue;
        public float highlightsValue;
        public float saturationValue;
        public float shadowsValue;
        public float sharpenValue;
        public int tintHighlightsColor;
        public int tintShadowsColor;
        public float vignetteValue;
        public float warmthValue;
    }

    public static native int isOpusFile(String str);

    private native int startRecord(String str);

    private native void stopRecord();

    /* JADX INFO: Access modifiers changed from: private */
    public native int writeFrame(ByteBuffer byteBuffer, int i);

    public native byte[] getWaveform(String str);

    public native byte[] getWaveform2(short[] sArr, int i);

    private class AudioBuffer {
        ByteBuffer buffer;
        byte[] bufferBytes;
        int finished;
        long pcmOffset;
        int size;

        public AudioBuffer(int capacity) {
            this.buffer = ByteBuffer.allocateDirect(capacity);
            this.bufferBytes = new byte[capacity];
        }
    }

    static {
        String[] strArr = new String[6];
        strArr[0] = "_id";
        strArr[1] = "bucket_id";
        strArr[2] = "bucket_display_name";
        strArr[3] = "_data";
        strArr[4] = Build.VERSION.SDK_INT > 28 ? "date_modified" : "datetaken";
        strArr[5] = "orientation";
        projectionPhotos = strArr;
        String[] strArr2 = new String[6];
        strArr2[0] = "_id";
        strArr2[1] = "bucket_id";
        strArr2[2] = "bucket_display_name";
        strArr2[3] = "_data";
        strArr2[4] = Build.VERSION.SDK_INT <= 28 ? "datetaken" : "date_modified";
        strArr2[5] = "duration";
        projectionVideo = strArr2;
        allMediaAlbums = new ArrayList<>();
        allPhotoAlbums = new ArrayList<>();
    }

    public static class AlbumEntry {
        public int bucketId;
        public String bucketName;
        public PhotoEntry coverPhoto;
        public ArrayList<PhotoEntry> photos = new ArrayList<>();
        public SparseArray<PhotoEntry> photosByIds = new SparseArray<>();
        public boolean videoOnly;

        public AlbumEntry(int bucketId, String bucketName, PhotoEntry coverPhoto) {
            this.bucketId = bucketId;
            this.bucketName = bucketName;
            this.coverPhoto = coverPhoto;
        }

        public void addPhoto(PhotoEntry photoEntry) {
            this.photos.add(photoEntry);
            this.photosByIds.put(photoEntry.imageId, photoEntry);
        }
    }

    public static class PhotoEntry {
        public int bucketId;
        public boolean canDeleteAfter;
        public CharSequence caption;
        public long dateTaken;
        public int duration;
        public VideoEditedInfo editedInfo;
        public ArrayList<TLRPC.MessageEntity> entities;
        public int imageId;
        public String imagePath;
        public boolean isCropped;
        public boolean isFiltered;
        public boolean isMuted;
        public boolean isPainted;
        public boolean isVideo;
        public int orientation;
        public String path;
        public SavedFilterState savedFilterState;
        public ArrayList<TLRPC.InputDocument> stickers = new ArrayList<>();
        public String thumbPath;
        public int ttl;

        public PhotoEntry(int bucketId, int imageId, long dateTaken, String path, int orientation, boolean isVideo) {
            this.bucketId = bucketId;
            this.imageId = imageId;
            this.dateTaken = dateTaken;
            this.path = path;
            if (isVideo) {
                this.duration = orientation;
            } else {
                this.orientation = orientation;
            }
            this.isVideo = isVideo;
        }

        public void reset() {
            this.isFiltered = false;
            this.isPainted = false;
            this.isCropped = false;
            this.ttl = 0;
            this.imagePath = null;
            if (!this.isVideo) {
                this.thumbPath = null;
            }
            this.editedInfo = null;
            this.caption = null;
            this.entities = null;
            this.savedFilterState = null;
            this.stickers.clear();
        }

        public String toString() {
            return "PhotoEntry{bucketId=" + this.bucketId + ", imageId=" + this.imageId + ", dateTaken=" + this.dateTaken + ", duration=" + this.duration + ", path='" + this.path + "', orientation=" + this.orientation + ", thumbPath='" + this.thumbPath + "', imagePath='" + this.imagePath + "', editedInfo=" + this.editedInfo + ", isVideo=" + this.isVideo + ", caption=" + ((Object) this.caption) + ", entities=" + this.entities + ", isFiltered=" + this.isFiltered + ", isPainted=" + this.isPainted + ", isCropped=" + this.isCropped + ", isMuted=" + this.isMuted + ", ttl=" + this.ttl + ", canDeleteAfter=" + this.canDeleteAfter + ", savedFilterState=" + this.savedFilterState + ", stickers=" + this.stickers + '}';
        }
    }

    public static class SearchImage {
        public CharSequence caption;
        public int date;
        public TLRPC.Document document;
        public ArrayList<TLRPC.MessageEntity> entities;
        public int height;
        public String id;
        public String imagePath;
        public String imageUrl;
        public TLRPC.BotInlineResult inlineResult;
        public boolean isCropped;
        public boolean isFiltered;
        public boolean isPainted;
        public HashMap<String, String> params;
        public TLRPC.Photo photo;
        public TLRPC.PhotoSize photoSize;
        public SavedFilterState savedFilterState;
        public int size;
        public ArrayList<TLRPC.InputDocument> stickers = new ArrayList<>();
        public String thumbPath;
        public TLRPC.PhotoSize thumbPhotoSize;
        public String thumbUrl;
        public int ttl;
        public int type;
        public int width;

        public void reset() {
            this.isFiltered = false;
            this.isPainted = false;
            this.isCropped = false;
            this.ttl = 0;
            this.imagePath = null;
            this.thumbPath = null;
            this.caption = null;
            this.entities = null;
            this.savedFilterState = null;
            this.stickers.clear();
        }

        public String getAttachName() {
            TLRPC.PhotoSize photoSize = this.photoSize;
            if (photoSize != null) {
                return FileLoader.getAttachFileName(photoSize);
            }
            TLRPC.Document document = this.document;
            if (document != null) {
                return FileLoader.getAttachFileName(document);
            }
            return Utilities.MD5(this.imageUrl) + "." + ImageLoader.getHttpUrlExtension(this.imageUrl, "jpg");
        }

        public String getPathToAttach() {
            TLRPC.PhotoSize photoSize = this.photoSize;
            if (photoSize != null) {
                return FileLoader.getPathToAttach(photoSize, true).getAbsolutePath();
            }
            TLRPC.Document document = this.document;
            if (document != null) {
                return FileLoader.getPathToAttach(document, true).getAbsolutePath();
            }
            return this.imageUrl;
        }
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.messenger.MediaController$2, reason: invalid class name */
    class AnonymousClass2 implements Runnable {
        AnonymousClass2() {
        }

        /* JADX WARN: Removed duplicated region for block: B:23:0x00b4 A[Catch: Exception -> 0x00ed, TRY_LEAVE, TryCatch #0 {Exception -> 0x00ed, blocks: (B:11:0x0058, B:21:0x00b0, B:23:0x00b4), top: B:51:0x0058 }] */
        /* JADX WARN: Removed duplicated region for block: B:43:0x010a  */
        /* JADX WARN: Removed duplicated region for block: B:45:0x010d  */
        @Override // java.lang.Runnable
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public void run() {
            /*
                Method dump skipped, instruction units count: 348
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MediaController.AnonymousClass2.run():void");
        }

        public /* synthetic */ void lambda$run$1$MediaController$2(final ByteBuffer finalBuffer, boolean flush) {
            while (finalBuffer.hasRemaining()) {
                int oldLimit = -1;
                if (finalBuffer.remaining() > MediaController.this.fileBuffer.remaining()) {
                    oldLimit = finalBuffer.limit();
                    finalBuffer.limit(MediaController.this.fileBuffer.remaining() + finalBuffer.position());
                }
                MediaController.this.fileBuffer.put(finalBuffer);
                if (MediaController.this.fileBuffer.position() == MediaController.this.fileBuffer.limit() || flush) {
                    MediaController mediaController = MediaController.this;
                    if (mediaController.writeFrame(mediaController.fileBuffer, !flush ? MediaController.this.fileBuffer.limit() : finalBuffer.position()) != 0) {
                        MediaController.this.fileBuffer.rewind();
                        MediaController.this.recordTimeCount += (long) ((MediaController.this.fileBuffer.limit() / 2) / 16);
                    }
                }
                if (oldLimit != -1) {
                    finalBuffer.limit(oldLimit);
                }
            }
            MediaController.this.recordQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaController$2$OXbbT9fQktz-M2tjtUVQcaI_PVg
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$0$MediaController$2(finalBuffer);
                }
            });
        }

        public /* synthetic */ void lambda$null$0$MediaController$2(ByteBuffer finalBuffer) {
            MediaController.this.recordBuffers.add(finalBuffer);
        }

        public /* synthetic */ void lambda$run$2$MediaController$2(double amplitude) {
            NotificationCenter.getInstance(MediaController.this.recordingCurrentAccount).postNotificationName(NotificationCenter.recordProgressChanged, Integer.valueOf(MediaController.this.recordingGuid), Long.valueOf(System.currentTimeMillis() - MediaController.this.recordStartTime), Double.valueOf(amplitude));
        }
    }

    private class InternalObserver extends ContentObserver {
        public InternalObserver() {
            super(null);
        }

        @Override // android.database.ContentObserver
        public void onChange(boolean selfChange) {
            super.onChange(selfChange);
            MediaController.this.processMediaObserver(MediaStore.Images.Media.INTERNAL_CONTENT_URI);
        }
    }

    private class ExternalObserver extends ContentObserver {
        public ExternalObserver() {
            super(null);
        }

        @Override // android.database.ContentObserver
        public void onChange(boolean selfChange) {
            super.onChange(selfChange);
            MediaController.this.processMediaObserver(MediaStore.Images.Media.EXTERNAL_CONTENT_URI);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    class GalleryObserverInternal extends ContentObserver {
        public GalleryObserverInternal() {
            super(null);
        }

        private void scheduleReloadRunnable() {
            AndroidUtilities.runOnUIThread(MediaController.refreshGalleryRunnable = new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaController$GalleryObserverInternal$A0o6XFnyRAgzDVDPRM1evNAUuiE
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$scheduleReloadRunnable$0$MediaController$GalleryObserverInternal();
                }
            }, AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS);
        }

        public /* synthetic */ void lambda$scheduleReloadRunnable$0$MediaController$GalleryObserverInternal() {
            if (!PhotoViewer.getInstance().isVisible()) {
                Runnable unused = MediaController.refreshGalleryRunnable = null;
                MediaController.loadGalleryPhotosAlbums(0);
            } else {
                scheduleReloadRunnable();
            }
        }

        @Override // android.database.ContentObserver
        public void onChange(boolean selfChange) {
            super.onChange(selfChange);
            if (MediaController.refreshGalleryRunnable != null) {
                AndroidUtilities.cancelRunOnUIThread(MediaController.refreshGalleryRunnable);
            }
            scheduleReloadRunnable();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    class GalleryObserverExternal extends ContentObserver {
        public GalleryObserverExternal() {
            super(null);
        }

        @Override // android.database.ContentObserver
        public void onChange(boolean selfChange) {
            super.onChange(selfChange);
            if (MediaController.refreshGalleryRunnable != null) {
                AndroidUtilities.cancelRunOnUIThread(MediaController.refreshGalleryRunnable);
            }
            AndroidUtilities.runOnUIThread(MediaController.refreshGalleryRunnable = new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaController$GalleryObserverExternal$D-nUkZvEuNj07xOyNBp0KX_RUvo
                @Override // java.lang.Runnable
                public final void run() {
                    MediaController.GalleryObserverExternal.lambda$onChange$0();
                }
            }, AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS);
        }

        static /* synthetic */ void lambda$onChange$0() {
            Runnable unused = MediaController.refreshGalleryRunnable = null;
            MediaController.loadGalleryPhotosAlbums(0);
        }
    }

    public static void checkGallery() {
        AlbumEntry albumEntry;
        if (Build.VERSION.SDK_INT < 24 || (albumEntry = allPhotosAlbumEntry) == null) {
            return;
        }
        final int prevSize = albumEntry.photos.size();
        Utilities.globalQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaController$6pyqI-DyIdTIRFm5V1j32ipq83U
            @Override // java.lang.Runnable
            public final void run() {
                MediaController.lambda$checkGallery$0(prevSize);
            }
        }, AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS);
    }

    static /* synthetic */ void lambda$checkGallery$0(int prevSize) {
        int count = 0;
        Cursor cursor = null;
        try {
            if (ApplicationLoader.applicationContext.checkSelfPermission(PermissionUtils.PERMISSION_READ_EXTERNAL_STORAGE) == 0 && (cursor = MediaStore.Images.Media.query(ApplicationLoader.applicationContext.getContentResolver(), MediaStore.Images.Media.EXTERNAL_CONTENT_URI, new String[]{"COUNT(_id)"}, null, null, null)) != null && cursor.moveToNext()) {
                count = 0 + cursor.getInt(0);
            }
        } catch (Throwable e) {
            try {
                FileLog.e(e);
                if (cursor != null) {
                }
            } finally {
                if (cursor != null) {
                    cursor.close();
                }
            }
        }
        if (cursor != null) {
            cursor.close();
        }
        try {
            if (ApplicationLoader.applicationContext.checkSelfPermission(PermissionUtils.PERMISSION_READ_EXTERNAL_STORAGE) == 0 && (cursor = MediaStore.Images.Media.query(ApplicationLoader.applicationContext.getContentResolver(), MediaStore.Video.Media.EXTERNAL_CONTENT_URI, new String[]{"COUNT(_id)"}, null, null, null)) != null && cursor.moveToNext()) {
                count += cursor.getInt(0);
            }
        } catch (Throwable e2) {
            try {
                FileLog.e(e2);
                if (cursor != null) {
                }
            } finally {
                if (cursor != null) {
                    cursor.close();
                }
            }
        }
        if (prevSize != count) {
            Runnable runnable = refreshGalleryRunnable;
            if (runnable != null) {
                AndroidUtilities.cancelRunOnUIThread(runnable);
                refreshGalleryRunnable = null;
            }
            loadGalleryPhotosAlbums(0);
        }
    }

    private final class StopMediaObserverRunnable implements Runnable {
        public int currentObserverToken;

        private StopMediaObserverRunnable() {
            this.currentObserverToken = 0;
        }

        @Override // java.lang.Runnable
        public void run() {
            if (this.currentObserverToken == MediaController.this.startObserverToken) {
                try {
                    if (MediaController.this.internalObserver != null) {
                        ApplicationLoader.applicationContext.getContentResolver().unregisterContentObserver(MediaController.this.internalObserver);
                        MediaController.this.internalObserver = null;
                    }
                } catch (Exception e) {
                    FileLog.e(e);
                }
                try {
                    if (MediaController.this.externalObserver != null) {
                        ApplicationLoader.applicationContext.getContentResolver().unregisterContentObserver(MediaController.this.externalObserver);
                        MediaController.this.externalObserver = null;
                    }
                } catch (Exception e2) {
                    FileLog.e(e2);
                }
            }
        }
    }

    public static MediaController getInstance() {
        MediaController localInstance = Instance;
        if (localInstance == null) {
            synchronized (MediaController.class) {
                localInstance = Instance;
                if (localInstance == null) {
                    MediaController mediaController = new MediaController();
                    localInstance = mediaController;
                    Instance = mediaController;
                }
            }
        }
        return localInstance;
    }

    public MediaController() {
        DispatchQueue dispatchQueue = new DispatchQueue("recordQueue");
        this.recordQueue = dispatchQueue;
        dispatchQueue.setPriority(10);
        DispatchQueue dispatchQueue2 = new DispatchQueue("fileEncodingQueue");
        this.fileEncodingQueue = dispatchQueue2;
        dispatchQueue2.setPriority(10);
        this.recordQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaController$nBv4QRXlRcbboznolIlSX9tbS6I
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$new$1$MediaController();
            }
        });
        Utilities.globalQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaController$wUJ71FbXVzlQIsn7GhkHFHnG2lg
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$new$2$MediaController();
            }
        });
        this.fileBuffer = ByteBuffer.allocateDirect(1920);
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaController$2u3fiMf-gj5OKCFUiOuSyOuNbeo
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$new$3$MediaController();
            }
        });
        String[] strArr = new String[7];
        strArr[0] = "_data";
        strArr[1] = "_display_name";
        strArr[2] = "bucket_display_name";
        strArr[3] = Build.VERSION.SDK_INT > 28 ? "date_modified" : "datetaken";
        strArr[4] = "title";
        strArr[5] = "width";
        strArr[6] = "height";
        this.mediaProjections = strArr;
        ContentResolver contentResolver = ApplicationLoader.applicationContext.getContentResolver();
        try {
            contentResolver.registerContentObserver(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, true, new GalleryObserverExternal());
        } catch (Exception e) {
            FileLog.e(e);
        }
        try {
            contentResolver.registerContentObserver(MediaStore.Images.Media.INTERNAL_CONTENT_URI, true, new GalleryObserverInternal());
        } catch (Exception e2) {
            FileLog.e(e2);
        }
        try {
            contentResolver.registerContentObserver(MediaStore.Video.Media.EXTERNAL_CONTENT_URI, true, new GalleryObserverExternal());
        } catch (Exception e3) {
            FileLog.e(e3);
        }
        try {
            contentResolver.registerContentObserver(MediaStore.Video.Media.INTERNAL_CONTENT_URI, true, new GalleryObserverInternal());
        } catch (Exception e4) {
            FileLog.e(e4);
        }
    }

    public /* synthetic */ void lambda$new$1$MediaController() {
        try {
            int minBufferSize = AudioRecord.getMinBufferSize(AudioEditConstant.ExportSampleRate, 16, 2);
            this.recordBufferSize = minBufferSize;
            if (minBufferSize <= 0) {
                this.recordBufferSize = 1280;
            }
            for (int a = 0; a < 5; a++) {
                ByteBuffer buffer = ByteBuffer.allocateDirect(4096);
                buffer.order(ByteOrder.nativeOrder());
                this.recordBuffers.add(buffer);
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public /* synthetic */ void lambda$new$2$MediaController() {
        try {
            this.currentPlaybackSpeed = MessagesController.getGlobalMainSettings().getFloat("playbackSpeed", 1.0f);
            SensorManager sensorManager = (SensorManager) ApplicationLoader.applicationContext.getSystemService("sensor");
            this.sensorManager = sensorManager;
            this.linearSensor = sensorManager.getDefaultSensor(10);
            Sensor defaultSensor = this.sensorManager.getDefaultSensor(9);
            this.gravitySensor = defaultSensor;
            if (this.linearSensor == null || defaultSensor == null) {
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.d("gravity or linear sensor not found");
                }
                this.accelerometerSensor = this.sensorManager.getDefaultSensor(1);
                this.linearSensor = null;
                this.gravitySensor = null;
            }
            this.proximitySensor = this.sensorManager.getDefaultSensor(8);
            PowerManager powerManager = (PowerManager) ApplicationLoader.applicationContext.getSystemService("power");
            this.proximityWakeLock = powerManager.newWakeLock(32, "proximity");
        } catch (Exception e) {
            FileLog.e(e);
        }
        try {
            PhoneStateListener phoneStateListener = new AnonymousClass3();
            TelephonyManager mgr = (TelephonyManager) ApplicationLoader.applicationContext.getSystemService("phone");
            if (mgr != null) {
                mgr.listen(phoneStateListener, 32);
            }
        } catch (Exception e2) {
            FileLog.e(e2);
        }
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.messenger.MediaController$3, reason: invalid class name */
    class AnonymousClass3 extends PhoneStateListener {
        AnonymousClass3() {
        }

        @Override // android.telephony.PhoneStateListener
        public void onCallStateChanged(final int state, String incomingNumber) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaController$3$WdViIxnj3xkBnBzZb_KoI_KZ5tw
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onCallStateChanged$0$MediaController$3(state);
                }
            });
        }

        public /* synthetic */ void lambda$onCallStateChanged$0$MediaController$3(int state) {
            if (state != 1) {
                if (state == 0) {
                    MediaController.this.callInProgress = false;
                    return;
                } else {
                    if (state == 2) {
                        EmbedBottomSheet embedBottomSheet = EmbedBottomSheet.getInstance();
                        if (embedBottomSheet != null) {
                            embedBottomSheet.pause();
                        }
                        MediaController.this.callInProgress = true;
                        return;
                    }
                    return;
                }
            }
            MediaController mediaController = MediaController.this;
            if (!mediaController.isPlayingMessage(mediaController.playingMessageObject) || MediaController.this.isMessagePaused()) {
                if (MediaController.this.recordStartRunnable != null || MediaController.this.recordingAudio != null) {
                    MediaController.this.stopRecording(2, false, 0);
                }
            } else {
                MediaController mediaController2 = MediaController.this;
                mediaController2.lambda$startAudioAgain$5$MediaController(mediaController2.playingMessageObject);
            }
            EmbedBottomSheet embedBottomSheet2 = EmbedBottomSheet.getInstance();
            if (embedBottomSheet2 != null) {
                embedBottomSheet2.pause();
            }
            MediaController.this.callInProgress = true;
        }
    }

    public /* synthetic */ void lambda$new$3$MediaController() {
        for (int a = 0; a < 3; a++) {
            NotificationCenter.getInstance(a).addObserver(this, NotificationCenter.fileDidLoad);
            NotificationCenter.getInstance(a).addObserver(this, NotificationCenter.httpFileDidLoad);
            NotificationCenter.getInstance(a).addObserver(this, NotificationCenter.didReceiveNewMessages);
            NotificationCenter.getInstance(a).addObserver(this, NotificationCenter.messagesDeleted);
            NotificationCenter.getInstance(a).addObserver(this, NotificationCenter.removeAllMessagesFromDialog);
            NotificationCenter.getInstance(a).addObserver(this, NotificationCenter.musicDidLoad);
            NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.playerDidStartPlaying);
        }
    }

    @Override // android.media.AudioManager.OnAudioFocusChangeListener
    public void onAudioFocusChange(int focusChange) {
        if (focusChange == -1) {
            if (isPlayingMessage(getPlayingMessageObject()) && !isMessagePaused()) {
                lambda$startAudioAgain$5$MediaController(this.playingMessageObject);
            }
            this.hasAudioFocus = 0;
            this.audioFocus = 0;
        } else if (focusChange == 1) {
            this.audioFocus = 2;
            if (this.resumeAudioOnFocusGain) {
                this.resumeAudioOnFocusGain = false;
                if (isPlayingMessage(getPlayingMessageObject()) && isMessagePaused()) {
                    playMessage(getPlayingMessageObject());
                }
            }
        } else if (focusChange == -3) {
            this.audioFocus = 1;
        } else if (focusChange == -2) {
            this.audioFocus = 0;
            if (isPlayingMessage(getPlayingMessageObject()) && !isMessagePaused()) {
                lambda$startAudioAgain$5$MediaController(this.playingMessageObject);
                this.resumeAudioOnFocusGain = true;
            }
        }
        setPlayerVolume();
    }

    private void setPlayerVolume() {
        float volume;
        try {
            if (this.audioFocus != 1) {
                volume = 1.0f;
            } else {
                volume = VOLUME_DUCK;
            }
            if (this.audioPlayer != null) {
                this.audioPlayer.setVolume(volume);
            } else if (this.videoPlayer != null) {
                this.videoPlayer.setVolume(volume);
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    private void startProgressTimer(MessageObject currentPlayingMessageObject) {
        synchronized (this.progressTimerSync) {
            if (this.progressTimer != null) {
                try {
                    this.progressTimer.cancel();
                    this.progressTimer = null;
                } catch (Exception e) {
                    FileLog.e(e);
                }
                currentPlayingMessageObject.getFileName();
                Timer timer = new Timer();
                this.progressTimer = timer;
                timer.schedule(new AnonymousClass4(currentPlayingMessageObject), 0L, 17L);
            } else {
                currentPlayingMessageObject.getFileName();
                Timer timer2 = new Timer();
                this.progressTimer = timer2;
                timer2.schedule(new AnonymousClass4(currentPlayingMessageObject), 0L, 17L);
            }
        }
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.messenger.MediaController$4, reason: invalid class name */
    class AnonymousClass4 extends TimerTask {
        final /* synthetic */ MessageObject val$currentPlayingMessageObject;

        AnonymousClass4(MessageObject messageObject) {
            this.val$currentPlayingMessageObject = messageObject;
        }

        @Override // java.util.TimerTask, java.lang.Runnable
        public void run() {
            synchronized (MediaController.this.sync) {
                final MessageObject messageObject = this.val$currentPlayingMessageObject;
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaController$4$s4T-3Z7ud5xDzHKRzFAux7H6nD8
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$run$0$MediaController$4(messageObject);
                    }
                });
            }
        }

        public /* synthetic */ void lambda$run$0$MediaController$4(MessageObject currentPlayingMessageObject) {
            long duration;
            long progress;
            float value;
            float value2;
            if (currentPlayingMessageObject != null) {
                if ((MediaController.this.audioPlayer != null || MediaController.this.videoPlayer != null) && !MediaController.this.isPaused) {
                    try {
                        if (MediaController.this.videoPlayer != null) {
                            duration = MediaController.this.videoPlayer.getDuration();
                            progress = MediaController.this.videoPlayer.getCurrentPosition();
                            if (progress >= 0 && duration > 0) {
                                value2 = MediaController.this.videoPlayer.getBufferedPosition() / duration;
                                value = duration >= 0 ? progress / duration : 0.0f;
                                if (value >= 1.0f) {
                                    return;
                                }
                            }
                            return;
                        }
                        duration = MediaController.this.audioPlayer.getDuration();
                        progress = MediaController.this.audioPlayer.getCurrentPosition();
                        float value3 = duration >= 0 ? progress / duration : 0.0f;
                        float bufferedValue = MediaController.this.audioPlayer.getBufferedPosition() / duration;
                        if (duration != C.TIME_UNSET && progress >= 0 && MediaController.this.seekToProgressPending == 0.0f) {
                            value = value3;
                            value2 = bufferedValue;
                        }
                        return;
                        MediaController.this.lastProgress = progress;
                        currentPlayingMessageObject.audioPlayerDuration = (int) (duration / 1000);
                        currentPlayingMessageObject.audioProgress = value;
                        currentPlayingMessageObject.audioProgressSec = (int) (MediaController.this.lastProgress / 1000);
                        currentPlayingMessageObject.bufferedProgress = value2;
                        NotificationCenter.getInstance(currentPlayingMessageObject.currentAccount).postNotificationName(NotificationCenter.messagePlayingProgressDidChanged, Integer.valueOf(currentPlayingMessageObject.getId()), Float.valueOf(value));
                    } catch (Exception e) {
                        FileLog.e(e);
                    }
                }
            }
        }
    }

    private void stopProgressTimer() {
        synchronized (this.progressTimerSync) {
            if (this.progressTimer != null) {
                try {
                    this.progressTimer.cancel();
                    this.progressTimer = null;
                } catch (Exception e) {
                    FileLog.e(e);
                }
            }
        }
    }

    public void cleanup() {
        cleanupPlayer(false, true);
        this.audioInfo = null;
        this.playMusicAgain = false;
        for (int a = 0; a < 3; a++) {
            DownloadController.getInstance(a).cleanup();
        }
        this.videoConvertQueue.clear();
        this.playlist.clear();
        this.shuffledPlaylist.clear();
        this.generatingWaveform.clear();
        this.voiceMessagesPlaylist = null;
        this.voiceMessagesPlaylistMap = null;
        cancelVideoConvert(null);
    }

    public void startMediaObserver() {
        ApplicationLoader.applicationHandler.removeCallbacks(this.stopMediaObserverRunnable);
        this.startObserverToken++;
        try {
            if (this.internalObserver == null) {
                ContentResolver contentResolver = ApplicationLoader.applicationContext.getContentResolver();
                Uri uri = MediaStore.Images.Media.EXTERNAL_CONTENT_URI;
                ExternalObserver externalObserver = new ExternalObserver();
                this.externalObserver = externalObserver;
                contentResolver.registerContentObserver(uri, false, externalObserver);
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
        try {
            if (this.externalObserver == null) {
                ContentResolver contentResolver2 = ApplicationLoader.applicationContext.getContentResolver();
                Uri uri2 = MediaStore.Images.Media.INTERNAL_CONTENT_URI;
                InternalObserver internalObserver = new InternalObserver();
                this.internalObserver = internalObserver;
                contentResolver2.registerContentObserver(uri2, false, internalObserver);
            }
        } catch (Exception e2) {
            FileLog.e(e2);
        }
    }

    public void stopMediaObserver() {
        if (this.stopMediaObserverRunnable == null) {
            this.stopMediaObserverRunnable = new StopMediaObserverRunnable();
        }
        this.stopMediaObserverRunnable.currentObserverToken = this.startObserverToken;
        ApplicationLoader.applicationHandler.postDelayed(this.stopMediaObserverRunnable, DefaultRenderersFactory.DEFAULT_ALLOWED_VIDEO_JOINING_TIME_MS);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Removed duplicated region for block: B:34:0x00aa A[Catch: Exception -> 0x00b2, all -> 0x00d6, TRY_LEAVE, TryCatch #2 {all -> 0x00d6, blocks: (B:3:0x0003, B:5:0x0023, B:7:0x0029, B:10:0x0054, B:26:0x009a, B:28:0x009e, B:30:0x00a2, B:32:0x00a6, B:34:0x00aa, B:23:0x0086, B:37:0x00b3, B:13:0x0060, B:16:0x006c, B:19:0x0078, B:39:0x00bc, B:40:0x00bf, B:42:0x00c5, B:52:0x00db), top: B:66:0x0003, inners: #1 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void processMediaObserver(android.net.Uri r17) {
        /*
            Method dump skipped, instruction units count: 239
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MediaController.processMediaObserver(android.net.Uri):void");
    }

    public /* synthetic */ void lambda$processMediaObserver$4$MediaController(ArrayList screenshotDates) {
        NotificationCenter.getInstance(this.lastChatAccount).postNotificationName(NotificationCenter.screenshotTook, new Object[0]);
        checkScreenshots(screenshotDates);
    }

    private void checkScreenshots(ArrayList<Long> dates) {
        if (dates == null || dates.isEmpty() || this.lastChatEnterTime == 0) {
            return;
        }
        if (this.lastUser == null && !(this.lastSecretChat instanceof TLRPC.TL_encryptedChat)) {
            return;
        }
        boolean send = false;
        for (int a = 0; a < dates.size(); a++) {
            Long date = dates.get(a);
            if ((this.lastMediaCheckTime == 0 || date.longValue() > this.lastMediaCheckTime) && date.longValue() >= this.lastChatEnterTime && (this.lastChatLeaveTime == 0 || date.longValue() <= this.lastChatLeaveTime + AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS)) {
                this.lastMediaCheckTime = Math.max(this.lastMediaCheckTime, date.longValue());
                send = true;
            }
        }
        if (send) {
            if (this.lastSecretChat != null) {
                SecretChatHelper.getInstance(this.lastChatAccount).sendScreenshotMessage(this.lastSecretChat, this.lastChatVisibleMessages, null);
            } else {
                SendMessagesHelper.getInstance(this.lastChatAccount).sendScreenshotMessage(this.lastUser, this.lastMessageId, null);
            }
        }
    }

    public void setLastVisibleMessageIds(int account, long enterTime, long leaveTime, TLRPC.User user, TLRPC.EncryptedChat encryptedChat, ArrayList<Long> visibleMessages, int visibleMessage) {
        this.lastChatEnterTime = enterTime;
        this.lastChatLeaveTime = leaveTime;
        this.lastChatAccount = account;
        this.lastSecretChat = encryptedChat;
        this.lastUser = user;
        this.lastMessageId = visibleMessage;
        this.lastChatVisibleMessages = visibleMessages;
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        MessageObject messageObject;
        ArrayList<MessageObject> arrayList;
        if (id == NotificationCenter.fileDidLoad || id == NotificationCenter.httpFileDidLoad) {
            String fileName = (String) args[0];
            if (this.downloadingCurrentMessage && (messageObject = this.playingMessageObject) != null && messageObject.currentAccount == account) {
                String file = FileLoader.getAttachFileName(this.playingMessageObject.getDocument());
                if (file.equals(fileName)) {
                    this.playMusicAgain = true;
                    playMessage(this.playingMessageObject);
                    return;
                }
                return;
            }
            return;
        }
        if (id == NotificationCenter.messagesDeleted) {
            boolean scheduled = ((Boolean) args[2]).booleanValue();
            if (scheduled) {
                return;
            }
            int channelId = ((Integer) args[1]).intValue();
            ArrayList<Integer> markAsDeletedMessages = (ArrayList) args[0];
            MessageObject messageObject2 = this.playingMessageObject;
            if (messageObject2 != null && channelId == messageObject2.messageOwner.to_id.channel_id && markAsDeletedMessages.contains(Integer.valueOf(this.playingMessageObject.getId()))) {
                cleanupPlayer(true, true);
            }
            ArrayList<MessageObject> arrayList2 = this.voiceMessagesPlaylist;
            if (arrayList2 != null && !arrayList2.isEmpty()) {
                MessageObject messageObject3 = this.voiceMessagesPlaylist.get(0);
                if (channelId == messageObject3.messageOwner.to_id.channel_id) {
                    for (int a = 0; a < markAsDeletedMessages.size(); a++) {
                        Integer key = markAsDeletedMessages.get(a);
                        MessageObject messageObject4 = this.voiceMessagesPlaylistMap.get(key.intValue());
                        MessageObject messageObject5 = messageObject4;
                        this.voiceMessagesPlaylistMap.remove(key.intValue());
                        if (messageObject5 != null) {
                            this.voiceMessagesPlaylist.remove(messageObject5);
                        }
                    }
                    return;
                }
                return;
            }
            return;
        }
        if (id == NotificationCenter.removeAllMessagesFromDialog) {
            long did = ((Long) args[0]).longValue();
            MessageObject messageObject6 = this.playingMessageObject;
            if (messageObject6 != null && messageObject6.getDialogId() == did) {
                cleanupPlayer(false, true);
                return;
            }
            return;
        }
        if (id == NotificationCenter.musicDidLoad) {
            long did2 = ((Long) args[0]).longValue();
            MessageObject messageObject7 = this.playingMessageObject;
            if (messageObject7 != null && messageObject7.isMusic() && this.playingMessageObject.getDialogId() == did2 && !this.playingMessageObject.scheduled) {
                ArrayList<MessageObject> arrayList3 = (ArrayList) args[1];
                this.playlist.addAll(0, arrayList3);
                if (SharedConfig.shuffleMusic) {
                    buildShuffledPlayList();
                    this.currentPlaylistNum = 0;
                    return;
                } else {
                    this.currentPlaylistNum += arrayList3.size();
                    return;
                }
            }
            return;
        }
        if (id == NotificationCenter.didReceiveNewMessages) {
            boolean scheduled2 = ((Boolean) args[2]).booleanValue();
            if (!scheduled2 && (arrayList = this.voiceMessagesPlaylist) != null && !arrayList.isEmpty()) {
                MessageObject messageObject8 = this.voiceMessagesPlaylist.get(0);
                long did3 = ((Long) args[0]).longValue();
                if (did3 == messageObject8.getDialogId()) {
                    ArrayList<MessageObject> arr = (ArrayList) args[1];
                    for (int a2 = 0; a2 < arr.size(); a2++) {
                        MessageObject messageObject9 = arr.get(a2);
                        MessageObject messageObject10 = messageObject9;
                        if ((messageObject10.isVoice() || messageObject10.isRoundVideo()) && (!this.voiceMessagesPlaylistUnread || (messageObject10.isContentUnread() && !messageObject10.isOut()))) {
                            this.voiceMessagesPlaylist.add(messageObject10);
                            this.voiceMessagesPlaylistMap.put(messageObject10.getId(), messageObject10);
                        }
                    }
                    return;
                }
                return;
            }
            return;
        }
        if (id == NotificationCenter.playerDidStartPlaying) {
            VideoPlayer p = (VideoPlayer) args[0];
            if (!getInstance().isCurrentPlayer(p)) {
                getInstance().lambda$startAudioAgain$5$MediaController(getInstance().getPlayingMessageObject());
            }
        }
    }

    protected boolean isRecordingAudio() {
        return (this.recordStartRunnable == null && this.recordingAudio == null) ? false : true;
    }

    private boolean isNearToSensor(float value) {
        return value < 5.0f && value != this.proximitySensor.getMaximumRange();
    }

    public boolean isRecordingOrListeningByProximity() {
        MessageObject messageObject;
        return this.proximityTouched && (isRecordingAudio() || ((messageObject = this.playingMessageObject) != null && (messageObject.isVoice() || this.playingMessageObject.isRoundVideo())));
    }

    @Override // android.hardware.SensorEventListener
    public void onSensorChanged(SensorEvent event) {
        boolean goodValue;
        int sign;
        int i;
        PowerManager.WakeLock wakeLock;
        PowerManager.WakeLock wakeLock2;
        PowerManager.WakeLock wakeLock3;
        PowerManager.WakeLock wakeLock4;
        PowerManager.WakeLock wakeLock5;
        if (this.sensorsStarted && VoIPService.getSharedInstance() == null) {
            if (event.sensor != this.proximitySensor) {
                if (event.sensor == this.accelerometerSensor) {
                    double alpha = this.lastTimestamp == 0 ? 0.9800000190734863d : 1.0d / (((event.timestamp - this.lastTimestamp) / 1.0E9d) + 1.0d);
                    this.lastTimestamp = event.timestamp;
                    float[] fArr = this.gravity;
                    fArr[0] = (float) ((((double) fArr[0]) * alpha) + ((1.0d - alpha) * ((double) event.values[0])));
                    float[] fArr2 = this.gravity;
                    fArr2[1] = (float) ((((double) fArr2[1]) * alpha) + ((1.0d - alpha) * ((double) event.values[1])));
                    float[] fArr3 = this.gravity;
                    fArr3[2] = (float) ((((double) fArr3[2]) * alpha) + ((1.0d - alpha) * ((double) event.values[2])));
                    this.gravityFast[0] = (this.gravity[0] * 0.8f) + (event.values[0] * 0.19999999f);
                    this.gravityFast[1] = (this.gravity[1] * 0.8f) + (event.values[1] * 0.19999999f);
                    this.gravityFast[2] = (this.gravity[2] * 0.8f) + (event.values[2] * 0.19999999f);
                    this.linearAcceleration[0] = event.values[0] - this.gravity[0];
                    this.linearAcceleration[1] = event.values[1] - this.gravity[1];
                    this.linearAcceleration[2] = event.values[2] - this.gravity[2];
                } else if (event.sensor != this.linearSensor) {
                    if (event.sensor == this.gravitySensor) {
                        float[] fArr4 = this.gravityFast;
                        float[] fArr5 = this.gravity;
                        float f = event.values[0];
                        fArr5[0] = f;
                        fArr4[0] = f;
                        float[] fArr6 = this.gravityFast;
                        float[] fArr7 = this.gravity;
                        float f2 = event.values[1];
                        fArr7[1] = f2;
                        fArr6[1] = f2;
                        float[] fArr8 = this.gravityFast;
                        float[] fArr9 = this.gravity;
                        float f3 = event.values[2];
                        fArr9[2] = f3;
                        fArr8[2] = f3;
                    }
                } else {
                    this.linearAcceleration[0] = event.values[0];
                    this.linearAcceleration[1] = event.values[1];
                    this.linearAcceleration[2] = event.values[2];
                }
            } else {
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.d("proximity changed to " + event.values[0] + " max value = " + this.proximitySensor.getMaximumRange());
                }
                float f4 = this.lastProximityValue;
                if (f4 == -100.0f) {
                    this.lastProximityValue = event.values[0];
                } else if (f4 != event.values[0]) {
                    this.proximityHasDifferentValues = true;
                }
                if (this.proximityHasDifferentValues) {
                    this.proximityTouched = isNearToSensor(event.values[0]);
                }
            }
            if (event.sensor == this.linearSensor || event.sensor == this.gravitySensor || event.sensor == this.accelerometerSensor) {
                float[] fArr10 = this.gravity;
                float f5 = fArr10[0];
                float[] fArr11 = this.linearAcceleration;
                float val = (f5 * fArr11[0]) + (fArr10[1] * fArr11[1]) + (fArr10[2] * fArr11[2]);
                if (this.raisedToBack != 6 && ((val > 0.0f && this.previousAccValue > 0.0f) || (val < 0.0f && this.previousAccValue < 0.0f))) {
                    if (val > 0.0f) {
                        goodValue = val > 15.0f;
                        sign = 1;
                    } else {
                        goodValue = val < -15.0f;
                        sign = 2;
                    }
                    int i2 = this.raisedToTopSign;
                    if (i2 != 0 && i2 != sign) {
                        if (this.raisedToTop == 6 && goodValue) {
                            int i3 = this.raisedToBack;
                            if (i3 < 6) {
                                int i4 = i3 + 1;
                                this.raisedToBack = i4;
                                if (i4 == 6) {
                                    this.raisedToTop = 0;
                                    this.raisedToTopSign = 0;
                                    this.countLess = 0;
                                    this.timeSinceRaise = System.currentTimeMillis();
                                    if (BuildVars.LOGS_ENABLED && BuildVars.DEBUG_PRIVATE_VERSION) {
                                        FileLog.d("motion detected");
                                    }
                                }
                            }
                        } else {
                            if (!goodValue) {
                                this.countLess++;
                            }
                            if (this.countLess == 10 || this.raisedToTop != 6 || this.raisedToBack != 0) {
                                this.raisedToTop = 0;
                                this.raisedToTopSign = 0;
                                this.raisedToBack = 0;
                                this.countLess = 0;
                            }
                        }
                    } else if (goodValue && this.raisedToBack == 0 && ((i = this.raisedToTopSign) == 0 || i == sign)) {
                        int i5 = this.raisedToTop;
                        if (i5 < 6 && !this.proximityTouched) {
                            this.raisedToTopSign = sign;
                            int i6 = i5 + 1;
                            this.raisedToTop = i6;
                            if (i6 == 6) {
                                this.countLess = 0;
                            }
                        }
                    } else {
                        if (!goodValue) {
                            this.countLess++;
                        }
                        if (this.raisedToTopSign != sign || this.countLess == 10 || this.raisedToTop != 6 || this.raisedToBack != 0) {
                            this.raisedToBack = 0;
                            this.raisedToTop = 0;
                            this.raisedToTopSign = 0;
                            this.countLess = 0;
                        }
                    }
                }
                this.previousAccValue = val;
                float[] fArr12 = this.gravityFast;
                this.accelerometerVertical = fArr12[1] > 2.5f && Math.abs(fArr12[2]) < 4.0f && Math.abs(this.gravityFast[0]) > 1.5f;
            }
            if (this.raisedToBack == 6 && this.accelerometerVertical && this.proximityTouched && !NotificationsController.audioManager.isWiredHeadsetOn()) {
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.d("sensor values reached");
                }
                if (this.playingMessageObject == null && this.recordStartRunnable == null && this.recordingAudio == null && !PhotoViewer.getInstance().isVisible() && ApplicationLoader.isScreenOn && !this.inputFieldHasText && this.allowStartRecord && this.raiseChat != null && !this.callInProgress) {
                    if (!this.raiseToEarRecord) {
                        if (BuildVars.LOGS_ENABLED) {
                            FileLog.d("start record");
                        }
                        this.useFrontSpeaker = true;
                        if (!this.raiseChat.playFirstUnreadVoiceMessage()) {
                            this.raiseToEarRecord = true;
                            this.useFrontSpeaker = false;
                            startRecording(this.raiseChat.getCurrentAccount(), this.raiseChat.getDialogId(), null, this.raiseChat.getClassGuid());
                        }
                        if (this.useFrontSpeaker) {
                            setUseFrontSpeaker(true);
                        }
                        this.ignoreOnPause = true;
                        if (this.proximityHasDifferentValues && (wakeLock5 = this.proximityWakeLock) != null && !wakeLock5.isHeld()) {
                            this.proximityWakeLock.acquire();
                        }
                    }
                } else {
                    MessageObject messageObject = this.playingMessageObject;
                    if (messageObject != null && ((messageObject.isVoice() || this.playingMessageObject.isRoundVideo()) && !this.useFrontSpeaker)) {
                        if (BuildVars.LOGS_ENABLED) {
                            FileLog.d("start listen");
                        }
                        if (this.proximityHasDifferentValues && (wakeLock4 = this.proximityWakeLock) != null && !wakeLock4.isHeld()) {
                            this.proximityWakeLock.acquire();
                        }
                        setUseFrontSpeaker(true);
                        startAudioAgain(false);
                        this.ignoreOnPause = true;
                    }
                }
                this.raisedToBack = 0;
                this.raisedToTop = 0;
                this.raisedToTopSign = 0;
                this.countLess = 0;
            } else {
                boolean z = this.proximityTouched;
                if (z) {
                    if (this.playingMessageObject != null && !ApplicationLoader.mainInterfacePaused && ((this.playingMessageObject.isVoice() || this.playingMessageObject.isRoundVideo()) && !this.useFrontSpeaker)) {
                        if (BuildVars.LOGS_ENABLED) {
                            FileLog.d("start listen by proximity only");
                        }
                        if (this.proximityHasDifferentValues && (wakeLock3 = this.proximityWakeLock) != null && !wakeLock3.isHeld()) {
                            this.proximityWakeLock.acquire();
                        }
                        setUseFrontSpeaker(true);
                        startAudioAgain(false);
                        this.ignoreOnPause = true;
                    }
                } else if (!z) {
                    if (this.raiseToEarRecord) {
                        if (BuildVars.LOGS_ENABLED) {
                            FileLog.d("stop record");
                        }
                        stopRecording(2, false, 0);
                        this.raiseToEarRecord = false;
                        this.ignoreOnPause = false;
                        if (this.proximityHasDifferentValues && (wakeLock2 = this.proximityWakeLock) != null && wakeLock2.isHeld()) {
                            this.proximityWakeLock.release();
                        }
                    } else if (this.useFrontSpeaker) {
                        if (BuildVars.LOGS_ENABLED) {
                            FileLog.d("stop listen");
                        }
                        this.useFrontSpeaker = false;
                        startAudioAgain(true);
                        this.ignoreOnPause = false;
                        if (this.proximityHasDifferentValues && (wakeLock = this.proximityWakeLock) != null && wakeLock.isHeld()) {
                            this.proximityWakeLock.release();
                        }
                    }
                }
            }
            if (this.timeSinceRaise != 0 && this.raisedToBack == 6 && Math.abs(System.currentTimeMillis() - this.timeSinceRaise) > 1000) {
                this.raisedToBack = 0;
                this.raisedToTop = 0;
                this.raisedToTopSign = 0;
                this.countLess = 0;
                this.timeSinceRaise = 0L;
            }
        }
    }

    private void setUseFrontSpeaker(boolean value) {
        this.useFrontSpeaker = value;
        AudioManager audioManager = NotificationsController.audioManager;
        if (this.useFrontSpeaker) {
            audioManager.setBluetoothScoOn(false);
            audioManager.setSpeakerphoneOn(false);
        } else {
            audioManager.setSpeakerphoneOn(true);
        }
    }

    public void startRecordingIfFromSpeaker() {
        ChatActivity chatActivity;
        if (!this.useFrontSpeaker || (chatActivity = this.raiseChat) == null || !this.allowStartRecord) {
            return;
        }
        this.raiseToEarRecord = true;
        startRecording(chatActivity.getCurrentAccount(), this.raiseChat.getDialogId(), null, this.raiseChat.getClassGuid());
        this.ignoreOnPause = true;
    }

    private void startAudioAgain(boolean paused) {
        MessageObject messageObject = this.playingMessageObject;
        if (messageObject == null) {
            return;
        }
        NotificationCenter.getInstance(messageObject.currentAccount).postNotificationName(NotificationCenter.audioRouteChanged, Boolean.valueOf(this.useFrontSpeaker));
        VideoPlayer videoPlayer = this.videoPlayer;
        if (videoPlayer != null) {
            videoPlayer.setStreamType(this.useFrontSpeaker ? 0 : 3);
            if (!paused) {
                this.videoPlayer.play();
                return;
            } else {
                lambda$startAudioAgain$5$MediaController(this.playingMessageObject);
                return;
            }
        }
        boolean post = this.audioPlayer != null;
        final MessageObject currentMessageObject = this.playingMessageObject;
        float progress = this.playingMessageObject.audioProgress;
        cleanupPlayer(false, true);
        currentMessageObject.audioProgress = progress;
        playMessage(currentMessageObject);
        if (paused) {
            if (post) {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaController$m_adyCgWJXmOUq2qdbZDn-7SHUI
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$startAudioAgain$5$MediaController(currentMessageObject);
                    }
                }, 100L);
            } else {
                lambda$startAudioAgain$5$MediaController(currentMessageObject);
            }
        }
    }

    @Override // android.hardware.SensorEventListener
    public void onAccuracyChanged(Sensor sensor, int accuracy) {
    }

    public void setInputFieldHasText(boolean value) {
        this.inputFieldHasText = value;
    }

    public void setAllowStartRecord(boolean value) {
        this.allowStartRecord = value;
    }

    public void startRaiseToEarSensors(ChatActivity chatActivity) {
        if (chatActivity != null) {
            if ((this.accelerometerSensor == null && (this.gravitySensor == null || this.linearAcceleration == null)) || this.proximitySensor == null) {
                return;
            }
            this.raiseChat = chatActivity;
            if (!SharedConfig.raiseToSpeak) {
                MessageObject messageObject = this.playingMessageObject;
                if (messageObject == null) {
                    return;
                }
                if (!messageObject.isVoice() && !this.playingMessageObject.isRoundVideo()) {
                    return;
                }
            }
            if (!this.sensorsStarted) {
                float[] fArr = this.gravity;
                fArr[2] = 0.0f;
                fArr[1] = 0.0f;
                fArr[0] = 0.0f;
                float[] fArr2 = this.linearAcceleration;
                fArr2[2] = 0.0f;
                fArr2[1] = 0.0f;
                fArr2[0] = 0.0f;
                float[] fArr3 = this.gravityFast;
                fArr3[2] = 0.0f;
                fArr3[1] = 0.0f;
                fArr3[0] = 0.0f;
                this.lastTimestamp = 0L;
                this.previousAccValue = 0.0f;
                this.raisedToTop = 0;
                this.raisedToTopSign = 0;
                this.countLess = 0;
                this.raisedToBack = 0;
                Utilities.globalQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaController$GwfmAAnOarl4c-ZgaeoG8qZBOvU
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$startRaiseToEarSensors$6$MediaController();
                    }
                });
                this.sensorsStarted = true;
            }
        }
    }

    public /* synthetic */ void lambda$startRaiseToEarSensors$6$MediaController() {
        Sensor sensor = this.gravitySensor;
        if (sensor != null) {
            this.sensorManager.registerListener(this, sensor, 30000);
        }
        Sensor sensor2 = this.linearSensor;
        if (sensor2 != null) {
            this.sensorManager.registerListener(this, sensor2, 30000);
        }
        Sensor sensor3 = this.accelerometerSensor;
        if (sensor3 != null) {
            this.sensorManager.registerListener(this, sensor3, 30000);
        }
        this.sensorManager.registerListener(this, this.proximitySensor, 3);
    }

    public void stopRaiseToEarSensors(ChatActivity chatActivity, boolean fromChat) {
        PowerManager.WakeLock wakeLock;
        if (this.ignoreOnPause) {
            this.ignoreOnPause = false;
            return;
        }
        stopRecording(fromChat ? 2 : 0, false, 0);
        if (!this.sensorsStarted || this.ignoreOnPause) {
            return;
        }
        if ((this.accelerometerSensor == null && (this.gravitySensor == null || this.linearAcceleration == null)) || this.proximitySensor == null || this.raiseChat != chatActivity) {
            return;
        }
        this.raiseChat = null;
        this.sensorsStarted = false;
        this.accelerometerVertical = false;
        this.proximityTouched = false;
        this.raiseToEarRecord = false;
        this.useFrontSpeaker = false;
        Utilities.globalQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaController$oct1eNsvXRj0g-_9-eG_rRM6ras
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$stopRaiseToEarSensors$7$MediaController();
            }
        });
        if (this.proximityHasDifferentValues && (wakeLock = this.proximityWakeLock) != null && wakeLock.isHeld()) {
            this.proximityWakeLock.release();
        }
    }

    public /* synthetic */ void lambda$stopRaiseToEarSensors$7$MediaController() {
        Sensor sensor = this.linearSensor;
        if (sensor != null) {
            this.sensorManager.unregisterListener(this, sensor);
        }
        Sensor sensor2 = this.gravitySensor;
        if (sensor2 != null) {
            this.sensorManager.unregisterListener(this, sensor2);
        }
        Sensor sensor3 = this.accelerometerSensor;
        if (sensor3 != null) {
            this.sensorManager.unregisterListener(this, sensor3);
        }
        this.sensorManager.unregisterListener(this, this.proximitySensor);
    }

    public void cleanupPlayer(boolean notify, boolean stopService) {
        cleanupPlayer(notify, stopService, false, false);
    }

    /* JADX WARN: Removed duplicated region for block: B:55:0x0149 A[PHI: r2
      0x0149: PHI (r2v6 'index' int) = (r2v4 'index' int), (r2v7 'index' int) binds: [B:49:0x0125, B:51:0x012c] A[DONT_GENERATE, DONT_INLINE]] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void cleanupPlayer(boolean r14, boolean r15, boolean r16, boolean r17) {
        /*
            Method dump skipped, instruction units count: 449
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MediaController.cleanupPlayer(boolean, boolean, boolean, boolean):void");
    }

    public boolean isGoingToShowMessageObject(MessageObject messageObject) {
        return this.goingToShowMessageObject == messageObject;
    }

    public void resetGoingToShowMessageObject() {
        this.goingToShowMessageObject = null;
    }

    private boolean isSamePlayingMessage(MessageObject messageObject) {
        MessageObject messageObject2 = this.playingMessageObject;
        if (messageObject2 != null && messageObject2.getDialogId() == messageObject.getDialogId() && this.playingMessageObject.getId() == messageObject.getId()) {
            if ((this.playingMessageObject.eventId == 0) == (messageObject.eventId == 0)) {
                return true;
            }
        }
        return false;
    }

    public boolean seekToProgress(MessageObject messageObject, float progress) {
        if ((this.audioPlayer == null && this.videoPlayer == null) || messageObject == null || this.playingMessageObject == null || !isSamePlayingMessage(messageObject)) {
            return false;
        }
        try {
            if (this.audioPlayer != null) {
                long duration = this.audioPlayer.getDuration();
                if (duration == C.TIME_UNSET) {
                    this.seekToProgressPending = progress;
                } else {
                    int seekTo = (int) (duration * progress);
                    this.audioPlayer.seekTo(seekTo);
                    this.lastProgress = seekTo;
                }
            } else if (this.videoPlayer != null) {
                this.videoPlayer.seekTo((long) (this.videoPlayer.getDuration() * progress));
            }
            NotificationCenter.getInstance(messageObject.currentAccount).postNotificationName(NotificationCenter.messagePlayingDidSeek, Integer.valueOf(this.playingMessageObject.getId()), Float.valueOf(progress));
            return true;
        } catch (Exception e) {
            FileLog.e(e);
            return false;
        }
    }

    public MessageObject getPlayingMessageObject() {
        return this.playingMessageObject;
    }

    public int getPlayingMessageObjectNum() {
        return this.currentPlaylistNum;
    }

    private void buildShuffledPlayList() {
        if (this.playlist.isEmpty()) {
            return;
        }
        ArrayList<MessageObject> all = new ArrayList<>(this.playlist);
        this.shuffledPlaylist.clear();
        MessageObject messageObject = this.playlist.get(this.currentPlaylistNum);
        all.remove(this.currentPlaylistNum);
        this.shuffledPlaylist.add(messageObject);
        int count = all.size();
        for (int a = 0; a < count; a++) {
            int index = Utilities.random.nextInt(all.size());
            this.shuffledPlaylist.add(all.get(index));
            all.remove(index);
        }
    }

    public boolean setPlaylist(ArrayList<MessageObject> messageObjects, MessageObject current) {
        return setPlaylist(messageObjects, current, true);
    }

    public boolean setPlaylist(ArrayList<MessageObject> messageObjects, MessageObject current, boolean loadMusic) {
        if (this.playingMessageObject == current) {
            return playMessage(current);
        }
        this.forceLoopCurrentPlaylist = !loadMusic;
        this.playMusicAgain = !this.playlist.isEmpty();
        this.playlist.clear();
        for (int a = messageObjects.size() - 1; a >= 0; a--) {
            MessageObject messageObject = messageObjects.get(a);
            if (messageObject.isMusic()) {
                this.playlist.add(messageObject);
            }
        }
        int iIndexOf = this.playlist.indexOf(current);
        this.currentPlaylistNum = iIndexOf;
        if (iIndexOf == -1) {
            this.playlist.clear();
            this.shuffledPlaylist.clear();
            this.currentPlaylistNum = this.playlist.size();
            this.playlist.add(current);
        }
        if (current.isMusic() && !current.scheduled) {
            if (SharedConfig.shuffleMusic) {
                buildShuffledPlayList();
                this.currentPlaylistNum = 0;
            }
            if (loadMusic) {
                MediaDataController.getInstance(current.currentAccount).loadMusic(current.getDialogId(), this.playlist.get(0).getIdWithChannel());
            }
        }
        return playMessage(current);
    }

    public void playNextMessage() {
        playNextMessageWithoutOrder(false);
    }

    public boolean findMessageInPlaylistAndPlay(MessageObject messageObject) {
        int index = this.playlist.indexOf(messageObject);
        if (index == -1) {
            return playMessage(messageObject);
        }
        playMessageAtIndex(index);
        return true;
    }

    public void playMessageAtIndex(int index) {
        int i = this.currentPlaylistNum;
        if (i < 0 || i >= this.playlist.size()) {
            return;
        }
        this.currentPlaylistNum = index;
        this.playMusicAgain = true;
        MessageObject messageObject = this.playingMessageObject;
        if (messageObject != null) {
            messageObject.resetPlayingProgress();
        }
        playMessage(this.playlist.get(this.currentPlaylistNum));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void playNextMessageWithoutOrder(boolean byStop) {
        ArrayList<MessageObject> currentPlayList = SharedConfig.shuffleMusic ? this.shuffledPlaylist : this.playlist;
        if (byStop && ((SharedConfig.repeatMode == 2 || (SharedConfig.repeatMode == 1 && currentPlayList.size() == 1)) && !this.forceLoopCurrentPlaylist)) {
            cleanupPlayer(false, false);
            MessageObject messageObject = currentPlayList.get(this.currentPlaylistNum);
            messageObject.audioProgress = 0.0f;
            messageObject.audioProgressSec = 0;
            playMessage(messageObject);
            return;
        }
        boolean last = false;
        if (SharedConfig.playOrderReversed) {
            int i = this.currentPlaylistNum + 1;
            this.currentPlaylistNum = i;
            if (i >= currentPlayList.size()) {
                this.currentPlaylistNum = 0;
                last = true;
            }
        } else {
            int i2 = this.currentPlaylistNum - 1;
            this.currentPlaylistNum = i2;
            if (i2 < 0) {
                this.currentPlaylistNum = currentPlayList.size() - 1;
                last = true;
            }
        }
        if (last && byStop && SharedConfig.repeatMode == 0 && !this.forceLoopCurrentPlaylist) {
            if (this.audioPlayer != null || this.videoPlayer != null) {
                VideoPlayer videoPlayer = this.audioPlayer;
                if (videoPlayer != null) {
                    try {
                        videoPlayer.releasePlayer(true);
                    } catch (Exception e) {
                        FileLog.e(e);
                    }
                    this.audioPlayer = null;
                } else {
                    VideoPlayer videoPlayer2 = this.videoPlayer;
                    if (videoPlayer2 != null) {
                        this.currentAspectRatioFrameLayout = null;
                        this.currentTextureViewContainer = null;
                        this.currentAspectRatioFrameLayoutReady = false;
                        this.currentTextureView = null;
                        videoPlayer2.releasePlayer(true);
                        this.videoPlayer = null;
                        try {
                            this.baseActivity.getWindow().clearFlags(128);
                        } catch (Exception e2) {
                            FileLog.e(e2);
                        }
                        AndroidUtilities.cancelRunOnUIThread(this.setLoadingRunnable);
                        FileLoader.getInstance(this.playingMessageObject.currentAccount).removeLoadingVideo(this.playingMessageObject.getDocument(), true, false);
                    }
                }
                stopProgressTimer();
                this.lastProgress = 0L;
                this.isPaused = true;
                this.playingMessageObject.audioProgress = 0.0f;
                this.playingMessageObject.audioProgressSec = 0;
                NotificationCenter.getInstance(this.playingMessageObject.currentAccount).postNotificationName(NotificationCenter.messagePlayingProgressDidChanged, Integer.valueOf(this.playingMessageObject.getId()), 0);
                NotificationCenter.getInstance(this.playingMessageObject.currentAccount).postNotificationName(NotificationCenter.messagePlayingPlayStateChanged, Integer.valueOf(this.playingMessageObject.getId()));
                return;
            }
            return;
        }
        int i3 = this.currentPlaylistNum;
        if (i3 < 0 || i3 >= currentPlayList.size()) {
            return;
        }
        MessageObject messageObject2 = this.playingMessageObject;
        if (messageObject2 != null) {
            messageObject2.resetPlayingProgress();
        }
        this.playMusicAgain = true;
        playMessage(currentPlayList.get(this.currentPlaylistNum));
    }

    public void playPreviousMessage() {
        int i;
        ArrayList<MessageObject> currentPlayList = SharedConfig.shuffleMusic ? this.shuffledPlaylist : this.playlist;
        if (currentPlayList.isEmpty() || (i = this.currentPlaylistNum) < 0 || i >= currentPlayList.size()) {
            return;
        }
        MessageObject currentSong = currentPlayList.get(this.currentPlaylistNum);
        if (currentSong.audioProgressSec > 10) {
            seekToProgress(currentSong, 0.0f);
            return;
        }
        if (SharedConfig.playOrderReversed) {
            int i2 = this.currentPlaylistNum - 1;
            this.currentPlaylistNum = i2;
            if (i2 < 0) {
                this.currentPlaylistNum = currentPlayList.size() - 1;
            }
        } else {
            int i3 = this.currentPlaylistNum + 1;
            this.currentPlaylistNum = i3;
            if (i3 >= currentPlayList.size()) {
                this.currentPlaylistNum = 0;
            }
        }
        int i4 = this.currentPlaylistNum;
        if (i4 < 0 || i4 >= currentPlayList.size()) {
            return;
        }
        this.playMusicAgain = true;
        playMessage(currentPlayList.get(this.currentPlaylistNum));
    }

    protected void checkIsNextMediaFileDownloaded() {
        MessageObject messageObject = this.playingMessageObject;
        if (messageObject == null || !messageObject.isMusic()) {
            return;
        }
        checkIsNextMusicFileDownloaded(this.playingMessageObject.currentAccount);
    }

    private void checkIsNextVoiceFileDownloaded(int currentAccount) {
        ArrayList<MessageObject> arrayList = this.voiceMessagesPlaylist;
        if (arrayList == null || arrayList.size() < 2) {
            return;
        }
        MessageObject nextAudio = this.voiceMessagesPlaylist.get(1);
        File file = null;
        if (nextAudio.messageOwner.attachPath != null && nextAudio.messageOwner.attachPath.length() > 0) {
            file = new File(nextAudio.messageOwner.attachPath);
            if (!file.exists()) {
                file = null;
            }
        }
        File cacheFile = file != null ? file : FileLoader.getPathToMessage(nextAudio.messageOwner);
        if (cacheFile == null || !cacheFile.exists()) {
        }
        if (cacheFile != null && cacheFile != file && !cacheFile.exists()) {
            FileLoader.getInstance(currentAccount).loadFile(nextAudio.getDocument(), nextAudio, 0, 0);
        }
    }

    private void checkIsNextMusicFileDownloaded(int currentAccount) {
        int nextIndex;
        if (!DownloadController.getInstance(currentAccount).canDownloadNextTrack()) {
            return;
        }
        ArrayList<MessageObject> currentPlayList = SharedConfig.shuffleMusic ? this.shuffledPlaylist : this.playlist;
        if (currentPlayList == null || currentPlayList.size() < 2) {
            return;
        }
        if (SharedConfig.playOrderReversed) {
            nextIndex = this.currentPlaylistNum + 1;
            if (nextIndex >= currentPlayList.size()) {
                nextIndex = 0;
            }
        } else {
            nextIndex = this.currentPlaylistNum - 1;
            if (nextIndex < 0) {
                nextIndex = currentPlayList.size() - 1;
            }
        }
        if (nextIndex < 0 || nextIndex >= currentPlayList.size()) {
            return;
        }
        MessageObject nextAudio = currentPlayList.get(nextIndex);
        File file = null;
        if (!TextUtils.isEmpty(nextAudio.messageOwner.attachPath)) {
            file = new File(nextAudio.messageOwner.attachPath);
            if (!file.exists()) {
                file = null;
            }
        }
        File cacheFile = file != null ? file : FileLoader.getPathToMessage(nextAudio.messageOwner);
        if (cacheFile == null || !cacheFile.exists()) {
        }
        if (cacheFile != null && cacheFile != file && !cacheFile.exists() && nextAudio.isMusic()) {
            FileLoader.getInstance(currentAccount).loadFile(nextAudio.getDocument(), nextAudio, 0, 0);
        }
    }

    public void setVoiceMessagesPlaylist(ArrayList<MessageObject> playlist, boolean unread) {
        this.voiceMessagesPlaylist = playlist;
        if (playlist != null) {
            this.voiceMessagesPlaylistUnread = unread;
            this.voiceMessagesPlaylistMap = new SparseArray<>();
            for (int a = 0; a < this.voiceMessagesPlaylist.size(); a++) {
                MessageObject messageObject = this.voiceMessagesPlaylist.get(a);
                this.voiceMessagesPlaylistMap.put(messageObject.getId(), messageObject);
            }
        }
    }

    private void checkAudioFocus(MessageObject messageObject) {
        int neededAudioFocus;
        int result;
        if (messageObject.isVoice() || messageObject.isRoundVideo()) {
            if (this.useFrontSpeaker) {
                neededAudioFocus = 3;
            } else {
                neededAudioFocus = 2;
            }
        } else {
            neededAudioFocus = 1;
        }
        if (this.hasAudioFocus != neededAudioFocus) {
            this.hasAudioFocus = neededAudioFocus;
            if (neededAudioFocus != 3) {
                result = NotificationsController.audioManager.requestAudioFocus(this, 3, neededAudioFocus == 2 ? 3 : 1);
            } else {
                result = NotificationsController.audioManager.requestAudioFocus(this, 0, 1);
            }
            if (result == 1) {
                this.audioFocus = 2;
            }
        }
    }

    public void setCurrentVideoVisible(boolean visible) {
        AspectRatioFrameLayout aspectRatioFrameLayout = this.currentAspectRatioFrameLayout;
        if (aspectRatioFrameLayout == null) {
            return;
        }
        if (visible) {
            PipRoundVideoView pipRoundVideoView = this.pipRoundVideoView;
            if (pipRoundVideoView != null) {
                this.pipSwitchingState = 2;
                pipRoundVideoView.close(true);
                this.pipRoundVideoView = null;
                return;
            } else {
                if (aspectRatioFrameLayout != null) {
                    if (aspectRatioFrameLayout.getParent() == null) {
                        this.currentTextureViewContainer.addView(this.currentAspectRatioFrameLayout);
                    }
                    this.videoPlayer.setTextureView(this.currentTextureView);
                    return;
                }
                return;
            }
        }
        if (aspectRatioFrameLayout.getParent() != null) {
            this.pipSwitchingState = 1;
            this.currentTextureViewContainer.removeView(this.currentAspectRatioFrameLayout);
            return;
        }
        if (this.pipRoundVideoView == null) {
            try {
                PipRoundVideoView pipRoundVideoView2 = new PipRoundVideoView();
                this.pipRoundVideoView = pipRoundVideoView2;
                pipRoundVideoView2.show(this.baseActivity, new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaController$rM_wBhDzXbTROjXV8ZbPjpJ6mMw
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$setCurrentVideoVisible$8$MediaController();
                    }
                });
            } catch (Exception e) {
                this.pipRoundVideoView = null;
            }
        }
        PipRoundVideoView pipRoundVideoView3 = this.pipRoundVideoView;
        if (pipRoundVideoView3 != null) {
            this.videoPlayer.setTextureView(pipRoundVideoView3.getTextureView());
        }
    }

    public /* synthetic */ void lambda$setCurrentVideoVisible$8$MediaController() {
        cleanupPlayer(true, true);
    }

    public void setTextureView(TextureView textureView, AspectRatioFrameLayout aspectRatioFrameLayout, FrameLayout container, boolean set) {
        if (textureView == null) {
            return;
        }
        if (!set && this.currentTextureView == textureView) {
            this.pipSwitchingState = 1;
            this.currentTextureView = null;
            this.currentAspectRatioFrameLayout = null;
            this.currentTextureViewContainer = null;
            return;
        }
        if (this.videoPlayer == null || textureView == this.currentTextureView) {
            return;
        }
        this.isDrawingWasReady = aspectRatioFrameLayout != null && aspectRatioFrameLayout.isDrawingReady();
        this.currentTextureView = textureView;
        PipRoundVideoView pipRoundVideoView = this.pipRoundVideoView;
        if (pipRoundVideoView != null) {
            this.videoPlayer.setTextureView(pipRoundVideoView.getTextureView());
        } else {
            this.videoPlayer.setTextureView(textureView);
        }
        this.currentAspectRatioFrameLayout = aspectRatioFrameLayout;
        this.currentTextureViewContainer = container;
        if (this.currentAspectRatioFrameLayoutReady && aspectRatioFrameLayout != null && aspectRatioFrameLayout != null) {
            aspectRatioFrameLayout.setAspectRatio(this.currentAspectRatioFrameLayoutRatio, this.currentAspectRatioFrameLayoutRotation);
        }
    }

    public boolean hasFlagSecureFragment() {
        return this.flagSecureFragment != null;
    }

    public void setFlagSecure(BaseFragment parentFragment, boolean set) {
        if (set) {
            try {
                parentFragment.getParentActivity().getWindow().setFlags(8192, 8192);
            } catch (Exception e) {
            }
            this.flagSecureFragment = parentFragment;
        } else if (this.flagSecureFragment == parentFragment) {
            try {
                parentFragment.getParentActivity().getWindow().clearFlags(8192);
            } catch (Exception e2) {
            }
            this.flagSecureFragment = null;
        }
    }

    public void setBaseActivity(Activity activity, boolean set) {
        if (set) {
            this.baseActivity = activity;
        } else if (this.baseActivity == activity) {
            this.baseActivity = null;
        }
    }

    public void setFeedbackView(View view, boolean set) {
        if (set) {
            this.feedbackView = view;
        } else if (this.feedbackView == view) {
            this.feedbackView = null;
        }
    }

    public void setPlaybackSpeed(float speed) {
        this.currentPlaybackSpeed = speed;
        VideoPlayer videoPlayer = this.audioPlayer;
        if (videoPlayer != null) {
            videoPlayer.setPlaybackSpeed(speed);
        } else {
            VideoPlayer videoPlayer2 = this.videoPlayer;
            if (videoPlayer2 != null) {
                videoPlayer2.setPlaybackSpeed(speed);
            }
        }
        MessagesController.getGlobalMainSettings().edit().putFloat("playbackSpeed", speed).commit();
    }

    public float getPlaybackSpeed() {
        return this.currentPlaybackSpeed;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateVideoState(MessageObject messageObject, int[] playCount, boolean destroyAtEnd, boolean playWhenReady, int playbackState) {
        MessageObject messageObject2;
        if (this.videoPlayer == null) {
            return;
        }
        if (playbackState == 4 || playbackState == 1) {
            try {
                this.baseActivity.getWindow().clearFlags(128);
            } catch (Exception e) {
                FileLog.e(e);
            }
        } else {
            try {
                this.baseActivity.getWindow().addFlags(128);
            } catch (Exception e2) {
                FileLog.e(e2);
            }
        }
        if (playbackState == 3) {
            this.playerWasReady = true;
            MessageObject messageObject3 = this.playingMessageObject;
            if (messageObject3 != null && (messageObject3.isVideo() || this.playingMessageObject.isRoundVideo())) {
                AndroidUtilities.cancelRunOnUIThread(this.setLoadingRunnable);
                FileLoader.getInstance(messageObject.currentAccount).removeLoadingVideo(this.playingMessageObject.getDocument(), true, false);
            }
            this.currentAspectRatioFrameLayoutReady = true;
            return;
        }
        if (playbackState == 2) {
            if (!playWhenReady || (messageObject2 = this.playingMessageObject) == null) {
                return;
            }
            if (messageObject2.isVideo() || this.playingMessageObject.isRoundVideo()) {
                if (this.playerWasReady) {
                    this.setLoadingRunnable.run();
                    return;
                } else {
                    AndroidUtilities.runOnUIThread(this.setLoadingRunnable, 1000L);
                    return;
                }
            }
            return;
        }
        if (this.videoPlayer.isPlaying() && playbackState == 4) {
            if (this.playingMessageObject.isVideo() && !destroyAtEnd && (playCount == null || playCount[0] < 4)) {
                this.videoPlayer.seekTo(0L);
                if (playCount != null) {
                    playCount[0] = playCount[0] + 1;
                    return;
                }
                return;
            }
            cleanupPlayer(true, true, true, false);
        }
    }

    public void injectVideoPlayer(VideoPlayer player, MessageObject messageObject) {
        if (player == null || messageObject == null) {
            return;
        }
        FileLoader.getInstance(messageObject.currentAccount).setLoadingVideoForPlayer(messageObject.getDocument(), true);
        this.playerWasReady = false;
        this.playlist.clear();
        this.shuffledPlaylist.clear();
        this.videoPlayer = player;
        this.playingMessageObject = messageObject;
        player.setDelegate(new AnonymousClass5(messageObject, null, true));
        this.currentAspectRatioFrameLayoutReady = false;
        TextureView textureView = this.currentTextureView;
        if (textureView != null) {
            this.videoPlayer.setTextureView(textureView);
        }
        checkAudioFocus(messageObject);
        setPlayerVolume();
        this.isPaused = false;
        this.lastProgress = 0L;
        this.playingMessageObject = messageObject;
        if (!SharedConfig.raiseToSpeak) {
            startRaiseToEarSensors(this.raiseChat);
        }
        startProgressTimer(this.playingMessageObject);
        NotificationCenter.getInstance(messageObject.currentAccount).postNotificationName(NotificationCenter.messagePlayingDidStart, messageObject);
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.messenger.MediaController$5, reason: invalid class name */
    class AnonymousClass5 implements VideoPlayer.VideoPlayerDelegate {
        final /* synthetic */ boolean val$destroyAtEnd;
        final /* synthetic */ MessageObject val$messageObject;
        final /* synthetic */ int[] val$playCount;

        AnonymousClass5(MessageObject messageObject, int[] iArr, boolean z) {
            this.val$messageObject = messageObject;
            this.val$playCount = iArr;
            this.val$destroyAtEnd = z;
        }

        @Override // im.uwrkaxlmjj.ui.components.VideoPlayer.VideoPlayerDelegate
        public void onStateChanged(boolean playWhenReady, int playbackState) {
            MediaController.this.updateVideoState(this.val$messageObject, this.val$playCount, this.val$destroyAtEnd, playWhenReady, playbackState);
        }

        @Override // im.uwrkaxlmjj.ui.components.VideoPlayer.VideoPlayerDelegate
        public void onError(Exception e) {
            FileLog.e(e);
        }

        @Override // im.uwrkaxlmjj.ui.components.VideoPlayer.VideoPlayerDelegate
        public void onVideoSizeChanged(int width, int height, int unappliedRotationDegrees, float pixelWidthHeightRatio) {
            MediaController.this.currentAspectRatioFrameLayoutRotation = unappliedRotationDegrees;
            if (unappliedRotationDegrees == 90 || unappliedRotationDegrees == 270) {
                width = height;
                height = width;
            }
            MediaController.this.currentAspectRatioFrameLayoutRatio = height == 0 ? 1.0f : (width * pixelWidthHeightRatio) / height;
            if (MediaController.this.currentAspectRatioFrameLayout != null) {
                MediaController.this.currentAspectRatioFrameLayout.setAspectRatio(MediaController.this.currentAspectRatioFrameLayoutRatio, MediaController.this.currentAspectRatioFrameLayoutRotation);
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.VideoPlayer.VideoPlayerDelegate
        public void onRenderedFirstFrame() {
            if (MediaController.this.currentAspectRatioFrameLayout != null && !MediaController.this.currentAspectRatioFrameLayout.isDrawingReady()) {
                MediaController.this.isDrawingWasReady = true;
                MediaController.this.currentAspectRatioFrameLayout.setDrawingReady(true);
                MediaController.this.currentTextureViewContainer.setTag(1);
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.VideoPlayer.VideoPlayerDelegate
        public boolean onSurfaceDestroyed(SurfaceTexture surfaceTexture) {
            if (MediaController.this.videoPlayer == null) {
                return false;
            }
            if (MediaController.this.pipSwitchingState == 2) {
                if (MediaController.this.currentAspectRatioFrameLayout != null) {
                    if (MediaController.this.isDrawingWasReady) {
                        MediaController.this.currentAspectRatioFrameLayout.setDrawingReady(true);
                    }
                    if (MediaController.this.currentAspectRatioFrameLayout.getParent() == null) {
                        MediaController.this.currentTextureViewContainer.addView(MediaController.this.currentAspectRatioFrameLayout);
                    }
                    if (MediaController.this.currentTextureView.getSurfaceTexture() != surfaceTexture) {
                        MediaController.this.currentTextureView.setSurfaceTexture(surfaceTexture);
                    }
                    MediaController.this.videoPlayer.setTextureView(MediaController.this.currentTextureView);
                }
                MediaController.this.pipSwitchingState = 0;
                return true;
            }
            if (MediaController.this.pipSwitchingState == 1) {
                if (MediaController.this.baseActivity != null) {
                    if (MediaController.this.pipRoundVideoView == null) {
                        try {
                            MediaController.this.pipRoundVideoView = new PipRoundVideoView();
                            MediaController.this.pipRoundVideoView.show(MediaController.this.baseActivity, new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaController$5$sXDQEY_N-4owGZdsFwHeb8ojrCk
                                @Override // java.lang.Runnable
                                public final void run() {
                                    this.f$0.lambda$onSurfaceDestroyed$0$MediaController$5();
                                }
                            });
                        } catch (Exception e) {
                            MediaController.this.pipRoundVideoView = null;
                        }
                    }
                    if (MediaController.this.pipRoundVideoView != null) {
                        if (MediaController.this.pipRoundVideoView.getTextureView().getSurfaceTexture() != surfaceTexture) {
                            MediaController.this.pipRoundVideoView.getTextureView().setSurfaceTexture(surfaceTexture);
                        }
                        MediaController.this.videoPlayer.setTextureView(MediaController.this.pipRoundVideoView.getTextureView());
                    }
                }
                MediaController.this.pipSwitchingState = 0;
                return true;
            }
            if (!PhotoViewer.hasInstance() || !PhotoViewer.getInstance().isInjectingVideoPlayer()) {
                return false;
            }
            PhotoViewer.getInstance().injectVideoPlayerSurface(surfaceTexture);
            return true;
        }

        public /* synthetic */ void lambda$onSurfaceDestroyed$0$MediaController$5() {
            MediaController.this.cleanupPlayer(true, true);
        }

        @Override // im.uwrkaxlmjj.ui.components.VideoPlayer.VideoPlayerDelegate
        public void onSurfaceTextureUpdated(SurfaceTexture surfaceTexture) {
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:109:0x0267 A[Catch: Exception -> 0x02a4, TryCatch #11 {Exception -> 0x02a4, blocks: (B:107:0x0261, B:109:0x0267, B:111:0x026d, B:112:0x0274, B:118:0x028d, B:122:0x0296, B:117:0x028a, B:106:0x025c, B:114:0x0282), top: B:271:0x025c, inners: #4 }] */
    /* JADX WARN: Removed duplicated region for block: B:120:0x0293  */
    /* JADX WARN: Removed duplicated region for block: B:121:0x0295  */
    /* JADX WARN: Removed duplicated region for block: B:134:0x02c5  */
    /* JADX WARN: Removed duplicated region for block: B:135:0x02ca  */
    /* JADX WARN: Removed duplicated region for block: B:138:0x02d9  */
    /* JADX WARN: Removed duplicated region for block: B:175:0x03a0  */
    /* JADX WARN: Removed duplicated region for block: B:182:0x03bf  */
    /* JADX WARN: Removed duplicated region for block: B:198:0x046b  */
    /* JADX WARN: Removed duplicated region for block: B:205:0x0483  */
    /* JADX WARN: Removed duplicated region for block: B:209:0x049f  */
    /* JADX WARN: Removed duplicated region for block: B:225:0x0531  */
    /* JADX WARN: Removed duplicated region for block: B:238:0x058a  */
    /* JADX WARN: Removed duplicated region for block: B:257:0x0282 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:273:0x04c6 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean playMessage(final im.uwrkaxlmjj.messenger.MessageObject r31) {
        /*
            Method dump skipped, instruction units count: 1461
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MediaController.playMessage(im.uwrkaxlmjj.messenger.MessageObject):boolean");
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.messenger.MediaController$6, reason: invalid class name */
    class AnonymousClass6 implements VideoPlayer.VideoPlayerDelegate {
        final /* synthetic */ boolean val$destroyAtEnd;
        final /* synthetic */ MessageObject val$messageObject;
        final /* synthetic */ int[] val$playCount;

        AnonymousClass6(MessageObject messageObject, int[] iArr, boolean z) {
            this.val$messageObject = messageObject;
            this.val$playCount = iArr;
            this.val$destroyAtEnd = z;
        }

        @Override // im.uwrkaxlmjj.ui.components.VideoPlayer.VideoPlayerDelegate
        public void onStateChanged(boolean playWhenReady, int playbackState) {
            MediaController.this.updateVideoState(this.val$messageObject, this.val$playCount, this.val$destroyAtEnd, playWhenReady, playbackState);
        }

        @Override // im.uwrkaxlmjj.ui.components.VideoPlayer.VideoPlayerDelegate
        public void onError(Exception e) {
            FileLog.e(e);
        }

        @Override // im.uwrkaxlmjj.ui.components.VideoPlayer.VideoPlayerDelegate
        public void onVideoSizeChanged(int width, int height, int unappliedRotationDegrees, float pixelWidthHeightRatio) {
            MediaController.this.currentAspectRatioFrameLayoutRotation = unappliedRotationDegrees;
            if (unappliedRotationDegrees == 90 || unappliedRotationDegrees == 270) {
                width = height;
                height = width;
            }
            MediaController.this.currentAspectRatioFrameLayoutRatio = height == 0 ? 1.0f : (width * pixelWidthHeightRatio) / height;
            if (MediaController.this.currentAspectRatioFrameLayout != null) {
                MediaController.this.currentAspectRatioFrameLayout.setAspectRatio(MediaController.this.currentAspectRatioFrameLayoutRatio, MediaController.this.currentAspectRatioFrameLayoutRotation);
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.VideoPlayer.VideoPlayerDelegate
        public void onRenderedFirstFrame() {
            if (MediaController.this.currentAspectRatioFrameLayout != null && !MediaController.this.currentAspectRatioFrameLayout.isDrawingReady()) {
                MediaController.this.isDrawingWasReady = true;
                MediaController.this.currentAspectRatioFrameLayout.setDrawingReady(true);
                MediaController.this.currentTextureViewContainer.setTag(1);
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.VideoPlayer.VideoPlayerDelegate
        public boolean onSurfaceDestroyed(SurfaceTexture surfaceTexture) {
            if (MediaController.this.videoPlayer == null) {
                return false;
            }
            if (MediaController.this.pipSwitchingState == 2) {
                if (MediaController.this.currentAspectRatioFrameLayout != null) {
                    if (MediaController.this.isDrawingWasReady) {
                        MediaController.this.currentAspectRatioFrameLayout.setDrawingReady(true);
                    }
                    if (MediaController.this.currentAspectRatioFrameLayout.getParent() == null) {
                        MediaController.this.currentTextureViewContainer.addView(MediaController.this.currentAspectRatioFrameLayout);
                    }
                    if (MediaController.this.currentTextureView.getSurfaceTexture() != surfaceTexture) {
                        MediaController.this.currentTextureView.setSurfaceTexture(surfaceTexture);
                    }
                    MediaController.this.videoPlayer.setTextureView(MediaController.this.currentTextureView);
                }
                MediaController.this.pipSwitchingState = 0;
                return true;
            }
            if (MediaController.this.pipSwitchingState == 1) {
                if (MediaController.this.baseActivity != null) {
                    if (MediaController.this.pipRoundVideoView == null) {
                        try {
                            MediaController.this.pipRoundVideoView = new PipRoundVideoView();
                            MediaController.this.pipRoundVideoView.show(MediaController.this.baseActivity, new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaController$6$RpE4BKvvAl_JQ3bv_eRCVP0ewmI
                                @Override // java.lang.Runnable
                                public final void run() {
                                    this.f$0.lambda$onSurfaceDestroyed$0$MediaController$6();
                                }
                            });
                        } catch (Exception e) {
                            MediaController.this.pipRoundVideoView = null;
                        }
                    }
                    if (MediaController.this.pipRoundVideoView != null) {
                        if (MediaController.this.pipRoundVideoView.getTextureView().getSurfaceTexture() != surfaceTexture) {
                            MediaController.this.pipRoundVideoView.getTextureView().setSurfaceTexture(surfaceTexture);
                        }
                        MediaController.this.videoPlayer.setTextureView(MediaController.this.pipRoundVideoView.getTextureView());
                    }
                }
                MediaController.this.pipSwitchingState = 0;
                return true;
            }
            if (!PhotoViewer.hasInstance() || !PhotoViewer.getInstance().isInjectingVideoPlayer()) {
                return false;
            }
            PhotoViewer.getInstance().injectVideoPlayerSurface(surfaceTexture);
            return true;
        }

        public /* synthetic */ void lambda$onSurfaceDestroyed$0$MediaController$6() {
            MediaController.this.cleanupPlayer(true, true);
        }

        @Override // im.uwrkaxlmjj.ui.components.VideoPlayer.VideoPlayerDelegate
        public void onSurfaceTextureUpdated(SurfaceTexture surfaceTexture) {
        }
    }

    public /* synthetic */ void lambda$playMessage$9$MediaController() {
        cleanupPlayer(true, true);
    }

    public AudioInfo getAudioInfo() {
        return this.audioInfo;
    }

    public void toggleShuffleMusic(int type) {
        boolean oldShuffle = SharedConfig.shuffleMusic;
        SharedConfig.toggleShuffleMusic(type);
        if (oldShuffle != SharedConfig.shuffleMusic) {
            if (SharedConfig.shuffleMusic) {
                buildShuffledPlayList();
                this.currentPlaylistNum = 0;
                return;
            }
            MessageObject messageObject = this.playingMessageObject;
            if (messageObject != null) {
                int iIndexOf = this.playlist.indexOf(messageObject);
                this.currentPlaylistNum = iIndexOf;
                if (iIndexOf == -1) {
                    this.playlist.clear();
                    this.shuffledPlaylist.clear();
                    cleanupPlayer(true, true);
                }
            }
        }
    }

    public boolean isCurrentPlayer(VideoPlayer player) {
        return this.videoPlayer == player || this.audioPlayer == player;
    }

    /* JADX INFO: renamed from: pauseMessage, reason: merged with bridge method [inline-methods] */
    public boolean lambda$startAudioAgain$5$MediaController(MessageObject messageObject) {
        if ((this.audioPlayer == null && this.videoPlayer == null) || messageObject == null || this.playingMessageObject == null || !isSamePlayingMessage(messageObject)) {
            return false;
        }
        stopProgressTimer();
        try {
            if (this.audioPlayer != null) {
                this.audioPlayer.pause();
            } else if (this.videoPlayer != null) {
                this.videoPlayer.pause();
            }
            this.isPaused = true;
            NotificationCenter.getInstance(this.playingMessageObject.currentAccount).postNotificationName(NotificationCenter.messagePlayingPlayStateChanged, Integer.valueOf(this.playingMessageObject.getId()));
            return true;
        } catch (Exception e) {
            FileLog.e(e);
            this.isPaused = false;
            return false;
        }
    }

    public boolean resumeAudio(MessageObject messageObject) {
        if ((this.audioPlayer == null && this.videoPlayer == null) || messageObject == null || this.playingMessageObject == null || !isSamePlayingMessage(messageObject)) {
            return false;
        }
        try {
            startProgressTimer(this.playingMessageObject);
            if (this.audioPlayer != null) {
                this.audioPlayer.play();
            } else if (this.videoPlayer != null) {
                this.videoPlayer.play();
            }
            checkAudioFocus(messageObject);
            this.isPaused = false;
            NotificationCenter.getInstance(this.playingMessageObject.currentAccount).postNotificationName(NotificationCenter.messagePlayingPlayStateChanged, Integer.valueOf(this.playingMessageObject.getId()));
            return true;
        } catch (Exception e) {
            FileLog.e(e);
            return false;
        }
    }

    public boolean isVideoDrawingReady() {
        AspectRatioFrameLayout aspectRatioFrameLayout = this.currentAspectRatioFrameLayout;
        return aspectRatioFrameLayout != null && aspectRatioFrameLayout.isDrawingReady();
    }

    public ArrayList<MessageObject> getPlaylist() {
        return this.playlist;
    }

    public boolean isPlayingMessage(MessageObject messageObject) {
        MessageObject messageObject2;
        if ((this.audioPlayer == null && this.videoPlayer == null) || messageObject == null || (messageObject2 = this.playingMessageObject) == null) {
            return false;
        }
        if (messageObject2.eventId != 0 && this.playingMessageObject.eventId == messageObject.eventId) {
            return !this.downloadingCurrentMessage;
        }
        if (isSamePlayingMessage(messageObject)) {
            return !this.downloadingCurrentMessage;
        }
        return false;
    }

    public boolean isPlayingMessageAndReadyToDraw(MessageObject messageObject) {
        return this.isDrawingWasReady && isPlayingMessage(messageObject);
    }

    public boolean isMessagePaused() {
        return this.isPaused || this.downloadingCurrentMessage;
    }

    public boolean isDownloadingCurrentMessage() {
        return this.downloadingCurrentMessage;
    }

    public void setReplyingMessage(MessageObject reply_to_msg) {
        this.recordReplyingMessageObject = reply_to_msg;
    }

    public void startRecording(final int currentAccount, final long dialog_id, final MessageObject reply_to_msg, final int guid) {
        boolean paused = false;
        MessageObject messageObject = this.playingMessageObject;
        if (messageObject != null && isPlayingMessage(messageObject) && !isMessagePaused()) {
            paused = true;
            lambda$startAudioAgain$5$MediaController(this.playingMessageObject);
        }
        try {
            this.feedbackView.performHapticFeedback(3, 2);
        } catch (Exception e) {
        }
        DispatchQueue dispatchQueue = this.recordQueue;
        Runnable runnable = new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaController$xbNIGTYu0WQjsTwhveFrOkgGWzA
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$startRecording$16$MediaController(currentAccount, guid, dialog_id, reply_to_msg);
            }
        };
        this.recordStartRunnable = runnable;
        dispatchQueue.postRunnable(runnable, paused ? 500L : 50L);
    }

    public /* synthetic */ void lambda$startRecording$16$MediaController(final int currentAccount, final int guid, long dialog_id, MessageObject reply_to_msg) {
        if (this.audioRecorder != null) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaController$KNL0kfW9ZXOD9mgH_w1cTM6pP7g
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$12$MediaController(currentAccount, guid);
                }
            });
            return;
        }
        this.sendAfterDone = 0;
        TLRPC.TL_document tL_document = new TLRPC.TL_document();
        this.recordingAudio = tL_document;
        this.recordingGuid = guid;
        tL_document.file_reference = new byte[0];
        this.recordingAudio.dc_id = Integer.MIN_VALUE;
        this.recordingAudio.id = SharedConfig.getLastLocalId();
        this.recordingAudio.user_id = UserConfig.getInstance(currentAccount).getClientUserId();
        this.recordingAudio.mime_type = "audio/ogg";
        this.recordingAudio.file_reference = new byte[0];
        SharedConfig.saveConfig();
        File file = new File(FileLoader.getDirectory(4), FileLoader.getAttachFileName(this.recordingAudio));
        this.recordingAudioFile = file;
        try {
            if (startRecord(file.getAbsolutePath()) == 0) {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaController$Yfj6PRJlCWehPXLeyLXZfBRb1vM
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$13$MediaController(currentAccount, guid);
                    }
                });
                return;
            }
            this.audioRecorder = new AudioRecord(0, AudioEditConstant.ExportSampleRate, 16, 2, this.recordBufferSize * 10);
            this.recordStartTime = System.currentTimeMillis();
            this.recordTimeCount = 0L;
            this.samplesCount = 0L;
            this.recordDialogId = dialog_id;
            this.recordingCurrentAccount = currentAccount;
            this.recordReplyingMessageObject = reply_to_msg;
            this.fileBuffer.rewind();
            this.audioRecorder.startRecording();
            this.recordQueue.postRunnable(this.recordRunnable);
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaController$rv76kB5xNbFv6svL8-RmzTHGE34
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$15$MediaController(currentAccount, guid);
                }
            });
        } catch (Exception e) {
            FileLog.e(e);
            this.recordingAudio = null;
            stopRecord();
            this.recordingAudioFile.delete();
            this.recordingAudioFile = null;
            try {
                this.audioRecorder.release();
                this.audioRecorder = null;
            } catch (Exception e2) {
                FileLog.e(e2);
            }
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaController$jm4VA4vLV7m1xsf6iJTCMCurBQY
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$14$MediaController(currentAccount, guid);
                }
            });
        }
    }

    public /* synthetic */ void lambda$null$12$MediaController(int currentAccount, int guid) {
        this.recordStartRunnable = null;
        NotificationCenter.getInstance(currentAccount).postNotificationName(NotificationCenter.recordStartError, Integer.valueOf(guid));
    }

    public /* synthetic */ void lambda$null$13$MediaController(int currentAccount, int guid) {
        this.recordStartRunnable = null;
        NotificationCenter.getInstance(currentAccount).postNotificationName(NotificationCenter.recordStartError, Integer.valueOf(guid));
    }

    public /* synthetic */ void lambda$null$14$MediaController(int currentAccount, int guid) {
        this.recordStartRunnable = null;
        NotificationCenter.getInstance(currentAccount).postNotificationName(NotificationCenter.recordStartError, Integer.valueOf(guid));
    }

    public /* synthetic */ void lambda$null$15$MediaController(int currentAccount, int guid) {
        this.recordStartRunnable = null;
        NotificationCenter.getInstance(currentAccount).postNotificationName(NotificationCenter.recordStarted, Integer.valueOf(guid));
    }

    public void generateWaveform(final MessageObject messageObject) {
        final String id = messageObject.getId() + "_" + messageObject.getDialogId();
        final String path = FileLoader.getPathToMessage(messageObject.messageOwner).getAbsolutePath();
        if (this.generatingWaveform.containsKey(id)) {
            return;
        }
        this.generatingWaveform.put(id, messageObject);
        Utilities.globalQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaController$f453J7U10c8TGwye3cKuy_8uyxA
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$generateWaveform$18$MediaController(path, id, messageObject);
            }
        });
    }

    public /* synthetic */ void lambda$generateWaveform$18$MediaController(String path, final String id, final MessageObject messageObject) {
        final byte[] waveform = getWaveform(path);
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaController$6_2p9Fep1zBzRp1eU3PCc4ZxBXI
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$17$MediaController(id, waveform, messageObject);
            }
        });
    }

    public /* synthetic */ void lambda$null$17$MediaController(String id, byte[] waveform, MessageObject messageObject) {
        MessageObject messageObject1 = this.generatingWaveform.remove(id);
        if (messageObject1 != null && waveform != null) {
            int a = 0;
            while (true) {
                if (a >= messageObject1.getDocument().attributes.size()) {
                    break;
                }
                TLRPC.DocumentAttribute attribute = messageObject1.getDocument().attributes.get(a);
                if (!(attribute instanceof TLRPC.TL_documentAttributeAudio)) {
                    a++;
                } else {
                    attribute.waveform = waveform;
                    attribute.flags |= 4;
                    break;
                }
            }
            TLRPC.TL_messages_messages messagesRes = new TLRPC.TL_messages_messages();
            messagesRes.messages.add(messageObject1.messageOwner);
            MessagesStorage.getInstance(messageObject1.currentAccount).putMessages((TLRPC.messages_Messages) messagesRes, messageObject1.getDialogId(), -1, 0, false, messageObject.scheduled);
            ArrayList<MessageObject> arrayList = new ArrayList<>();
            arrayList.add(messageObject1);
            NotificationCenter.getInstance(messageObject1.currentAccount).postNotificationName(NotificationCenter.replaceMessagesObjects, Long.valueOf(messageObject1.getDialogId()), arrayList);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void stopRecordingInternal(final int send, final boolean notify, final int scheduleDate) {
        if (send != 0) {
            final TLRPC.TL_document audioToSend = this.recordingAudio;
            final File recordingAudioFileToSend = this.recordingAudioFile;
            this.fileEncodingQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaController$SIWMrgJyfO6nCK6qCDL6PrvXK7U
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$stopRecordingInternal$20$MediaController(audioToSend, recordingAudioFileToSend, send, notify, scheduleDate);
                }
            });
        } else {
            File file = this.recordingAudioFile;
            if (file != null) {
                file.delete();
            }
        }
        try {
            if (this.audioRecorder != null) {
                this.audioRecorder.release();
                this.audioRecorder = null;
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
        this.recordingAudio = null;
        this.recordingAudioFile = null;
    }

    public /* synthetic */ void lambda$stopRecordingInternal$20$MediaController(final TLRPC.TL_document audioToSend, final File recordingAudioFileToSend, final int send, final boolean notify, final int scheduleDate) {
        stopRecord();
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaController$lqeS-o3VBnTpsCLcwW6KETv5K4M
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$19$MediaController(audioToSend, recordingAudioFileToSend, send, notify, scheduleDate);
            }
        });
    }

    public /* synthetic */ void lambda$null$19$MediaController(TLRPC.TL_document audioToSend, File recordingAudioFileToSend, int send, boolean notify, int scheduleDate) {
        char c;
        audioToSend.date = ConnectionsManager.getInstance(this.recordingCurrentAccount).getCurrentTime();
        audioToSend.size = (int) recordingAudioFileToSend.length();
        TLRPC.TL_documentAttributeAudio attributeAudio = new TLRPC.TL_documentAttributeAudio();
        attributeAudio.voice = true;
        short[] sArr = this.recordSamples;
        attributeAudio.waveform = getWaveform2(sArr, sArr.length);
        if (attributeAudio.waveform != null) {
            attributeAudio.flags |= 4;
        }
        long duration = this.recordTimeCount;
        attributeAudio.duration = (int) (this.recordTimeCount / 1000);
        audioToSend.attributes.add(attributeAudio);
        if (duration <= 700) {
            NotificationCenter.getInstance(this.recordingCurrentAccount).postNotificationName(NotificationCenter.audioRecordTooShort, Integer.valueOf(this.recordingGuid), false);
            recordingAudioFileToSend.delete();
            return;
        }
        if (send == 1) {
            c = 1;
            SendMessagesHelper.getInstance(this.recordingCurrentAccount).sendMessage(audioToSend, null, recordingAudioFileToSend.getAbsolutePath(), this.recordDialogId, this.recordReplyingMessageObject, null, null, null, null, notify, scheduleDate, 0, null);
        } else {
            c = 1;
        }
        NotificationCenter notificationCenter = NotificationCenter.getInstance(this.recordingCurrentAccount);
        int i = NotificationCenter.audioDidSent;
        Object[] objArr = new Object[3];
        objArr[0] = Integer.valueOf(this.recordingGuid);
        objArr[c] = send == 2 ? audioToSend : null;
        objArr[2] = send == 2 ? recordingAudioFileToSend.getAbsolutePath() : null;
        notificationCenter.postNotificationName(i, objArr);
    }

    public void stopRecording(final int send, final boolean notify, final int scheduleDate) {
        Runnable runnable = this.recordStartRunnable;
        if (runnable != null) {
            this.recordQueue.cancelRunnable(runnable);
            this.recordStartRunnable = null;
        }
        this.recordQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaController$a3PSc1j3U1pVAleYdm9LL-EdgnY
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$stopRecording$22$MediaController(send, notify, scheduleDate);
            }
        });
    }

    public /* synthetic */ void lambda$stopRecording$22$MediaController(final int send, boolean notify, int scheduleDate) {
        if (this.sendAfterDone == 3) {
            this.sendAfterDone = 0;
            stopRecordingInternal(send, notify, scheduleDate);
            return;
        }
        AudioRecord audioRecord = this.audioRecorder;
        if (audioRecord == null) {
            return;
        }
        try {
            this.sendAfterDone = send;
            this.sendAfterDoneNotify = notify;
            this.sendAfterDoneScheduleDate = scheduleDate;
            audioRecord.stop();
        } catch (Exception e) {
            FileLog.e(e);
            File file = this.recordingAudioFile;
            if (file != null) {
                file.delete();
            }
        }
        if (send == 0) {
            stopRecordingInternal(0, false, 0);
        }
        try {
            this.feedbackView.performHapticFeedback(3, 2);
        } catch (Exception e2) {
        }
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaController$AY-Qp2yd09DM8AwnoK4VNfoylx8
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$21$MediaController(send);
            }
        });
    }

    public /* synthetic */ void lambda$null$21$MediaController(int send) {
        NotificationCenter notificationCenter = NotificationCenter.getInstance(this.recordingCurrentAccount);
        int i = NotificationCenter.recordStopped;
        Object[] objArr = new Object[2];
        objArr[0] = Integer.valueOf(this.recordingGuid);
        objArr[1] = Integer.valueOf(send == 2 ? 1 : 0);
        notificationCenter.postNotificationName(i, objArr);
    }

    public static void saveFile(String fullPath, Context context, final int type, final String name, final String mime) {
        File file;
        AlertDialog progressDialog;
        if (fullPath == null) {
            return;
        }
        if (fullPath != null && fullPath.length() != 0) {
            File file2 = new File(fullPath);
            file = (!file2.exists() || AndroidUtilities.isInternalUri(Uri.fromFile(file2))) ? null : file2;
        } else {
            file = null;
        }
        if (file == null) {
            return;
        }
        final File sourceFile = file;
        final boolean[] cancelled = {false};
        if (sourceFile.exists()) {
            AlertDialog progressDialog2 = null;
            if (context != null && type != 0) {
                try {
                    progressDialog2 = new AlertDialog(context, 2);
                    progressDialog2.setMessage(LocaleController.getString("Loading", mpEIGo.juqQQs.esbSDO.R.string.Loading));
                    progressDialog2.setCanceledOnTouchOutside(false);
                    progressDialog2.setCancelable(true);
                    progressDialog2.setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaController$URzmxJK_YEhiNYIFphm9gGigM7o
                        @Override // android.content.DialogInterface.OnCancelListener
                        public final void onCancel(DialogInterface dialogInterface) {
                            MediaController.lambda$saveFile$23(cancelled, dialogInterface);
                        }
                    });
                    progressDialog2.show();
                    progressDialog = progressDialog2;
                } catch (Exception e) {
                    FileLog.e(e);
                    progressDialog = progressDialog2;
                }
            } else {
                progressDialog = null;
            }
            final AlertDialog finalProgress = progressDialog;
            new Thread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaController$CFti_6l1X8usGmDmdKxtUZlMBdI
                @Override // java.lang.Runnable
                public final void run() {
                    MediaController.lambda$saveFile$26(type, name, sourceFile, cancelled, finalProgress, mime);
                }
            }).start();
        }
    }

    static /* synthetic */ void lambda$saveFile$23(boolean[] cancelled, DialogInterface dialog) {
        cancelled[0] = true;
    }

    /* JADX WARN: Removed duplicated region for block: B:105:0x0193  */
    /* JADX WARN: Removed duplicated region for block: B:139:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:89:0x014d A[Catch: Exception -> 0x018b, TRY_LEAVE, TryCatch #3 {Exception -> 0x018b, blocks: (B:87:0x0148, B:89:0x014d, B:86:0x0144), top: B:112:0x0144 }] */
    /* JADX WARN: Removed duplicated region for block: B:92:0x0153  */
    /* JADX WARN: Removed duplicated region for block: B:99:0x0188  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    static /* synthetic */ void lambda$saveFile$26(int r22, java.lang.String r23, java.io.File r24, boolean[] r25, final im.uwrkaxlmjj.ui.actionbar.AlertDialog r26, java.lang.String r27) {
        /*
            Method dump skipped, instruction units count: 412
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MediaController.lambda$saveFile$26(int, java.lang.String, java.io.File, boolean[], im.uwrkaxlmjj.ui.actionbar.AlertDialog, java.lang.String):void");
    }

    static /* synthetic */ void lambda$null$24(AlertDialog finalProgress, int progress) {
        try {
            finalProgress.setProgress(progress);
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    static /* synthetic */ void lambda$null$25(AlertDialog finalProgress) {
        try {
            finalProgress.dismiss();
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public static boolean isWebp(Uri uri) {
        InputStream inputStream = null;
        try {
            try {
                try {
                    inputStream = ApplicationLoader.applicationContext.getContentResolver().openInputStream(uri);
                    byte[] header = new byte[12];
                    if (inputStream.read(header, 0, 12) == 12) {
                        String str = new String(header).toLowerCase();
                        if (str.startsWith("riff")) {
                            if (str.endsWith("webp")) {
                                return true;
                            }
                        }
                    }
                    if (inputStream != null) {
                        inputStream.close();
                    }
                } catch (Exception e) {
                    FileLog.e(e);
                    if (inputStream != null) {
                        inputStream.close();
                    }
                }
            } catch (Exception e2) {
                FileLog.e(e2);
            }
            return false;
        } finally {
            if (inputStream != null) {
                try {
                    inputStream.close();
                } catch (Exception e22) {
                    FileLog.e(e22);
                }
            }
        }
    }

    public static boolean isGif(Uri uri) {
        InputStream inputStream = null;
        try {
            try {
                try {
                    inputStream = ApplicationLoader.applicationContext.getContentResolver().openInputStream(uri);
                    byte[] header = new byte[3];
                    if (inputStream.read(header, 0, 3) == 3) {
                        String str = new String(header);
                        if (str.equalsIgnoreCase("gif")) {
                            return true;
                        }
                    }
                    if (inputStream != null) {
                        inputStream.close();
                    }
                } catch (Exception e) {
                    FileLog.e(e);
                    if (inputStream != null) {
                        inputStream.close();
                    }
                }
            } catch (Exception e2) {
                FileLog.e(e2);
            }
            return false;
        } finally {
            if (inputStream != null) {
                try {
                    inputStream.close();
                } catch (Exception e22) {
                    FileLog.e(e22);
                }
            }
        }
    }

    public static String getFileName(Uri uri) {
        if (uri.getScheme().equals("content")) {
            try {
                Cursor cursor = ApplicationLoader.applicationContext.getContentResolver().query(uri, new String[]{"_display_name"}, null, null, null);
                try {
                    result = cursor.moveToFirst() ? cursor.getString(cursor.getColumnIndex("_display_name")) : null;
                    if (cursor != null) {
                        cursor.close();
                    }
                } finally {
                }
            } catch (Exception e) {
                FileLog.e(e);
            }
        }
        if (result == null) {
            String result = uri.getPath();
            int cut = result.lastIndexOf(47);
            if (cut != -1) {
                return result.substring(cut + 1);
            }
            return result;
        }
        return result;
    }

    /* JADX WARN: Removed duplicated region for block: B:72:0x00cb A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:84:0x00bf A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:88:? A[DONT_GENERATE, FINALLY_INSNS, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.lang.String copyFileToCache(android.net.Uri r10, java.lang.String r11) {
        /*
            Method dump skipped, instruction units count: 214
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MediaController.copyFileToCache(android.net.Uri, java.lang.String):java.lang.String");
    }

    public static void loadGalleryPhotosAlbums(final int guid) {
        Thread thread = new Thread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaController$gM2wjPXYzFyXnOD6O3PdC9-kyTs
            @Override // java.lang.Runnable
            public final void run() {
                MediaController.lambda$loadGalleryPhotosAlbums$28(guid);
            }
        });
        thread.setPriority(1);
        thread.start();
    }

    /* JADX WARN: Removed duplicated region for block: B:132:0x02bd A[Catch: all -> 0x044e, TryCatch #20 {all -> 0x044e, blocks: (B:130:0x02b7, B:132:0x02bd, B:134:0x02c1, B:138:0x02ce, B:142:0x02e7), top: B:273:0x02b7 }] */
    /* JADX WARN: Removed duplicated region for block: B:138:0x02ce A[Catch: all -> 0x044e, TryCatch #20 {all -> 0x044e, blocks: (B:130:0x02b7, B:132:0x02bd, B:134:0x02c1, B:138:0x02ce, B:142:0x02e7), top: B:273:0x02b7 }] */
    /* JADX WARN: Removed duplicated region for block: B:140:0x02e2  */
    /* JADX WARN: Removed duplicated region for block: B:141:0x02e5  */
    /* JADX WARN: Removed duplicated region for block: B:197:0x043b  */
    /* JADX WARN: Removed duplicated region for block: B:214:0x046d A[LOOP:0: B:212:0x0467->B:214:0x046d, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:235:0x02ab A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:24:0x0088 A[Catch: all -> 0x029d, TRY_ENTER, TryCatch #27 {all -> 0x029d, blocks: (B:13:0x0064, B:24:0x0088, B:28:0x00a1), top: B:287:0x0064 }] */
    /* JADX WARN: Removed duplicated region for block: B:251:0x02ee A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:257:0x0456 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:265:0x0292 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:285:0x0443 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    static /* synthetic */ void lambda$loadGalleryPhotosAlbums$28(int r40) {
        /*
            Method dump skipped, instruction units count: 1206
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MediaController.lambda$loadGalleryPhotosAlbums$28(int):void");
    }

    static /* synthetic */ int lambda$null$27(PhotoEntry o1, PhotoEntry o2) {
        if (o1.dateTaken < o2.dateTaken) {
            return 1;
        }
        if (o1.dateTaken > o2.dateTaken) {
            return -1;
        }
        return 0;
    }

    private static void broadcastNewPhotos(final int guid, final ArrayList<AlbumEntry> mediaAlbumsSorted, final ArrayList<AlbumEntry> photoAlbumsSorted, final Integer cameraAlbumIdFinal, final AlbumEntry allMediaAlbumFinal, final AlbumEntry allPhotosAlbumFinal, final AlbumEntry allVideosAlbumFinal, int delay) {
        Runnable runnable = broadcastPhotosRunnable;
        if (runnable != null) {
            AndroidUtilities.cancelRunOnUIThread(runnable);
        }
        Runnable runnable2 = new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaController$hxhfwvjy4PoNCkzC-3GWB6pypMM
            @Override // java.lang.Runnable
            public final void run() {
                MediaController.lambda$broadcastNewPhotos$29(guid, mediaAlbumsSorted, photoAlbumsSorted, cameraAlbumIdFinal, allMediaAlbumFinal, allPhotosAlbumFinal, allVideosAlbumFinal);
            }
        };
        broadcastPhotosRunnable = runnable2;
        AndroidUtilities.runOnUIThread(runnable2, delay);
    }

    static /* synthetic */ void lambda$broadcastNewPhotos$29(int guid, ArrayList mediaAlbumsSorted, ArrayList photoAlbumsSorted, Integer cameraAlbumIdFinal, AlbumEntry allMediaAlbumFinal, AlbumEntry allPhotosAlbumFinal, AlbumEntry allVideosAlbumFinal) {
        if (PhotoViewer.getInstance().isVisible()) {
            broadcastNewPhotos(guid, mediaAlbumsSorted, photoAlbumsSorted, cameraAlbumIdFinal, allMediaAlbumFinal, allPhotosAlbumFinal, allVideosAlbumFinal, 1000);
            return;
        }
        allMediaAlbums = mediaAlbumsSorted;
        allPhotoAlbums = photoAlbumsSorted;
        broadcastPhotosRunnable = null;
        allPhotosAlbumEntry = allPhotosAlbumFinal;
        allMediaAlbumEntry = allMediaAlbumFinal;
        allVideosAlbumEntry = allVideosAlbumFinal;
        for (int a = 0; a < 3; a++) {
            NotificationCenter.getInstance(a).postNotificationName(NotificationCenter.albumsDidLoad, Integer.valueOf(guid), mediaAlbumsSorted, photoAlbumsSorted, cameraAlbumIdFinal);
        }
    }

    public void scheduleVideoConvert(MessageObject messageObject) {
        scheduleVideoConvert(messageObject, false);
    }

    public boolean scheduleVideoConvert(MessageObject messageObject, boolean isEmpty) {
        if (messageObject == null || messageObject.videoEditedInfo == null) {
            return false;
        }
        if (isEmpty && !this.videoConvertQueue.isEmpty()) {
            return false;
        }
        if (isEmpty) {
            new File(messageObject.messageOwner.attachPath).delete();
        }
        this.videoConvertQueue.add(messageObject);
        if (this.videoConvertQueue.size() == 1) {
            startVideoConvertFromQueue();
        }
        return true;
    }

    public void cancelVideoConvert(MessageObject messageObject) {
        if (messageObject == null) {
            synchronized (this.videoConvertSync) {
                this.cancelCurrentVideoConversion = true;
            }
            return;
        }
        if (!this.videoConvertQueue.isEmpty()) {
            for (int a = 0; a < this.videoConvertQueue.size(); a++) {
                MessageObject object = this.videoConvertQueue.get(a);
                if (object.getId() == messageObject.getId() && object.currentAccount == messageObject.currentAccount) {
                    if (a == 0) {
                        synchronized (this.videoConvertSync) {
                            this.cancelCurrentVideoConversion = true;
                        }
                        return;
                    }
                    this.videoConvertQueue.remove(a);
                    return;
                }
            }
        }
    }

    private boolean startVideoConvertFromQueue() {
        if (this.videoConvertQueue.isEmpty()) {
            return false;
        }
        synchronized (this.videoConvertSync) {
            this.cancelCurrentVideoConversion = false;
        }
        MessageObject messageObject = this.videoConvertQueue.get(0);
        Intent intent = new Intent(ApplicationLoader.applicationContext, (Class<?>) VideoEncodingService.class);
        intent.putExtra("path", messageObject.messageOwner.attachPath);
        intent.putExtra("currentAccount", messageObject.currentAccount);
        if (messageObject.messageOwner.media.document != null) {
            int a = 0;
            while (true) {
                if (a >= messageObject.messageOwner.media.document.attributes.size()) {
                    break;
                }
                TLRPC.DocumentAttribute documentAttribute = messageObject.messageOwner.media.document.attributes.get(a);
                if (!(documentAttribute instanceof TLRPC.TL_documentAttributeAnimated)) {
                    a++;
                } else {
                    intent.putExtra("gif", true);
                    break;
                }
            }
        }
        int a2 = messageObject.getId();
        if (a2 != 0) {
            try {
                ApplicationLoader.applicationContext.startService(intent);
            } catch (Throwable e) {
                FileLog.e(e);
            }
        }
        VideoConvertRunnable.runConversion(messageObject);
        return true;
    }

    public static MediaCodecInfo selectCodec(String mimeType) {
        String name;
        int numCodecs = MediaCodecList.getCodecCount();
        MediaCodecInfo lastCodecInfo = null;
        for (int i = 0; i < numCodecs; i++) {
            MediaCodecInfo codecInfo = MediaCodecList.getCodecInfoAt(i);
            if (codecInfo.isEncoder()) {
                String[] types = codecInfo.getSupportedTypes();
                for (String type : types) {
                    if (type.equalsIgnoreCase(mimeType) && (name = (lastCodecInfo = codecInfo).getName()) != null) {
                        if (!name.equals("OMX.SEC.avc.enc")) {
                            return lastCodecInfo;
                        }
                        if (name.equals("OMX.SEC.AVC.Encoder")) {
                            return lastCodecInfo;
                        }
                    }
                }
            }
        }
        return lastCodecInfo;
    }

    private static boolean isRecognizedFormat(int colorFormat) {
        if (colorFormat == 39 || colorFormat == 2130706688) {
            return true;
        }
        switch (colorFormat) {
            case 19:
            case 20:
            case 21:
                return true;
            default:
                return false;
        }
    }

    public static int selectColorFormat(MediaCodecInfo codecInfo, String mimeType) {
        MediaCodecInfo.CodecCapabilities capabilities = codecInfo.getCapabilitiesForType(mimeType);
        int lastColorFormat = 0;
        for (int i = 0; i < capabilities.colorFormats.length; i++) {
            int colorFormat = capabilities.colorFormats[i];
            if (isRecognizedFormat(colorFormat)) {
                lastColorFormat = colorFormat;
                if (!codecInfo.getName().equals("OMX.SEC.AVC.Encoder") || colorFormat != 19) {
                    return colorFormat;
                }
            }
        }
        return lastColorFormat;
    }

    private int findTrack(MediaExtractor extractor, boolean audio) {
        int numTracks = extractor.getTrackCount();
        for (int i = 0; i < numTracks; i++) {
            MediaFormat format = extractor.getTrackFormat(i);
            String mime = format.getString("mime");
            if (audio) {
                if (mime.startsWith("audio/")) {
                    return i;
                }
            } else if (mime.startsWith("video/")) {
                return i;
            }
        }
        return -5;
    }

    private void didWriteData(final MessageObject messageObject, final File file, final boolean last, final long availableSize, final boolean error) {
        final boolean firstWrite = this.videoConvertFirstWrite;
        if (firstWrite) {
            this.videoConvertFirstWrite = false;
        }
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaController$CQnFDW0zZ601ZMEGZrIwBaI0VPs
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$didWriteData$30$MediaController(error, last, messageObject, file, firstWrite, availableSize);
            }
        });
    }

    public /* synthetic */ void lambda$didWriteData$30$MediaController(boolean error, boolean last, MessageObject messageObject, File file, boolean firstWrite, long availableSize) {
        if (error || last) {
            synchronized (this.videoConvertSync) {
                this.cancelCurrentVideoConversion = false;
            }
            this.videoConvertQueue.remove(messageObject);
            startVideoConvertFromQueue();
        }
        if (error) {
            NotificationCenter.getInstance(messageObject.currentAccount).postNotificationName(NotificationCenter.filePreparingFailed, messageObject, file.toString());
            return;
        }
        if (firstWrite) {
            NotificationCenter.getInstance(messageObject.currentAccount).postNotificationName(NotificationCenter.filePreparingStarted, messageObject, file.toString());
        }
        NotificationCenter notificationCenter = NotificationCenter.getInstance(messageObject.currentAccount);
        int i = NotificationCenter.fileNewChunkAvailable;
        Object[] objArr = new Object[4];
        objArr[0] = messageObject;
        objArr[1] = file.toString();
        objArr[2] = Long.valueOf(availableSize);
        objArr[3] = Long.valueOf(last ? file.length() : 0L);
        notificationCenter.postNotificationName(i, objArr);
    }

    /* JADX WARN: Removed duplicated region for block: B:57:0x00f3 A[PHI: r29
      0x00f3: PHI (r29v10 'muxerVideoTrackIndex' int) = (r29v8 'muxerVideoTrackIndex' int), (r29v11 'muxerVideoTrackIndex' int) binds: [B:56:0x00f1, B:52:0x00e9] A[DONT_GENERATE, DONT_INLINE]] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private long readAndWriteTracks(im.uwrkaxlmjj.messenger.MessageObject r35, android.media.MediaExtractor r36, im.uwrkaxlmjj.messenger.video.MP4Builder r37, android.media.MediaCodec.BufferInfo r38, long r39, long r41, java.io.File r43, boolean r44) throws java.lang.Exception {
        /*
            Method dump skipped, instruction units count: 527
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MediaController.readAndWriteTracks(im.uwrkaxlmjj.messenger.MessageObject, android.media.MediaExtractor, im.uwrkaxlmjj.messenger.video.MP4Builder, android.media.MediaCodec$BufferInfo, long, long, java.io.File, boolean):long");
    }

    /* JADX INFO: Access modifiers changed from: private */
    static class VideoConvertRunnable implements Runnable {
        private MessageObject messageObject;

        private VideoConvertRunnable(MessageObject message) {
            this.messageObject = message;
        }

        @Override // java.lang.Runnable
        public void run() throws Throwable {
            MediaController.getInstance().convertVideo(this.messageObject);
        }

        public static void runConversion(final MessageObject obj) {
            new Thread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaController$VideoConvertRunnable$6NJ_dHF4WVU-1gWLtBTaqQc5cUg
                @Override // java.lang.Runnable
                public final void run() {
                    MediaController.VideoConvertRunnable.lambda$runConversion$0(obj);
                }
            }).start();
        }

        static /* synthetic */ void lambda$runConversion$0(MessageObject obj) {
            try {
                VideoConvertRunnable wrapper = new VideoConvertRunnable(obj);
                Thread th = new Thread(wrapper, "VideoConvertRunnable");
                th.start();
                th.join();
            } catch (Exception e) {
                FileLog.e(e);
            }
        }
    }

    private void checkConversionCanceled() {
        synchronized (this.videoConvertSync) {
            boolean z = this.cancelCurrentVideoConversion;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Can't wrap try/catch for region: R(19:47|774|48|49|(11:800|50|51|772|52|759|53|54|788|55|56)|(1:87)(2:59|(4:61|768|62|(3:64|65|(12:70|(1:72)(1:73)|74|794|75|76|626|(2:738|628)|632|(1:634)|671|672)(1:69))(1:81))(1:86))|88|780|89|90|(4:92|695|93|94)(1:99)|100|(16:102|719|103|104|701|105|106|(3:692|108|(5:110|(2:112|(2:114|(1:118))(1:119))(2:120|(1:122)(2:123|(1:125)(2:126|(1:128)(2:129|(1:131)))))|132|(1:134)(1:135)|136)(2:137|138))(1:141)|758|142|(1:144)|145|796|146|763|(38:148|(1:150)(1:169)|170|171|(2:173|174)(1:175)|176|(4:178|765|179|180)(3:185|721|186)|187|(1:189)(1:190)|191|(1:193)(1:194)|195|196|(2:732|198)|204|205|753|206|207|(5:699|209|749|210|211)(1:216)|729|217|218|734|219|220|(23:727|222|223|229|747|230|231|757|232|233|(3:715|235|(2:237|238)(1:239))(1:242)|243|(4:245|(5:247|782|248|249|(6:251|705|252|(4:254|(1:256)(1:257)|258|(1:260)(1:261))|262|(4:318|703|319|(2:321|322))(1:327))(3:267|(2:314|(1:316))(13:270|693|271|272|755|273|274|(2:711|276)|280|(2:282|283)(2:284|285)|286|(2:288|(4:295|296|297|(3:299|741|300)(1:304))(1:294))(1:306)|307)|(0)(0)))(1:332)|333|(1:(7:792|338|339|(1:341)(1:(2:343|(1:345)(1:346))(2:347|(3:349|(2:351|352)(1:353)|354)(1:(3:356|(1:358)(1:360)|(9:362|363|(4:786|365|366|(5:798|368|369|(3:371|761|372)(1:378)|379)(2:384|(15:776|386|387|(1:(1:813)(2:391|(2:818|401)(2:814|399)))|402|743|403|(1:407)(1:406)|408|409|723|423|(1:425)(1:426)|427|428)(1:416)))(1:421)|422|723|423|(0)(0)|427|428)(3:804|559|560))(3:803|561|562))))|429|(3:808|431|811)(4:806|(5:433|717|434|435|(1:437)(2:438|(1:440)(2:441|(4:709|443|(1:445)(1:447)|448)(2:453|(16:455|456|(3:458|(1:460)(1:461)|462)(3:463|(3:465|466|(1:468)(1:469))(1:470)|471)|472|(11:474|(2:476|477)|480|(1:501)(4:484|784|485|(2:487|(4:489|490|707|491)(1:492))(8:493|494|503|736|504|(4:506|745|507|(3:515|516|(6:518|697|519|520|767|521)(2:524|(1:526)(2:527|(1:529))))(1:530))(1:531)|532|(5:534|(1:536)|537|(1:539)(2:540|(1:542))|543)(1:544)))|502|503|736|504|(0)(0)|532|(0)(0))(1:478)|479|480|(1:482)|501|502|503|736|504|(0)(0)|532|(0)(0))(3:805|549|550)))))(1:555)|556|810)|809)))|802|571|604|778|605|(1:607)|(1:609)|(1:611)|(1:613)|614)(24:226|227|790|228|229|747|230|231|757|232|233|(0)(0)|243|(0)|802|571|604|778|605|(0)|(0)|(0)|(0)|614)|770|602|603|604|778|605|(0)|(0)|(0)|(0)|614)(2:155|(38:157|(1:159)(0)|170|171|(0)(0)|176|(0)(0)|187|(0)(0)|191|(0)(0)|195|196|(0)|204|205|753|206|207|(0)(0)|729|217|218|734|219|220|(0)(0)|770|602|603|604|778|605|(0)|(0)|(0)|(0)|614)(38:160|(2:167|168)(0)|170|171|(0)(0)|176|(0)(0)|187|(0)(0)|191|(0)(0)|195|196|(0)|204|205|753|206|207|(0)(0)|729|217|218|734|219|220|(0)(0)|770|602|603|604|778|605|(0)|(0)|(0)|(0)|614)))(1:624)|626|(0)|632|(0)|671|672) */
    /* JADX WARN: Can't wrap try/catch for region: R(31:148|(1:150)(1:169)|170|171|(2:173|174)(1:175)|176|(4:178|765|179|180)(3:185|721|186)|187|(1:189)(1:190)|191|(1:193)(1:194)|195|196|(2:732|198)|204|205|753|206|207|(5:699|209|749|210|211)(1:216)|729|217|218|734|219|220|(8:(23:727|222|223|229|747|230|231|757|232|233|(3:715|235|(2:237|238)(1:239))(1:242)|243|(4:245|(5:247|782|248|249|(6:251|705|252|(4:254|(1:256)(1:257)|258|(1:260)(1:261))|262|(4:318|703|319|(2:321|322))(1:327))(3:267|(2:314|(1:316))(13:270|693|271|272|755|273|274|(2:711|276)|280|(2:282|283)(2:284|285)|286|(2:288|(4:295|296|297|(3:299|741|300)(1:304))(1:294))(1:306)|307)|(0)(0)))(1:332)|333|(1:(7:792|338|339|(1:341)(1:(2:343|(1:345)(1:346))(2:347|(3:349|(2:351|352)(1:353)|354)(1:(3:356|(1:358)(1:360)|(9:362|363|(4:786|365|366|(5:798|368|369|(3:371|761|372)(1:378)|379)(2:384|(15:776|386|387|(1:(1:813)(2:391|(2:818|401)(2:814|399)))|402|743|403|(1:407)(1:406)|408|409|723|423|(1:425)(1:426)|427|428)(1:416)))(1:421)|422|723|423|(0)(0)|427|428)(3:804|559|560))(3:803|561|562))))|429|(3:808|431|811)(4:806|(5:433|717|434|435|(1:437)(2:438|(1:440)(2:441|(4:709|443|(1:445)(1:447)|448)(2:453|(16:455|456|(3:458|(1:460)(1:461)|462)(3:463|(3:465|466|(1:468)(1:469))(1:470)|471)|472|(11:474|(2:476|477)|480|(1:501)(4:484|784|485|(2:487|(4:489|490|707|491)(1:492))(8:493|494|503|736|504|(4:506|745|507|(3:515|516|(6:518|697|519|520|767|521)(2:524|(1:526)(2:527|(1:529))))(1:530))(1:531)|532|(5:534|(1:536)|537|(1:539)(2:540|(1:542))|543)(1:544)))|502|503|736|504|(0)(0)|532|(0)(0))(1:478)|479|480|(1:482)|501|502|503|736|504|(0)(0)|532|(0)(0))(3:805|549|550)))))(1:555)|556|810)|809)))|802|571|604|778|605|(1:607)|(1:609)|(1:611)|(1:613)|614)(24:226|227|790|228|229|747|230|231|757|232|233|(0)(0)|243|(0)|802|571|604|778|605|(0)|(0)|(0)|(0)|614)|778|605|(0)|(0)|(0)|(0)|614)|770|602|603|604) */
    /* JADX WARN: Code restructure failed: missing block: B:337:0x09ee, code lost:
    
        r29 = r6;
        r50 = r8;
        r2 = r24;
        r24 = r26;
        r25 = r27;
        r27 = r28;
        r30 = r36;
        r60 = r48;
        r36 = r65;
        r8 = r66;
        r1 = r79;
        r61 = r80;
        r59 = r81;
        r3 = r82;
        r58 = r84;
        r28 = r88;
        r13 = r89;
        r6 = r5;
        r66 = r11;
        r65 = r47;
        r11 = r78;
        r94 = r34;
        r34 = r9;
        r9 = r94;
     */
    /* JADX WARN: Code restructure failed: missing block: B:620:0x116a, code lost:
    
        r0 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:621:0x116b, code lost:
    
        r4 = r0;
        r2 = r85;
        r1 = r15;
        r3 = r45;
     */
    /* JADX WARN: Code restructure failed: missing block: B:622:0x1176, code lost:
    
        r0 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:623:0x1177, code lost:
    
        r4 = r0;
        r2 = r85;
        r1 = r15;
        r3 = r45;
     */
    /* JADX WARN: Code restructure failed: missing block: B:635:0x11bf, code lost:
    
        r0 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:636:0x11c0, code lost:
    
        r3 = r45;
        r4 = r0;
        r2 = r10;
        r1 = r15;
     */
    /* JADX WARN: Code restructure failed: missing block: B:637:0x11d4, code lost:
    
        r0 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:638:0x11d5, code lost:
    
        r49 = r12;
        r3 = r45;
        r91 = r47;
        r4 = r0;
        r2 = r10;
        r1 = r15;
     */
    /* JADX WARN: Removed duplicated region for block: B:169:0x04cc  */
    /* JADX WARN: Removed duplicated region for block: B:173:0x04dc A[Catch: all -> 0x045f, Exception -> 0x046e, TRY_ENTER, TRY_LEAVE, TryCatch #87 {Exception -> 0x046e, all -> 0x045f, blocks: (B:148:0x0443, B:150:0x0447, B:173:0x04dc, B:157:0x048a, B:159:0x0494, B:165:0x04ad, B:167:0x04b5), top: B:763:0x0441 }] */
    /* JADX WARN: Removed duplicated region for block: B:175:0x0505  */
    /* JADX WARN: Removed duplicated region for block: B:178:0x051d  */
    /* JADX WARN: Removed duplicated region for block: B:185:0x054d  */
    /* JADX WARN: Removed duplicated region for block: B:189:0x0563  */
    /* JADX WARN: Removed duplicated region for block: B:190:0x0565  */
    /* JADX WARN: Removed duplicated region for block: B:193:0x056f  */
    /* JADX WARN: Removed duplicated region for block: B:194:0x0572  */
    /* JADX WARN: Removed duplicated region for block: B:216:0x060b  */
    /* JADX WARN: Removed duplicated region for block: B:226:0x0644 A[Catch: Exception -> 0x101d, all -> 0x106b, TRY_ENTER, TRY_LEAVE, TryCatch #54 {all -> 0x106b, blocks: (B:187:0x0555, B:191:0x0568, B:195:0x0574, B:204:0x05ba, B:206:0x05c1, B:217:0x060d, B:219:0x061c, B:230:0x064d, B:232:0x0657, B:243:0x06a8, B:245:0x06b3, B:226:0x0644, B:186:0x0552), top: B:721:0x0552 }] */
    /* JADX WARN: Removed duplicated region for block: B:242:0x06a3  */
    /* JADX WARN: Removed duplicated region for block: B:245:0x06b3 A[Catch: Exception -> 0x0fbc, all -> 0x106b, TRY_LEAVE, TryCatch #54 {all -> 0x106b, blocks: (B:187:0x0555, B:191:0x0568, B:195:0x0574, B:204:0x05ba, B:206:0x05c1, B:217:0x060d, B:219:0x061c, B:230:0x064d, B:232:0x0657, B:243:0x06a8, B:245:0x06b3, B:226:0x0644, B:186:0x0552), top: B:721:0x0552 }] */
    /* JADX WARN: Removed duplicated region for block: B:318:0x0940  */
    /* JADX WARN: Removed duplicated region for block: B:327:0x0977  */
    /* JADX WARN: Removed duplicated region for block: B:32:0x00b1  */
    /* JADX WARN: Removed duplicated region for block: B:425:0x0c30  */
    /* JADX WARN: Removed duplicated region for block: B:426:0x0c32  */
    /* JADX WARN: Removed duplicated region for block: B:506:0x0dba  */
    /* JADX WARN: Removed duplicated region for block: B:531:0x0e47  */
    /* JADX WARN: Removed duplicated region for block: B:534:0x0e53 A[Catch: all -> 0x0f5f, Exception -> 0x0f6a, TryCatch #85 {Exception -> 0x0f6a, all -> 0x0f5f, blocks: (B:521:0x0de4, B:532:0x0e4d, B:534:0x0e53, B:536:0x0e58, B:537:0x0e5d, B:539:0x0e63, B:540:0x0e68, B:542:0x0e71, B:524:0x0dfc, B:526:0x0e08, B:527:0x0e34, B:529:0x0e38, B:549:0x0ea7, B:550:0x0ec6, B:559:0x0f14, B:560:0x0f3b, B:561:0x0f3c, B:562:0x0f5e), top: B:767:0x0de4 }] */
    /* JADX WARN: Removed duplicated region for block: B:544:0x0e8a  */
    /* JADX WARN: Removed duplicated region for block: B:607:0x113c A[Catch: all -> 0x1158, Exception -> 0x1162, TryCatch #79 {Exception -> 0x1162, all -> 0x1158, blocks: (B:605:0x1137, B:607:0x113c, B:609:0x1141, B:611:0x1146, B:613:0x114e, B:614:0x1154), top: B:778:0x1137 }] */
    /* JADX WARN: Removed duplicated region for block: B:609:0x1141 A[Catch: all -> 0x1158, Exception -> 0x1162, TryCatch #79 {Exception -> 0x1162, all -> 0x1158, blocks: (B:605:0x1137, B:607:0x113c, B:609:0x1141, B:611:0x1146, B:613:0x114e, B:614:0x1154), top: B:778:0x1137 }] */
    /* JADX WARN: Removed duplicated region for block: B:611:0x1146 A[Catch: all -> 0x1158, Exception -> 0x1162, TryCatch #79 {Exception -> 0x1162, all -> 0x1158, blocks: (B:605:0x1137, B:607:0x113c, B:609:0x1141, B:611:0x1146, B:613:0x114e, B:614:0x1154), top: B:778:0x1137 }] */
    /* JADX WARN: Removed duplicated region for block: B:613:0x114e A[Catch: all -> 0x1158, Exception -> 0x1162, TryCatch #79 {Exception -> 0x1162, all -> 0x1158, blocks: (B:605:0x1137, B:607:0x113c, B:609:0x1141, B:611:0x1146, B:613:0x114e, B:614:0x1154), top: B:778:0x1137 }] */
    /* JADX WARN: Removed duplicated region for block: B:634:0x11a3  */
    /* JADX WARN: Removed duplicated region for block: B:662:0x12f9  */
    /* JADX WARN: Removed duplicated region for block: B:670:0x130b  */
    /* JADX WARN: Removed duplicated region for block: B:676:0x134a  */
    /* JADX WARN: Removed duplicated region for block: B:684:0x135c  */
    /* JADX WARN: Removed duplicated region for block: B:699:0x05ca A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:715:0x066c A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:725:0x12fe A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:727:0x0624 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:732:0x0583 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:738:0x1196 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:751:0x134f A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:819:? A[SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean convertVideo(im.uwrkaxlmjj.messenger.MessageObject r97) throws java.lang.Throwable {
        /*
            Method dump skipped, instruction units count: 5050
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MediaController.convertVideo(im.uwrkaxlmjj.messenger.MessageObject):boolean");
    }
}
