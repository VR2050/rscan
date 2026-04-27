package im.uwrkaxlmjj.messenger;

import android.content.SharedPreferences;
import android.util.LongSparseArray;
import android.util.SparseArray;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.SendMessagesHelper;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/* JADX INFO: loaded from: classes2.dex */
public class DownloadController extends BaseController implements NotificationCenter.NotificationCenterDelegate {
    public static final int AUTODOWNLOAD_TYPE_AUDIO = 2;
    public static final int AUTODOWNLOAD_TYPE_DOCUMENT = 8;
    public static final int AUTODOWNLOAD_TYPE_PHOTO = 1;
    public static final int AUTODOWNLOAD_TYPE_VIDEO = 4;
    private static volatile DownloadController[] Instance = new DownloadController[3];
    public static final int PRESET_NUM_CHANNEL = 3;
    public static final int PRESET_NUM_CONTACT = 0;
    public static final int PRESET_NUM_GROUP = 2;
    public static final int PRESET_NUM_PM = 1;
    public static final int PRESET_SIZE_NUM_AUDIO = 3;
    public static final int PRESET_SIZE_NUM_DOCUMENT = 2;
    public static final int PRESET_SIZE_NUM_PHOTO = 0;
    public static final int PRESET_SIZE_NUM_VIDEO = 1;
    private HashMap<String, FileDownloadProgressListener> addLaterArray;
    private ArrayList<DownloadObject> audioDownloadQueue;
    public int currentMobilePreset;
    public int currentRoamingPreset;
    public int currentWifiPreset;
    private ArrayList<FileDownloadProgressListener> deleteLaterArray;
    private ArrayList<DownloadObject> documentDownloadQueue;
    private HashMap<String, DownloadObject> downloadQueueKeys;
    public Preset highPreset;
    private int lastCheckMask;
    private int lastTag;
    private boolean listenerInProgress;
    private boolean loadingAutoDownloadConfig;
    private HashMap<String, ArrayList<MessageObject>> loadingFileMessagesObservers;
    private HashMap<String, ArrayList<WeakReference<FileDownloadProgressListener>>> loadingFileObservers;
    public Preset lowPreset;
    public Preset mediumPreset;
    public Preset mobilePreset;
    private SparseArray<String> observersByTag;
    private ArrayList<DownloadObject> photoDownloadQueue;
    public Preset roamingPreset;
    private LongSparseArray<Long> typingTimes;
    private ArrayList<DownloadObject> videoDownloadQueue;
    public Preset wifiPreset;

    public interface FileDownloadProgressListener {
        int getObserverTag();

        void onFailedDownload(String str, boolean z);

        void onProgressDownload(String str, float f);

        void onProgressUpload(String str, float f, boolean z);

        void onSuccessDownload(String str);
    }

    public static class Preset {
        public boolean enabled;
        public boolean lessCallData;
        public int[] mask;
        public boolean preloadMusic;
        public boolean preloadVideo;
        public int[] sizes;

        public Preset(int[] m, int p, int v, int f, boolean pv, boolean pm, boolean e, boolean l) {
            int[] iArr = new int[4];
            this.mask = iArr;
            this.sizes = new int[4];
            System.arraycopy(m, 0, iArr, 0, iArr.length);
            int[] iArr2 = this.sizes;
            iArr2[0] = p;
            iArr2[1] = v;
            iArr2[2] = f;
            iArr2[3] = 524288;
            this.preloadVideo = pv;
            this.preloadMusic = pm;
            this.lessCallData = l;
            this.enabled = e;
        }

        public Preset(String str) {
            this.mask = new int[4];
            this.sizes = new int[4];
            String[] args = str.split("_");
            if (args.length >= 11) {
                this.mask[0] = Utilities.parseInt(args[0]).intValue();
                this.mask[1] = Utilities.parseInt(args[1]).intValue();
                this.mask[2] = Utilities.parseInt(args[2]).intValue();
                this.mask[3] = Utilities.parseInt(args[3]).intValue();
                this.sizes[0] = Utilities.parseInt(args[4]).intValue();
                this.sizes[1] = Utilities.parseInt(args[5]).intValue();
                this.sizes[2] = Utilities.parseInt(args[6]).intValue();
                this.sizes[3] = Utilities.parseInt(args[7]).intValue();
                this.preloadVideo = Utilities.parseInt(args[8]).intValue() == 1;
                this.preloadMusic = Utilities.parseInt(args[9]).intValue() == 1;
                this.enabled = Utilities.parseInt(args[10]).intValue() == 1;
                if (args.length >= 12) {
                    this.lessCallData = Utilities.parseInt(args[11]).intValue() == 1;
                }
            }
        }

        public void set(Preset preset) {
            int[] iArr = preset.mask;
            int[] iArr2 = this.mask;
            System.arraycopy(iArr, 0, iArr2, 0, iArr2.length);
            int[] iArr3 = preset.sizes;
            int[] iArr4 = this.sizes;
            System.arraycopy(iArr3, 0, iArr4, 0, iArr4.length);
            this.preloadVideo = preset.preloadVideo;
            this.preloadMusic = preset.preloadMusic;
            this.lessCallData = preset.lessCallData;
        }

        public void set(TLRPC.TL_autoDownloadSettings settings) {
            this.preloadMusic = settings.audio_preload_next;
            this.preloadVideo = settings.video_preload_large;
            this.lessCallData = settings.phonecalls_less_data;
            this.sizes[0] = Math.max(512000, settings.photo_size_max);
            this.sizes[1] = Math.max(512000, settings.video_size_max);
            this.sizes[2] = Math.max(512000, settings.file_size_max);
            for (int a = 0; a < this.mask.length; a++) {
                if (settings.photo_size_max != 0 && !settings.disabled) {
                    int[] iArr = this.mask;
                    iArr[a] = iArr[a] | 1;
                } else {
                    int[] iArr2 = this.mask;
                    iArr2[a] = iArr2[a] & (-2);
                }
                if (settings.video_size_max != 0 && !settings.disabled) {
                    int[] iArr3 = this.mask;
                    iArr3[a] = iArr3[a] | 4;
                } else {
                    int[] iArr4 = this.mask;
                    iArr4[a] = iArr4[a] & (-5);
                }
                if (settings.file_size_max != 0 && !settings.disabled) {
                    int[] iArr5 = this.mask;
                    iArr5[a] = iArr5[a] | 8;
                } else {
                    int[] iArr6 = this.mask;
                    iArr6[a] = iArr6[a] & (-9);
                }
            }
        }

        public String toString() {
            return this.mask[0] + "_" + this.mask[1] + "_" + this.mask[2] + "_" + this.mask[3] + "_" + this.sizes[0] + "_" + this.sizes[1] + "_" + this.sizes[2] + "_" + this.sizes[3] + "_" + (this.preloadVideo ? 1 : 0) + "_" + (this.preloadMusic ? 1 : 0) + "_" + (this.enabled ? 1 : 0) + "_" + (this.lessCallData ? 1 : 0);
        }

        public boolean equals(Preset obj) {
            int[] iArr = this.mask;
            int i = iArr[0];
            int[] iArr2 = obj.mask;
            if (i != iArr2[0] || iArr[1] != iArr2[1] || iArr[2] != iArr2[2] || iArr[3] != iArr2[3]) {
                return false;
            }
            int[] iArr3 = this.sizes;
            int i2 = iArr3[0];
            int[] iArr4 = obj.sizes;
            return i2 == iArr4[0] && iArr3[1] == iArr4[1] && iArr3[2] == iArr4[2] && iArr3[3] == iArr4[3] && this.preloadVideo == obj.preloadVideo && this.preloadMusic == obj.preloadMusic;
        }

        public boolean isEnabled() {
            int a = 0;
            while (true) {
                int[] iArr = this.mask;
                if (a < iArr.length) {
                    if (iArr[a] == 0) {
                        a++;
                    } else {
                        return true;
                    }
                } else {
                    return false;
                }
            }
        }
    }

    public static DownloadController getInstance(int num) {
        DownloadController localInstance = Instance[num];
        if (localInstance == null) {
            synchronized (DownloadController.class) {
                localInstance = Instance[num];
                if (localInstance == null) {
                    DownloadController[] downloadControllerArr = Instance;
                    DownloadController downloadController = new DownloadController(num);
                    localInstance = downloadController;
                    downloadControllerArr[num] = downloadController;
                }
            }
        }
        return localInstance;
    }

    /* JADX WARN: Removed duplicated region for block: B:37:0x02d4  */
    /* JADX WARN: Removed duplicated region for block: B:42:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public DownloadController(int r31) {
        /*
            Method dump skipped, instruction units count: 728
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.DownloadController.<init>(int):void");
    }

    public /* synthetic */ void lambda$new$0$DownloadController() {
        getNotificationCenter().addObserver(this, NotificationCenter.fileDidFailToLoad);
        getNotificationCenter().addObserver(this, NotificationCenter.fileDidLoad);
        getNotificationCenter().addObserver(this, NotificationCenter.FileLoadProgressChanged);
        getNotificationCenter().addObserver(this, NotificationCenter.FileUploadProgressChanged);
        getNotificationCenter().addObserver(this, NotificationCenter.httpFileDidLoad);
        getNotificationCenter().addObserver(this, NotificationCenter.httpFileDidFailedLoad);
        loadAutoDownloadConfig(false);
    }

    public void loadAutoDownloadConfig(boolean force) {
        if (this.loadingAutoDownloadConfig) {
            return;
        }
        if (!force && Math.abs(System.currentTimeMillis() - getUserConfig().autoDownloadConfigLoadTime) < 86400000) {
            return;
        }
        this.loadingAutoDownloadConfig = true;
        TLRPC.TL_account_getAutoDownloadSettings req = new TLRPC.TL_account_getAutoDownloadSettings();
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$DownloadController$LitDM4A-JuOgTr9eX9cv10GTvRM
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$loadAutoDownloadConfig$2$DownloadController(tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$loadAutoDownloadConfig$2$DownloadController(final TLObject response, TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$DownloadController$S6BNcMIjfM9Sy3sKk-lGFkDg3LU
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$1$DownloadController(response);
            }
        });
    }

    public /* synthetic */ void lambda$null$1$DownloadController(TLObject response) {
        Preset preset;
        this.loadingAutoDownloadConfig = false;
        getUserConfig().autoDownloadConfigLoadTime = System.currentTimeMillis();
        getUserConfig().saveConfig(false);
        if (response != null) {
            TLRPC.TL_account_autoDownloadSettings res = (TLRPC.TL_account_autoDownloadSettings) response;
            this.lowPreset.set(res.low);
            this.mediumPreset.set(res.medium);
            this.highPreset.set(res.high);
            for (int a = 0; a < 3; a++) {
                if (a == 0) {
                    preset = this.mobilePreset;
                } else if (a == 1) {
                    preset = this.wifiPreset;
                } else {
                    preset = this.roamingPreset;
                }
                if (preset.equals(this.lowPreset)) {
                    preset.set(res.low);
                } else if (preset.equals(this.mediumPreset)) {
                    preset.set(res.medium);
                } else if (preset.equals(this.highPreset)) {
                    preset.set(res.high);
                }
            }
            int a2 = this.currentAccount;
            SharedPreferences.Editor editor = MessagesController.getMainSettings(a2).edit();
            editor.putString("mobilePreset", this.mobilePreset.toString());
            editor.putString("wifiPreset", this.wifiPreset.toString());
            editor.putString("roamingPreset", this.roamingPreset.toString());
            editor.putString("preset0", this.lowPreset.toString());
            editor.putString("preset1", this.mediumPreset.toString());
            editor.putString("preset2", this.highPreset.toString());
            editor.commit();
            this.lowPreset.toString();
            this.mediumPreset.toString();
            this.highPreset.toString();
            checkAutodownloadSettings();
        }
    }

    public Preset getCurrentMobilePreset() {
        int i = this.currentMobilePreset;
        if (i == 0) {
            return this.lowPreset;
        }
        if (i == 1) {
            return this.mediumPreset;
        }
        if (i == 2) {
            return this.highPreset;
        }
        return this.mobilePreset;
    }

    public Preset getCurrentWiFiPreset() {
        int i = this.currentWifiPreset;
        if (i == 0) {
            return this.lowPreset;
        }
        if (i == 1) {
            return this.mediumPreset;
        }
        if (i == 2) {
            return this.highPreset;
        }
        return this.wifiPreset;
    }

    public Preset getCurrentRoamingPreset() {
        int i = this.currentRoamingPreset;
        if (i == 0) {
            return this.lowPreset;
        }
        if (i == 1) {
            return this.mediumPreset;
        }
        if (i == 2) {
            return this.highPreset;
        }
        return this.roamingPreset;
    }

    public static int typeToIndex(int type) {
        if (type == 1) {
            return 0;
        }
        if (type == 2) {
            return 3;
        }
        if (type == 4) {
            return 1;
        }
        if (type != 8) {
            return 0;
        }
        return 2;
    }

    public void cleanup() {
        this.photoDownloadQueue.clear();
        this.audioDownloadQueue.clear();
        this.documentDownloadQueue.clear();
        this.videoDownloadQueue.clear();
        this.downloadQueueKeys.clear();
        this.typingTimes.clear();
    }

    public int getAutodownloadMask() {
        int[] masksArray;
        int result = 0;
        if (ApplicationLoader.isConnectedToWiFi()) {
            if (!this.wifiPreset.enabled) {
                return 0;
            }
            masksArray = getCurrentWiFiPreset().mask;
        } else if (ApplicationLoader.isRoaming()) {
            if (!this.roamingPreset.enabled) {
                return 0;
            }
            masksArray = getCurrentRoamingPreset().mask;
        } else {
            if (!this.mobilePreset.enabled) {
                return 0;
            }
            masksArray = getCurrentMobilePreset().mask;
        }
        for (int a = 0; a < masksArray.length; a++) {
            int mask = 0;
            if ((masksArray[a] & 1) != 0) {
                mask = 0 | 1;
            }
            if ((masksArray[a] & 2) != 0) {
                mask |= 2;
            }
            if ((masksArray[a] & 4) != 0) {
                mask |= 4;
            }
            if ((masksArray[a] & 8) != 0) {
                mask |= 8;
            }
            result |= mask << (a * 8);
        }
        return result;
    }

    protected int getAutodownloadMaskAll() {
        if (!this.mobilePreset.enabled && !this.roamingPreset.enabled && !this.wifiPreset.enabled) {
            return 0;
        }
        int mask = 0;
        for (int a = 0; a < 4; a++) {
            if ((getCurrentMobilePreset().mask[a] & 1) != 0 || (getCurrentWiFiPreset().mask[a] & 1) != 0 || (getCurrentRoamingPreset().mask[a] & 1) != 0) {
                mask |= 1;
            }
            if ((getCurrentMobilePreset().mask[a] & 2) != 0 || (getCurrentWiFiPreset().mask[a] & 2) != 0 || (getCurrentRoamingPreset().mask[a] & 2) != 0) {
                mask |= 2;
            }
            if ((getCurrentMobilePreset().mask[a] & 4) != 0 || (getCurrentWiFiPreset().mask[a] & 4) != 0 || (4 & getCurrentRoamingPreset().mask[a]) != 0) {
                mask |= 4;
            }
            if ((getCurrentMobilePreset().mask[a] & 8) != 0 || (getCurrentWiFiPreset().mask[a] & 8) != 0 || (getCurrentRoamingPreset().mask[a] & 8) != 0) {
                mask |= 8;
            }
        }
        return mask;
    }

    public void checkAutodownloadSettings() {
        int currentMask = getCurrentDownloadMask();
        if (currentMask == this.lastCheckMask) {
            return;
        }
        this.lastCheckMask = currentMask;
        if ((currentMask & 1) != 0) {
            if (this.photoDownloadQueue.isEmpty()) {
                newDownloadObjectsAvailable(1);
            }
        } else {
            for (int a = 0; a < this.photoDownloadQueue.size(); a++) {
                DownloadObject downloadObject = this.photoDownloadQueue.get(a);
                if (downloadObject.object instanceof TLRPC.Photo) {
                    TLRPC.Photo photo = (TLRPC.Photo) downloadObject.object;
                    TLRPC.PhotoSize photoSize = FileLoader.getClosestPhotoSizeWithSize(photo.sizes, AndroidUtilities.getPhotoSize());
                    getFileLoader().cancelLoadFile(photoSize);
                } else if (downloadObject.object instanceof TLRPC.Document) {
                    getFileLoader().cancelLoadFile((TLRPC.Document) downloadObject.object);
                }
            }
            this.photoDownloadQueue.clear();
        }
        if ((currentMask & 2) != 0) {
            if (this.audioDownloadQueue.isEmpty()) {
                newDownloadObjectsAvailable(2);
            }
        } else {
            for (int a2 = 0; a2 < this.audioDownloadQueue.size(); a2++) {
                getFileLoader().cancelLoadFile((TLRPC.Document) this.audioDownloadQueue.get(a2).object);
            }
            this.audioDownloadQueue.clear();
        }
        if ((currentMask & 8) != 0) {
            if (this.documentDownloadQueue.isEmpty()) {
                newDownloadObjectsAvailable(8);
            }
        } else {
            for (int a3 = 0; a3 < this.documentDownloadQueue.size(); a3++) {
                TLRPC.Document document = (TLRPC.Document) this.documentDownloadQueue.get(a3).object;
                getFileLoader().cancelLoadFile(document);
            }
            this.documentDownloadQueue.clear();
        }
        if ((currentMask & 4) != 0) {
            if (this.videoDownloadQueue.isEmpty()) {
                newDownloadObjectsAvailable(4);
            }
        } else {
            for (int a4 = 0; a4 < this.videoDownloadQueue.size(); a4++) {
                getFileLoader().cancelLoadFile((TLRPC.Document) this.videoDownloadQueue.get(a4).object);
            }
            this.videoDownloadQueue.clear();
        }
        int mask = getAutodownloadMaskAll();
        if (mask == 0) {
            getMessagesStorage().clearDownloadQueue(0);
            return;
        }
        if ((mask & 1) == 0) {
            getMessagesStorage().clearDownloadQueue(1);
        }
        if ((mask & 2) == 0) {
            getMessagesStorage().clearDownloadQueue(2);
        }
        if ((mask & 4) == 0) {
            getMessagesStorage().clearDownloadQueue(4);
        }
        if ((mask & 8) == 0) {
            getMessagesStorage().clearDownloadQueue(8);
        }
    }

    public boolean canDownloadMedia(MessageObject messageObject) {
        return canDownloadMedia(messageObject.messageOwner) == 1;
    }

    public boolean canDownloadMedia(int type, int size) {
        Preset preset;
        if (ApplicationLoader.isConnectedToWiFi()) {
            if (!this.wifiPreset.enabled) {
                return false;
            }
            preset = getCurrentWiFiPreset();
        } else if (ApplicationLoader.isRoaming()) {
            if (!this.roamingPreset.enabled) {
                return false;
            }
            preset = getCurrentRoamingPreset();
        } else {
            Preset preset2 = this.mobilePreset;
            if (!preset2.enabled) {
                return false;
            }
            preset = getCurrentMobilePreset();
        }
        int mask = preset.mask[1];
        int maxSize = preset.sizes[typeToIndex(type)];
        if (type == 1 || (size != 0 && size <= maxSize)) {
            return type == 2 || (mask & type) != 0;
        }
        return false;
    }

    public int canDownloadMedia(TLRPC.Message message) {
        int type;
        int index;
        Preset preset;
        if (message == null) {
            return 0;
        }
        boolean isVideo = MessageObject.isVideoMessage(message);
        if (isVideo || MessageObject.isGifMessage(message) || MessageObject.isRoundVideoMessage(message) || MessageObject.isGameMessage(message)) {
            type = 4;
        } else if (MessageObject.isVoiceMessage(message)) {
            type = 2;
        } else if (MessageObject.isPhoto(message) || MessageObject.isStickerMessage(message) || MessageObject.isAnimatedStickerMessage(message)) {
            type = 1;
        } else {
            if (MessageObject.getDocument(message) == null) {
                return 0;
            }
            type = 8;
        }
        TLRPC.Peer peer = message.to_id;
        if (peer != null) {
            if (peer.user_id != 0) {
                if (getContactsController().contactsDict.containsKey(Integer.valueOf(peer.user_id))) {
                    index = 0;
                } else {
                    index = 1;
                }
            } else {
                int index2 = peer.chat_id;
                if (index2 != 0) {
                    if (message.from_id != 0 && getContactsController().contactsDict.containsKey(Integer.valueOf(message.from_id))) {
                        index = 0;
                    } else {
                        index = 2;
                    }
                } else if (MessageObject.isMegagroup(message)) {
                    if (message.from_id != 0 && getContactsController().contactsDict.containsKey(Integer.valueOf(message.from_id))) {
                        index = 0;
                    } else {
                        index = 2;
                    }
                } else {
                    index = 3;
                }
            }
        } else {
            index = 1;
        }
        if (ApplicationLoader.isConnectedToWiFi()) {
            if (!this.wifiPreset.enabled) {
                return 0;
            }
            preset = getCurrentWiFiPreset();
        } else if (ApplicationLoader.isRoaming()) {
            if (!this.roamingPreset.enabled) {
                return 0;
            }
            preset = getCurrentRoamingPreset();
        } else {
            Preset preset2 = this.mobilePreset;
            if (!preset2.enabled) {
                return 0;
            }
            preset = getCurrentMobilePreset();
        }
        int mask = preset.mask[index];
        int maxSize = preset.sizes[typeToIndex(type)];
        int size = MessageObject.getMessageSize(message);
        if (isVideo && preset.preloadVideo && size > maxSize && maxSize > 2097152) {
            return (mask & type) != 0 ? 2 : 0;
        }
        if (type == 1 || (size != 0 && size <= maxSize)) {
            return (type == 2 || (mask & type) != 0) ? 1 : 0;
        }
        return 0;
    }

    protected boolean canDownloadNextTrack() {
        return ApplicationLoader.isConnectedToWiFi() ? this.wifiPreset.enabled && getCurrentWiFiPreset().preloadMusic : ApplicationLoader.isRoaming() ? this.roamingPreset.enabled && getCurrentRoamingPreset().preloadMusic : this.mobilePreset.enabled && getCurrentMobilePreset().preloadMusic;
    }

    public int getCurrentDownloadMask() {
        if (ApplicationLoader.isConnectedToWiFi()) {
            if (!this.wifiPreset.enabled) {
                return 0;
            }
            int mask = 0;
            for (int a = 0; a < 4; a++) {
                mask |= getCurrentWiFiPreset().mask[a];
            }
            return mask;
        }
        if (ApplicationLoader.isRoaming()) {
            if (!this.roamingPreset.enabled) {
                return 0;
            }
            int mask2 = 0;
            for (int a2 = 0; a2 < 4; a2++) {
                mask2 |= getCurrentRoamingPreset().mask[a2];
            }
            return mask2;
        }
        if (!this.mobilePreset.enabled) {
            return 0;
        }
        int mask3 = 0;
        for (int a3 = 0; a3 < 4; a3++) {
            mask3 |= getCurrentMobilePreset().mask[a3];
        }
        return mask3;
    }

    public void savePresetToServer(int type) {
        Preset preset;
        boolean enabled;
        TLRPC.TL_account_saveAutoDownloadSettings req = new TLRPC.TL_account_saveAutoDownloadSettings();
        if (type == 0) {
            preset = getCurrentMobilePreset();
            enabled = this.mobilePreset.enabled;
        } else if (type == 1) {
            preset = getCurrentWiFiPreset();
            enabled = this.wifiPreset.enabled;
        } else {
            preset = getCurrentRoamingPreset();
            enabled = this.roamingPreset.enabled;
        }
        req.settings = new TLRPC.TL_autoDownloadSettings();
        req.settings.audio_preload_next = preset.preloadMusic;
        req.settings.video_preload_large = preset.preloadVideo;
        req.settings.phonecalls_less_data = preset.lessCallData;
        req.settings.disabled = !enabled;
        boolean photo = false;
        boolean video = false;
        boolean document = false;
        for (int a = 0; a < preset.mask.length; a++) {
            if ((preset.mask[a] & 1) != 0) {
                photo = true;
            }
            if ((preset.mask[a] & 4) != 0) {
                video = true;
            }
            if ((preset.mask[a] & 8) != 0) {
                document = true;
            }
            if (photo && video && document) {
                break;
            }
        }
        req.settings.photo_size_max = photo ? preset.sizes[0] : 0;
        req.settings.video_size_max = video ? preset.sizes[1] : 0;
        req.settings.file_size_max = document ? preset.sizes[2] : 0;
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$DownloadController$q2B2WGeuKbu18Oh9yAAtXpf5vrE
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                DownloadController.lambda$savePresetToServer$3(tLObject, tL_error);
            }
        });
    }

    static /* synthetic */ void lambda$savePresetToServer$3(TLObject response, TLRPC.TL_error error) {
    }

    protected void processDownloadObjects(int type, ArrayList<DownloadObject> objects) {
        String path;
        int cacheType;
        if (objects.isEmpty()) {
            return;
        }
        ArrayList<DownloadObject> queue = null;
        if (type == 1) {
            queue = this.photoDownloadQueue;
        } else if (type == 2) {
            queue = this.audioDownloadQueue;
        } else if (type == 4) {
            queue = this.videoDownloadQueue;
        } else if (type == 8) {
            queue = this.documentDownloadQueue;
        }
        for (int a = 0; a < objects.size(); a++) {
            DownloadObject downloadObject = objects.get(a);
            TLRPC.PhotoSize photoSize = null;
            if (downloadObject.object instanceof TLRPC.Document) {
                TLRPC.Document document = (TLRPC.Document) downloadObject.object;
                path = FileLoader.getAttachFileName(document);
            } else if (downloadObject.object instanceof TLRPC.Photo) {
                path = FileLoader.getAttachFileName(downloadObject.object);
                TLRPC.Photo photo = (TLRPC.Photo) downloadObject.object;
                photoSize = FileLoader.getClosestPhotoSizeWithSize(photo.sizes, AndroidUtilities.getPhotoSize());
            } else {
                path = null;
            }
            if (path != null && !this.downloadQueueKeys.containsKey(path)) {
                boolean added = true;
                if (photoSize != null) {
                    TLRPC.Photo photo2 = (TLRPC.Photo) downloadObject.object;
                    if (downloadObject.secret) {
                        cacheType = 2;
                    } else if (downloadObject.forceCache) {
                        cacheType = 1;
                    } else {
                        cacheType = 0;
                    }
                    getFileLoader().loadFile(ImageLocation.getForPhoto(photoSize, photo2), downloadObject.parent, null, 0, cacheType);
                } else if (downloadObject.object instanceof TLRPC.Document) {
                    TLRPC.Document document2 = (TLRPC.Document) downloadObject.object;
                    getFileLoader().loadFile(document2, downloadObject.parent, 0, downloadObject.secret ? 2 : 0);
                } else {
                    added = false;
                }
                if (added) {
                    queue.add(downloadObject);
                    this.downloadQueueKeys.put(path, downloadObject);
                }
            }
        }
    }

    protected void newDownloadObjectsAvailable(int downloadMask) {
        int mask = getCurrentDownloadMask();
        if ((mask & 1) != 0 && (downloadMask & 1) != 0 && this.photoDownloadQueue.isEmpty()) {
            getMessagesStorage().getDownloadQueue(1);
        }
        if ((mask & 2) != 0 && (downloadMask & 2) != 0 && this.audioDownloadQueue.isEmpty()) {
            getMessagesStorage().getDownloadQueue(2);
        }
        if ((mask & 4) != 0 && (downloadMask & 4) != 0 && this.videoDownloadQueue.isEmpty()) {
            getMessagesStorage().getDownloadQueue(4);
        }
        if ((mask & 8) != 0 && (downloadMask & 8) != 0 && this.documentDownloadQueue.isEmpty()) {
            getMessagesStorage().getDownloadQueue(8);
        }
    }

    private void checkDownloadFinished(String fileName, int state) {
        DownloadObject downloadObject = this.downloadQueueKeys.get(fileName);
        if (downloadObject != null) {
            this.downloadQueueKeys.remove(fileName);
            if (state == 0 || state == 2) {
                getMessagesStorage().removeFromDownloadQueue(downloadObject.id, downloadObject.type, false);
            }
            if (downloadObject.type != 1) {
                if (downloadObject.type == 2) {
                    this.audioDownloadQueue.remove(downloadObject);
                    if (this.audioDownloadQueue.isEmpty()) {
                        newDownloadObjectsAvailable(2);
                        return;
                    }
                    return;
                }
                if (downloadObject.type == 4) {
                    this.videoDownloadQueue.remove(downloadObject);
                    if (this.videoDownloadQueue.isEmpty()) {
                        newDownloadObjectsAvailable(4);
                        return;
                    }
                    return;
                }
                if (downloadObject.type == 8) {
                    this.documentDownloadQueue.remove(downloadObject);
                    if (this.documentDownloadQueue.isEmpty()) {
                        newDownloadObjectsAvailable(8);
                        return;
                    }
                    return;
                }
                return;
            }
            this.photoDownloadQueue.remove(downloadObject);
            if (this.photoDownloadQueue.isEmpty()) {
                newDownloadObjectsAvailable(1);
            }
        }
    }

    public int generateObserverTag() {
        int i = this.lastTag;
        this.lastTag = i + 1;
        return i;
    }

    public void addLoadingFileObserver(String fileName, FileDownloadProgressListener observer) {
        addLoadingFileObserver(fileName, null, observer);
    }

    public void addLoadingFileObserver(String fileName, MessageObject messageObject, FileDownloadProgressListener observer) {
        if (this.listenerInProgress) {
            this.addLaterArray.put(fileName, observer);
            return;
        }
        removeLoadingFileObserver(observer);
        ArrayList<WeakReference<FileDownloadProgressListener>> arrayList = this.loadingFileObservers.get(fileName);
        if (arrayList == null) {
            arrayList = new ArrayList<>();
            this.loadingFileObservers.put(fileName, arrayList);
        }
        arrayList.add(new WeakReference<>(observer));
        if (messageObject != null) {
            ArrayList<MessageObject> messageObjects = this.loadingFileMessagesObservers.get(fileName);
            if (messageObjects == null) {
                messageObjects = new ArrayList<>();
                this.loadingFileMessagesObservers.put(fileName, messageObjects);
            }
            messageObjects.add(messageObject);
        }
        this.observersByTag.put(observer.getObserverTag(), fileName);
    }

    public void removeLoadingFileObserver(FileDownloadProgressListener observer) {
        if (this.listenerInProgress) {
            this.deleteLaterArray.add(observer);
            return;
        }
        String fileName = this.observersByTag.get(observer.getObserverTag());
        if (fileName != null) {
            ArrayList<WeakReference<FileDownloadProgressListener>> arrayList = this.loadingFileObservers.get(fileName);
            if (arrayList != null) {
                int a = 0;
                while (a < arrayList.size()) {
                    WeakReference<FileDownloadProgressListener> reference = arrayList.get(a);
                    if (reference.get() == null || reference.get() == observer) {
                        arrayList.remove(a);
                        a--;
                    }
                    a++;
                }
                if (arrayList.isEmpty()) {
                    this.loadingFileObservers.remove(fileName);
                }
            }
            this.observersByTag.remove(observer.getObserverTag());
        }
    }

    private void processLaterArrays() {
        for (Map.Entry<String, FileDownloadProgressListener> listener : this.addLaterArray.entrySet()) {
            addLoadingFileObserver(listener.getKey(), listener.getValue());
        }
        this.addLaterArray.clear();
        Iterator<FileDownloadProgressListener> it = this.deleteLaterArray.iterator();
        while (it.hasNext()) {
            removeLoadingFileObserver(it.next());
        }
        this.deleteLaterArray.clear();
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id == NotificationCenter.fileDidFailToLoad || id == NotificationCenter.httpFileDidFailedLoad) {
            String fileName = (String) args[0];
            Integer canceled = (Integer) args[1];
            this.listenerInProgress = true;
            ArrayList<WeakReference<FileDownloadProgressListener>> arrayList = this.loadingFileObservers.get(fileName);
            if (arrayList != null) {
                int size = arrayList.size();
                for (int a = 0; a < size; a++) {
                    WeakReference<FileDownloadProgressListener> reference = arrayList.get(a);
                    if (reference.get() != null) {
                        reference.get().onFailedDownload(fileName, canceled.intValue() == 1);
                        if (canceled.intValue() != 1) {
                            this.observersByTag.remove(reference.get().getObserverTag());
                        }
                    }
                }
                int a2 = canceled.intValue();
                if (a2 != 1) {
                    this.loadingFileObservers.remove(fileName);
                }
            }
            this.listenerInProgress = false;
            processLaterArrays();
            checkDownloadFinished(fileName, canceled.intValue());
            return;
        }
        if (id == NotificationCenter.fileDidLoad || id == NotificationCenter.httpFileDidLoad) {
            this.listenerInProgress = true;
            String fileName2 = (String) args[0];
            ArrayList<MessageObject> messageObjects = this.loadingFileMessagesObservers.get(fileName2);
            if (messageObjects != null) {
                int size2 = messageObjects.size();
                for (int a3 = 0; a3 < size2; a3++) {
                    messageObjects.get(a3).mediaExists = true;
                }
                this.loadingFileMessagesObservers.remove(fileName2);
            }
            ArrayList<WeakReference<FileDownloadProgressListener>> arrayList2 = this.loadingFileObservers.get(fileName2);
            if (arrayList2 != null) {
                int size3 = arrayList2.size();
                for (int a4 = 0; a4 < size3; a4++) {
                    WeakReference<FileDownloadProgressListener> reference2 = arrayList2.get(a4);
                    if (reference2.get() != null) {
                        reference2.get().onSuccessDownload(fileName2);
                        this.observersByTag.remove(reference2.get().getObserverTag());
                    }
                }
                this.loadingFileObservers.remove(fileName2);
            }
            this.listenerInProgress = false;
            processLaterArrays();
            checkDownloadFinished(fileName2, 0);
            return;
        }
        if (id == NotificationCenter.FileLoadProgressChanged) {
            this.listenerInProgress = true;
            String fileName3 = (String) args[0];
            ArrayList<WeakReference<FileDownloadProgressListener>> arrayList3 = this.loadingFileObservers.get(fileName3);
            if (arrayList3 != null) {
                Float progress = (Float) args[1];
                int size4 = arrayList3.size();
                for (int a5 = 0; a5 < size4; a5++) {
                    WeakReference<FileDownloadProgressListener> reference3 = arrayList3.get(a5);
                    if (reference3.get() != null) {
                        reference3.get().onProgressDownload(fileName3, progress.floatValue());
                    }
                }
            }
            this.listenerInProgress = false;
            processLaterArrays();
            return;
        }
        if (id == NotificationCenter.FileUploadProgressChanged) {
            this.listenerInProgress = true;
            String fileName4 = (String) args[0];
            ArrayList<WeakReference<FileDownloadProgressListener>> arrayList4 = this.loadingFileObservers.get(fileName4);
            if (arrayList4 != null) {
                Float progress2 = (Float) args[1];
                Boolean enc = (Boolean) args[2];
                int size5 = arrayList4.size();
                for (int a6 = 0; a6 < size5; a6++) {
                    WeakReference<FileDownloadProgressListener> reference4 = arrayList4.get(a6);
                    if (reference4.get() != null) {
                        reference4.get().onProgressUpload(fileName4, progress2.floatValue(), enc.booleanValue());
                    }
                }
            }
            this.listenerInProgress = false;
            processLaterArrays();
            try {
                ArrayList<SendMessagesHelper.DelayedMessage> delayedMessages = getSendMessagesHelper().getDelayedMessages(fileName4);
                if (delayedMessages != null) {
                    for (int a7 = 0; a7 < delayedMessages.size(); a7++) {
                        SendMessagesHelper.DelayedMessage delayedMessage = delayedMessages.get(a7);
                        if (delayedMessage.encryptedChat == null) {
                            long dialog_id = delayedMessage.peer;
                            if (delayedMessage.type == 4) {
                                Long lastTime = this.typingTimes.get(dialog_id);
                                if (lastTime == null || lastTime.longValue() + 4000 < System.currentTimeMillis()) {
                                    MessageObject messageObject = (MessageObject) delayedMessage.extraHashMap.get(fileName4 + "_i");
                                    if (messageObject != null && messageObject.isVideo()) {
                                        getMessagesController().sendTyping(dialog_id, 5, 0);
                                    } else {
                                        getMessagesController().sendTyping(dialog_id, 4, 0);
                                    }
                                    this.typingTimes.put(dialog_id, Long.valueOf(System.currentTimeMillis()));
                                }
                            } else {
                                Long lastTime2 = this.typingTimes.get(dialog_id);
                                delayedMessage.obj.getDocument();
                                if (lastTime2 == null || lastTime2.longValue() + 4000 < System.currentTimeMillis()) {
                                    if (delayedMessage.obj.isRoundVideo()) {
                                        getMessagesController().sendTyping(dialog_id, 8, 0);
                                    } else if (delayedMessage.obj.isVideo()) {
                                        getMessagesController().sendTyping(dialog_id, 5, 0);
                                    } else if (delayedMessage.obj.isVoice()) {
                                        getMessagesController().sendTyping(dialog_id, 9, 0);
                                    } else if (delayedMessage.obj.getDocument() != null) {
                                        getMessagesController().sendTyping(dialog_id, 3, 0);
                                    } else if (delayedMessage.photoSize != null) {
                                        getMessagesController().sendTyping(dialog_id, 4, 0);
                                    }
                                    this.typingTimes.put(dialog_id, Long.valueOf(System.currentTimeMillis()));
                                }
                            }
                        }
                    }
                }
            } catch (Exception e) {
                FileLog.e(e);
            }
        }
    }
}
