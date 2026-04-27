package im.uwrkaxlmjj.messenger;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ShortcutInfo;
import android.content.pm.ShortcutManager;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffXfermode;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.drawable.Icon;
import android.os.Build;
import android.text.Spannable;
import android.text.SpannableStringBuilder;
import android.text.Spanned;
import android.text.SpannedString;
import android.text.TextUtils;
import android.text.style.CharacterStyle;
import android.util.LongSparseArray;
import android.util.SparseArray;
import androidx.recyclerview.widget.ItemTouchHelper;
import com.google.firebase.remoteconfig.FirebaseRemoteConfig;
import com.snail.antifake.deviceid.ShellAdbUtils;
import im.uwrkaxlmjj.messenger.support.SparseLongArray;
import im.uwrkaxlmjj.sqlite.SQLiteCursor;
import im.uwrkaxlmjj.sqlite.SQLiteDatabase;
import im.uwrkaxlmjj.sqlite.SQLitePreparedStatement;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.NativeByteBuffer;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.SerializedData;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.LaunchActivity;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.components.TextStyleSpan;
import im.uwrkaxlmjj.ui.components.URLSpanReplacement;
import im.uwrkaxlmjj.ui.components.URLSpanUserMention;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CountDownLatch;

/* JADX INFO: loaded from: classes2.dex */
public class MediaDataController extends BaseController {
    public static final int MEDIA_AUDIO = 2;
    public static final int MEDIA_FILE = 1;
    public static final int MEDIA_MUSIC = 4;
    public static final int MEDIA_PHOTOVIDEO = 0;
    public static final int MEDIA_TYPES_COUNT = 5;
    public static final int MEDIA_URL = 3;
    public static final int TYPE_EMOJI = 4;
    public static final int TYPE_FAVE = 2;
    public static final int TYPE_FEATURED = 3;
    public static final int TYPE_IMAGE = 0;
    public static final int TYPE_MASK = 1;
    private static RectF bitmapRect;
    private static Paint erasePaint;
    private static Paint roundPaint;
    private static Path roundPath;
    private HashMap<String, ArrayList<TLRPC.Document>> allStickers;
    private HashMap<String, ArrayList<TLRPC.Document>> allStickersFeatured;
    private int[] archivedStickersCount;
    private SparseArray<TLRPC.BotInfo> botInfos;
    private LongSparseArray<TLRPC.Message> botKeyboards;
    private SparseLongArray botKeyboardsByMids;
    private HashMap<String, Boolean> currentFetchingEmoji;
    private LongSparseArray<TLRPC.Message> draftMessages;
    private LongSparseArray<TLRPC.DraftMessage> drafts;
    private ArrayList<TLRPC.StickerSetCovered> featuredStickerSets;
    private LongSparseArray<TLRPC.StickerSetCovered> featuredStickerSetsById;
    private boolean featuredStickersLoaded;
    private LongSparseArray<TLRPC.TL_messages_stickerSet> groupStickerSets;
    public ArrayList<TLRPC.TL_topPeer> hints;
    private boolean inTransaction;
    public ArrayList<TLRPC.TL_topPeer> inlineBots;
    private LongSparseArray<TLRPC.TL_messages_stickerSet> installedStickerSetsById;
    private long lastMergeDialogId;
    private int lastReqId;
    private int lastReturnedNum;
    private String lastSearchQuery;
    private int[] loadDate;
    private int loadFeaturedDate;
    private int loadFeaturedHash;
    private int[] loadHash;
    boolean loaded;
    boolean loading;
    private boolean loadingDrafts;
    private boolean loadingFeaturedStickers;
    private boolean loadingRecentGifs;
    private boolean[] loadingRecentStickers;
    private boolean[] loadingStickers;
    private int mergeReqId;
    private int[] messagesSearchCount;
    private boolean[] messagesSearchEndReached;
    private SharedPreferences preferences;
    private ArrayList<Long> readingStickerSets;
    private ArrayList<TLRPC.Document> recentGifs;
    private boolean recentGifsLoaded;
    private ArrayList<TLRPC.Document>[] recentStickers;
    private boolean[] recentStickersLoaded;
    private int reqId;
    private ArrayList<MessageObject> searchResultMessages;
    private SparseArray<MessageObject>[] searchResultMessagesMap;
    private ArrayList<TLRPC.TL_messages_stickerSet>[] stickerSets;
    private LongSparseArray<TLRPC.TL_messages_stickerSet> stickerSetsById;
    private HashMap<String, TLRPC.TL_messages_stickerSet> stickerSetsByName;
    private LongSparseArray<String> stickersByEmoji;
    private LongSparseArray<TLRPC.Document>[] stickersByIds;
    private boolean[] stickersLoaded;
    private ArrayList<Long> unreadStickerSets;
    private static volatile MediaDataController[] Instance = new MediaDataController[3];
    public static long installingStickerSetId = -1;
    private static Comparator<TLRPC.MessageEntity> entityComparator = new Comparator() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$ybuBNKZrsN_7re0FnNONsrnWe40
        @Override // java.util.Comparator
        public final int compare(Object obj, Object obj2) {
            return MediaDataController.lambda$static$86((TLRPC.MessageEntity) obj, (TLRPC.MessageEntity) obj2);
        }
    };

    public static class KeywordResult {
        public String emoji;
        public String keyword;
    }

    public interface KeywordResultCallback {
        void run(ArrayList<KeywordResult> arrayList, String str);
    }

    public static MediaDataController getInstance(int num) {
        MediaDataController localInstance = Instance[num];
        if (localInstance == null) {
            synchronized (MediaDataController.class) {
                localInstance = Instance[num];
                if (localInstance == null) {
                    MediaDataController[] mediaDataControllerArr = Instance;
                    MediaDataController mediaDataController = new MediaDataController(num);
                    localInstance = mediaDataController;
                    mediaDataControllerArr[num] = mediaDataController;
                }
            }
        }
        return localInstance;
    }

    public MediaDataController(int num) {
        super(num);
        this.stickerSets = new ArrayList[]{new ArrayList<>(), new ArrayList<>(), new ArrayList<>(0), new ArrayList<>(), new ArrayList<>()};
        this.stickersByIds = new LongSparseArray[]{new LongSparseArray<>(), new LongSparseArray<>(), new LongSparseArray<>(), new LongSparseArray<>(), new LongSparseArray<>()};
        this.stickerSetsById = new LongSparseArray<>();
        this.installedStickerSetsById = new LongSparseArray<>();
        this.groupStickerSets = new LongSparseArray<>();
        this.stickerSetsByName = new HashMap<>();
        this.loadingStickers = new boolean[5];
        this.stickersLoaded = new boolean[5];
        this.loadHash = new int[5];
        this.loadDate = new int[5];
        this.archivedStickersCount = new int[2];
        this.stickersByEmoji = new LongSparseArray<>();
        this.allStickers = new HashMap<>();
        this.allStickersFeatured = new HashMap<>();
        this.recentStickers = new ArrayList[]{new ArrayList<>(), new ArrayList<>(), new ArrayList<>()};
        this.loadingRecentStickers = new boolean[3];
        this.recentStickersLoaded = new boolean[3];
        this.recentGifs = new ArrayList<>();
        this.featuredStickerSets = new ArrayList<>();
        this.featuredStickerSetsById = new LongSparseArray<>();
        this.unreadStickerSets = new ArrayList<>();
        this.readingStickerSets = new ArrayList<>();
        this.messagesSearchCount = new int[]{0, 0};
        this.messagesSearchEndReached = new boolean[]{false, false};
        this.searchResultMessages = new ArrayList<>();
        this.searchResultMessagesMap = new SparseArray[]{new SparseArray<>(), new SparseArray<>()};
        this.hints = new ArrayList<>();
        this.inlineBots = new ArrayList<>();
        this.drafts = new LongSparseArray<>();
        this.draftMessages = new LongSparseArray<>();
        this.botInfos = new SparseArray<>();
        this.botKeyboards = new LongSparseArray<>();
        this.botKeyboardsByMids = new SparseLongArray();
        this.currentFetchingEmoji = new HashMap<>();
        if (this.currentAccount == 0) {
            this.preferences = ApplicationLoader.applicationContext.getSharedPreferences("drafts", 0);
        } else {
            this.preferences = ApplicationLoader.applicationContext.getSharedPreferences("drafts" + this.currentAccount, 0);
        }
        Map<String, ?> values = this.preferences.getAll();
        for (Map.Entry<String, ?> entry : values.entrySet()) {
            try {
                String key = entry.getKey();
                long did = Utilities.parseLong(key).longValue();
                byte[] bytes = Utilities.hexToBytes((String) entry.getValue());
                SerializedData serializedData = new SerializedData(bytes);
                if (key.startsWith("r_")) {
                    TLRPC.Message message = TLRPC.Message.TLdeserialize(serializedData, serializedData.readInt32(true), true);
                    message.readAttachPath(serializedData, getUserConfig().clientUserId);
                    if (message != null) {
                        this.draftMessages.put(did, message);
                    }
                } else {
                    TLRPC.DraftMessage draftMessage = TLRPC.DraftMessage.TLdeserialize(serializedData, serializedData.readInt32(true), true);
                    if (draftMessage != null) {
                        this.drafts.put(did, draftMessage);
                    }
                }
                serializedData.cleanup();
            } catch (Exception e) {
            }
        }
    }

    public void cleanup() {
        for (int a = 0; a < 3; a++) {
            this.recentStickers[a].clear();
            this.loadingRecentStickers[a] = false;
            this.recentStickersLoaded[a] = false;
        }
        for (int a2 = 0; a2 < 4; a2++) {
            this.loadHash[a2] = 0;
            this.loadDate[a2] = 0;
            this.stickerSets[a2].clear();
            this.loadingStickers[a2] = false;
            this.stickersLoaded[a2] = false;
        }
        this.featuredStickerSets.clear();
        this.loadFeaturedDate = 0;
        this.loadFeaturedHash = 0;
        this.allStickers.clear();
        this.allStickersFeatured.clear();
        this.stickersByEmoji.clear();
        this.featuredStickerSetsById.clear();
        this.featuredStickerSets.clear();
        this.unreadStickerSets.clear();
        this.recentGifs.clear();
        this.stickerSetsById.clear();
        this.installedStickerSetsById.clear();
        this.stickerSetsByName.clear();
        this.loadingFeaturedStickers = false;
        this.featuredStickersLoaded = false;
        this.loadingRecentGifs = false;
        this.recentGifsLoaded = false;
        this.currentFetchingEmoji.clear();
        if (Build.VERSION.SDK_INT >= 25) {
            Utilities.globalQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$sbCOOmAPwlItcTrfXmUk-ULUZP4
                @Override // java.lang.Runnable
                public final void run() {
                    MediaDataController.lambda$cleanup$0();
                }
            });
        }
        this.loading = false;
        this.loaded = false;
        this.hints.clear();
        this.inlineBots.clear();
        getNotificationCenter().postNotificationName(NotificationCenter.reloadHints, new Object[0]);
        getNotificationCenter().postNotificationName(NotificationCenter.reloadInlineHints, new Object[0]);
        this.drafts.clear();
        this.draftMessages.clear();
        this.preferences.edit().clear().commit();
        this.botInfos.clear();
        this.botKeyboards.clear();
        this.botKeyboardsByMids.clear();
    }

    static /* synthetic */ void lambda$cleanup$0() {
        try {
            ShortcutManager shortcutManager = (ShortcutManager) ApplicationLoader.applicationContext.getSystemService(ShortcutManager.class);
            shortcutManager.removeAllDynamicShortcuts();
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public void checkStickers(int type) {
        if (this.loadingStickers[type]) {
            return;
        }
        if (!this.stickersLoaded[type] || Math.abs((System.currentTimeMillis() / 1000) - ((long) this.loadDate[type])) >= 3600) {
            loadStickers(type, true, false);
        }
    }

    public void checkFeaturedStickers() {
        if (this.loadingFeaturedStickers) {
            return;
        }
        if (!this.featuredStickersLoaded || Math.abs((System.currentTimeMillis() / 1000) - ((long) this.loadFeaturedDate)) >= 3600) {
            loadFeaturedStickers(true, false);
        }
    }

    public ArrayList<TLRPC.Document> getRecentStickers(int type) {
        ArrayList<TLRPC.Document> arrayList = this.recentStickers[type];
        return new ArrayList<>(arrayList.subList(0, Math.min(arrayList.size(), 20)));
    }

    public ArrayList<TLRPC.Document> getRecentStickersNoCopy(int type) {
        return this.recentStickers[type];
    }

    public boolean isStickerInFavorites(TLRPC.Document document) {
        if (document == null) {
            return false;
        }
        for (int a = 0; a < this.recentStickers[2].size(); a++) {
            TLRPC.Document d = this.recentStickers[2].get(a);
            if (d.id == document.id && d.dc_id == document.dc_id) {
                return true;
            }
        }
        return false;
    }

    public void addRecentSticker(final int type, final Object parentObject, TLRPC.Document document, int date, boolean remove) {
        boolean found;
        int maxCount;
        final TLRPC.Document old;
        if (!MessageObject.isStickerDocument(document)) {
            return;
        }
        int a = 0;
        while (true) {
            if (a >= this.recentStickers[type].size()) {
                found = false;
                break;
            }
            TLRPC.Document image = this.recentStickers[type].get(a);
            if (image.id != document.id) {
                a++;
            } else {
                this.recentStickers[type].remove(a);
                if (!remove) {
                    this.recentStickers[type].add(0, image);
                }
                found = true;
            }
        }
        if (!found && !remove) {
            this.recentStickers[type].add(0, document);
        }
        if (type == 2) {
            if (remove) {
                ToastUtils.show(mpEIGo.juqQQs.esbSDO.R.string.RemovedFromFavorites);
            } else {
                ToastUtils.show(mpEIGo.juqQQs.esbSDO.R.string.AddedToFavorites);
            }
            final TLRPC.TL_messages_faveSticker req = new TLRPC.TL_messages_faveSticker();
            req.id = new TLRPC.TL_inputDocument();
            req.id.id = document.id;
            req.id.access_hash = document.access_hash;
            req.id.file_reference = document.file_reference;
            if (req.id.file_reference == null) {
                req.id.file_reference = new byte[0];
            }
            req.unfave = remove;
            getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$00KdazdQFpJ0-P1R4cSCIH1Fzww
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$addRecentSticker$1$MediaDataController(parentObject, req, tLObject, tL_error);
                }
            });
            int maxCount2 = getMessagesController().maxFaveStickersCount;
            maxCount = maxCount2;
        } else {
            maxCount = getMessagesController().maxRecentStickersCount;
        }
        if (this.recentStickers[type].size() > maxCount || remove) {
            if (remove) {
                old = document;
            } else {
                ArrayList<TLRPC.Document>[] arrayListArr = this.recentStickers;
                old = arrayListArr[type].remove(arrayListArr[type].size() - 1);
            }
            getMessagesStorage().getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$Qll4Rzu5YQLVKdRLY33ed6bNe8g
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$addRecentSticker$2$MediaDataController(type, old);
                }
            });
        }
        if (!remove) {
            ArrayList<TLRPC.Document> arrayList = new ArrayList<>();
            arrayList.add(document);
            processLoadedRecentDocuments(type, arrayList, false, date, false);
        }
        if (type == 2) {
            getNotificationCenter().postNotificationName(NotificationCenter.recentDocumentsDidLoad, false, Integer.valueOf(type));
        }
    }

    public /* synthetic */ void lambda$addRecentSticker$1$MediaDataController(Object parentObject, TLRPC.TL_messages_faveSticker req, TLObject response, TLRPC.TL_error error) {
        if (error != null && FileRefController.isFileRefError(error.text) && parentObject != null) {
            getFileRefController().requestReference(parentObject, req);
        }
    }

    public /* synthetic */ void lambda$addRecentSticker$2$MediaDataController(int type, TLRPC.Document old) {
        int cacheType;
        if (type == 0) {
            cacheType = 3;
        } else if (type == 1) {
            cacheType = 4;
        } else {
            cacheType = 5;
        }
        try {
            getMessagesStorage().getDatabase().executeFast("DELETE FROM web_recent_v3 WHERE id = '" + old.id + "' AND type = " + cacheType).stepThis().dispose();
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public ArrayList<TLRPC.Document> getRecentGifs() {
        return new ArrayList<>(this.recentGifs);
    }

    public void removeRecentGifById(TLRPC.Document document) {
        if (document == null) {
            return;
        }
        for (int i = 0; i < this.recentGifs.size(); i++) {
            TLRPC.Document realDocument = this.recentGifs.get(i);
            if (realDocument.id == document.id) {
                removeRecentGif(realDocument);
                return;
            }
        }
    }

    public void removeRecentGif(final TLRPC.Document document) {
        this.recentGifs.remove(document);
        final TLRPC.TL_messages_saveGif req = new TLRPC.TL_messages_saveGif();
        req.id = new TLRPC.TL_inputDocument();
        req.id.id = document.id;
        req.id.access_hash = document.access_hash;
        req.id.file_reference = document.file_reference;
        if (req.id.file_reference == null) {
            req.id.file_reference = new byte[0];
        }
        req.unsave = true;
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$Om3d0Cfi765tFMY37Os6uDDTisw
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$removeRecentGif$3$MediaDataController(req, tLObject, tL_error);
            }
        });
        getMessagesStorage().getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$yd1c2fmlxeZVZPXMPEAKeeTiu4U
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$removeRecentGif$4$MediaDataController(document);
            }
        });
    }

    public /* synthetic */ void lambda$removeRecentGif$3$MediaDataController(TLRPC.TL_messages_saveGif req, TLObject response, TLRPC.TL_error error) {
        if (error != null && FileRefController.isFileRefError(error.text)) {
            getFileRefController().requestReference("gif", req);
        }
    }

    public /* synthetic */ void lambda$removeRecentGif$4$MediaDataController(TLRPC.Document document) {
        try {
            getMessagesStorage().getDatabase().executeFast("DELETE FROM web_recent_v3 WHERE id = '" + document.id + "' AND type = 2").stepThis().dispose();
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public boolean hasRecentGif(TLRPC.Document document) {
        for (int a = 0; a < this.recentGifs.size(); a++) {
            TLRPC.Document image = this.recentGifs.get(a);
            if (image.id == document.id) {
                this.recentGifs.remove(a);
                this.recentGifs.add(0, image);
                return true;
            }
        }
        return false;
    }

    public boolean hasRecentGifNoChangeINdex(TLRPC.Document document) {
        for (int a = 0; a < this.recentGifs.size(); a++) {
            if (this.recentGifs.get(a).id == document.id) {
                return true;
            }
        }
        return false;
    }

    public void addRecentGif(TLRPC.Document document, int date) {
        boolean found = false;
        int a = 0;
        while (true) {
            if (a >= this.recentGifs.size()) {
                break;
            }
            TLRPC.Document image = this.recentGifs.get(a);
            if (image.id != document.id) {
                a++;
            } else {
                this.recentGifs.remove(a);
                this.recentGifs.add(0, image);
                found = true;
                break;
            }
        }
        if (!found) {
            this.recentGifs.add(0, document);
        }
        if (this.recentGifs.size() > getMessagesController().maxRecentGifsCount) {
            final TLRPC.Document old = this.recentGifs.remove(r1.size() - 1);
            getMessagesStorage().getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$eW922a-zWC4XxDhSODFn0w_iC20
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$addRecentGif$5$MediaDataController(old);
                }
            });
        }
        ArrayList<TLRPC.Document> arrayList = new ArrayList<>();
        arrayList.add(document);
        processLoadedRecentDocuments(0, arrayList, true, date, false);
    }

    public /* synthetic */ void lambda$addRecentGif$5$MediaDataController(TLRPC.Document old) {
        try {
            getMessagesStorage().getDatabase().executeFast("DELETE FROM web_recent_v3 WHERE id = '" + old.id + "' AND type = 2").stepThis().dispose();
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public boolean isLoadingStickers(int type) {
        return this.loadingStickers[type];
    }

    public void replaceStickerSet(final TLRPC.TL_messages_stickerSet tL_messages_stickerSet) {
        TLRPC.TL_messages_stickerSet tL_messages_stickerSet2 = this.stickerSetsById.get(tL_messages_stickerSet.set.id);
        boolean z = false;
        if (tL_messages_stickerSet2 == null) {
            tL_messages_stickerSet2 = this.stickerSetsByName.get(tL_messages_stickerSet.set.short_name);
        }
        if (tL_messages_stickerSet2 == null && (tL_messages_stickerSet2 = this.groupStickerSets.get(tL_messages_stickerSet.set.id)) != null) {
            z = true;
        }
        if (tL_messages_stickerSet2 == null) {
            return;
        }
        boolean z2 = false;
        if ("AnimatedEmojies".equals(tL_messages_stickerSet.set.short_name)) {
            z2 = true;
            tL_messages_stickerSet2.documents = tL_messages_stickerSet.documents;
            tL_messages_stickerSet2.packs = tL_messages_stickerSet.packs;
            tL_messages_stickerSet2.set = tL_messages_stickerSet.set;
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$lN4ZK3LZfpSV81LnE0KmHvkvTL4
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$replaceStickerSet$6$MediaDataController(tL_messages_stickerSet);
                }
            });
        } else {
            LongSparseArray longSparseArray = new LongSparseArray();
            int size = tL_messages_stickerSet.documents.size();
            for (int i = 0; i < size; i++) {
                TLRPC.Document document = tL_messages_stickerSet.documents.get(i);
                longSparseArray.put(document.id, document);
            }
            int size2 = tL_messages_stickerSet2.documents.size();
            for (int i2 = 0; i2 < size2; i2++) {
                TLRPC.Document document2 = (TLRPC.Document) longSparseArray.get(tL_messages_stickerSet.documents.get(i2).id);
                if (document2 != null) {
                    tL_messages_stickerSet2.documents.set(i2, document2);
                    z2 = true;
                }
            }
        }
        if (z2) {
            if (z) {
                putSetToCache(tL_messages_stickerSet2);
                return;
            }
            boolean z3 = tL_messages_stickerSet.set.masks;
            putStickersToCache(z3 ? 1 : 0, this.stickerSets[z3 ? 1 : 0], this.loadDate[z3 ? 1 : 0], this.loadHash[z3 ? 1 : 0]);
            if ("AnimatedEmojies".equals(tL_messages_stickerSet.set.short_name)) {
                putStickersToCache(4, this.stickerSets[4], this.loadDate[4], this.loadHash[4]);
            }
        }
    }

    public /* synthetic */ void lambda$replaceStickerSet$6$MediaDataController(TLRPC.TL_messages_stickerSet set) {
        LongSparseArray<TLRPC.Document> stickersById = getStickerByIds(4);
        for (int b = 0; b < set.documents.size(); b++) {
            TLRPC.Document document = set.documents.get(b);
            stickersById.put(document.id, document);
        }
    }

    public TLRPC.TL_messages_stickerSet getStickerSetByName(String name) {
        return this.stickerSetsByName.get(name);
    }

    public TLRPC.TL_messages_stickerSet getStickerSetById(long id) {
        return this.stickerSetsById.get(id);
    }

    public TLRPC.TL_messages_stickerSet getGroupStickerSetById(TLRPC.StickerSet stickerSet) {
        TLRPC.TL_messages_stickerSet set = this.stickerSetsById.get(stickerSet.id);
        if (set == null) {
            set = this.groupStickerSets.get(stickerSet.id);
            if (set == null || set.set == null) {
                loadGroupStickerSet(stickerSet, true);
            } else if (set.set.hash != stickerSet.hash) {
                loadGroupStickerSet(stickerSet, false);
            }
        }
        return set;
    }

    public void putGroupStickerSet(TLRPC.TL_messages_stickerSet stickerSet) {
        this.groupStickerSets.put(stickerSet.set.id, stickerSet);
    }

    private void loadGroupStickerSet(final TLRPC.StickerSet stickerSet, boolean cache) {
        if (cache) {
            getMessagesStorage().getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$vxJo3S2chf2wXh7jWIhwsTwZgkg
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$loadGroupStickerSet$8$MediaDataController(stickerSet);
                }
            });
            return;
        }
        TLRPC.TL_messages_getStickerSet req = new TLRPC.TL_messages_getStickerSet();
        req.stickerset = new TLRPC.TL_inputStickerSetID();
        req.stickerset.id = stickerSet.id;
        req.stickerset.access_hash = stickerSet.access_hash;
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$7s-UNf8npa4vKMj4U_rZIASTyWo
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$loadGroupStickerSet$10$MediaDataController(tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$loadGroupStickerSet$8$MediaDataController(TLRPC.StickerSet stickerSet) {
        final TLRPC.TL_messages_stickerSet set;
        try {
            SQLiteCursor cursor = getMessagesStorage().getDatabase().queryFinalized("SELECT document FROM web_recent_v3 WHERE id = 's_" + stickerSet.id + "'", new Object[0]);
            if (cursor.next() && !cursor.isNull(0)) {
                NativeByteBuffer data = cursor.byteBufferValue(0);
                if (data != null) {
                    set = TLRPC.TL_messages_stickerSet.TLdeserialize(data, data.readInt32(false), false);
                    data.reuse();
                } else {
                    set = null;
                }
            } else {
                set = null;
            }
            cursor.dispose();
            if (set == null || set.set == null || set.set.hash != stickerSet.hash) {
                loadGroupStickerSet(stickerSet, false);
            }
            if (set != null && set.set != null) {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$U2Veo85DQe8OV7G2CKFo-80PqFE
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$7$MediaDataController(set);
                    }
                });
            }
        } catch (Throwable e) {
            FileLog.e(e);
        }
    }

    public /* synthetic */ void lambda$null$7$MediaDataController(TLRPC.TL_messages_stickerSet set) {
        this.groupStickerSets.put(set.set.id, set);
        getNotificationCenter().postNotificationName(NotificationCenter.groupStickersDidLoad, Long.valueOf(set.set.id));
    }

    public /* synthetic */ void lambda$loadGroupStickerSet$10$MediaDataController(TLObject response, TLRPC.TL_error error) {
        if (response != null) {
            final TLRPC.TL_messages_stickerSet set = (TLRPC.TL_messages_stickerSet) response;
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$nrbcRYzVtV4NjG0F76G009b7-3Q
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$9$MediaDataController(set);
                }
            });
        }
    }

    public /* synthetic */ void lambda$null$9$MediaDataController(TLRPC.TL_messages_stickerSet set) {
        this.groupStickerSets.put(set.set.id, set);
        getNotificationCenter().postNotificationName(NotificationCenter.groupStickersDidLoad, Long.valueOf(set.set.id));
    }

    private void putSetToCache(final TLRPC.TL_messages_stickerSet set) {
        getMessagesStorage().getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$r-izhl8qBxnP2cxDKFtUaSLXTS0
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$putSetToCache$11$MediaDataController(set);
            }
        });
    }

    public /* synthetic */ void lambda$putSetToCache$11$MediaDataController(TLRPC.TL_messages_stickerSet set) {
        try {
            SQLiteDatabase database = getMessagesStorage().getDatabase();
            SQLitePreparedStatement state = database.executeFast("REPLACE INTO web_recent_v3 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
            state.requery();
            state.bindString(1, "s_" + set.set.id);
            state.bindInteger(2, 6);
            state.bindString(3, "");
            state.bindString(4, "");
            state.bindString(5, "");
            state.bindInteger(6, 0);
            state.bindInteger(7, 0);
            state.bindInteger(8, 0);
            state.bindInteger(9, 0);
            NativeByteBuffer data = new NativeByteBuffer(set.getObjectSize());
            set.serializeToStream(data);
            state.bindByteBuffer(10, data);
            state.step();
            data.reuse();
            state.dispose();
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public HashMap<String, ArrayList<TLRPC.Document>> getAllStickers() {
        return this.allStickers;
    }

    public HashMap<String, ArrayList<TLRPC.Document>> getAllStickersFeatured() {
        return this.allStickersFeatured;
    }

    public TLRPC.Document getEmojiAnimatedSticker(CharSequence message) {
        String emoji = message.toString().replace("️", "");
        ArrayList<TLRPC.TL_messages_stickerSet> arrayList = getStickerSets(4);
        int N = arrayList.size();
        for (int a = 0; a < N; a++) {
            TLRPC.TL_messages_stickerSet set = arrayList.get(a);
            int N2 = set.packs.size();
            for (int b = 0; b < N2; b++) {
                TLRPC.TL_stickerPack pack = set.packs.get(b);
                if (!pack.documents.isEmpty() && TextUtils.equals(pack.emoticon, emoji)) {
                    LongSparseArray<TLRPC.Document> stickerByIds = getStickerByIds(4);
                    return stickerByIds.get(pack.documents.get(0).longValue());
                }
            }
        }
        return null;
    }

    public boolean canAddStickerToFavorites() {
        return (this.stickersLoaded[0] && this.stickerSets[0].size() < 5 && this.recentStickers[2].isEmpty()) ? false : true;
    }

    public ArrayList<TLRPC.TL_messages_stickerSet> getStickerSets(int type) {
        if (type == 3) {
            return this.stickerSets[2];
        }
        return this.stickerSets[type];
    }

    public LongSparseArray<TLRPC.Document> getStickerByIds(int type) {
        return this.stickersByIds[type];
    }

    public ArrayList<TLRPC.StickerSetCovered> getFeaturedStickerSets() {
        return this.featuredStickerSets;
    }

    public ArrayList<Long> getUnreadStickerSets() {
        return this.unreadStickerSets;
    }

    public boolean areAllTrendingStickerSetsUnread() {
        int N = this.featuredStickerSets.size();
        for (int a = 0; a < N; a++) {
            TLRPC.StickerSetCovered pack = this.featuredStickerSets.get(a);
            if (!isStickerPackInstalled(pack.set.id) && ((!pack.covers.isEmpty() || pack.cover != null) && !this.unreadStickerSets.contains(Long.valueOf(pack.set.id)))) {
                return false;
            }
        }
        return true;
    }

    public boolean isStickerPackInstalled(long id) {
        return this.installedStickerSetsById.indexOfKey(id) >= 0;
    }

    public boolean isStickerPackUnread(long id) {
        return this.unreadStickerSets.contains(Long.valueOf(id));
    }

    public boolean isStickerPackInstalled(String name) {
        return this.stickerSetsByName.containsKey(name);
    }

    public String getEmojiForSticker(long id) {
        String value = this.stickersByEmoji.get(id);
        return value != null ? value : "";
    }

    private static int calcDocumentsHash(ArrayList<TLRPC.Document> arrayList) {
        if (arrayList == null) {
            return 0;
        }
        long acc = 0;
        for (int a = 0; a < Math.min(ItemTouchHelper.Callback.DEFAULT_DRAG_ANIMATION_DURATION, arrayList.size()); a++) {
            TLRPC.Document document = arrayList.get(a);
            if (document != null) {
                int high_id = (int) (document.id >> 32);
                int lower_id = (int) document.id;
                acc = (((20261 * ((((acc * 20261) + 2147483648L) + ((long) high_id)) % 2147483648L)) + 2147483648L) + ((long) lower_id)) % 2147483648L;
            }
        }
        int a2 = (int) acc;
        return a2;
    }

    public void loadRecents(final int i, final boolean z, boolean z2, boolean z3) {
        TLObject tLObject;
        long j;
        if (z) {
            if (this.loadingRecentGifs) {
                return;
            }
            this.loadingRecentGifs = true;
            if (this.recentGifsLoaded) {
                z2 = false;
            }
        } else {
            boolean[] zArr = this.loadingRecentStickers;
            if (zArr[i]) {
                return;
            }
            zArr[i] = true;
            if (this.recentStickersLoaded[i]) {
                z2 = false;
            }
        }
        if (z2) {
            getMessagesStorage().getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$Ck-HyULQJoFWNfkgPL3GH77P_9g
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$loadRecents$13$MediaDataController(z, i);
                }
            });
            return;
        }
        SharedPreferences emojiSettings = MessagesController.getEmojiSettings(this.currentAccount);
        if (!z3) {
            if (z) {
                j = emojiSettings.getLong("lastGifLoadTime", 0L);
            } else {
                j = i == 0 ? emojiSettings.getLong("lastStickersLoadTime", 0L) : i == 1 ? emojiSettings.getLong("lastStickersLoadTimeMask", 0L) : emojiSettings.getLong("lastStickersLoadTimeFavs", 0L);
            }
            if (Math.abs(System.currentTimeMillis() - j) < 3600000) {
                if (!z) {
                    this.loadingRecentStickers[i] = false;
                    return;
                } else {
                    this.loadingRecentGifs = false;
                    return;
                }
            }
        }
        if (z) {
            TLRPC.TL_messages_getSavedGifs tL_messages_getSavedGifs = new TLRPC.TL_messages_getSavedGifs();
            tL_messages_getSavedGifs.hash = calcDocumentsHash(this.recentGifs);
            getConnectionsManager().sendRequest(tL_messages_getSavedGifs, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$P8EjQ-gHAER1gCX4mqnL7RYnXYo
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject2, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$loadRecents$14$MediaDataController(i, z, tLObject2, tL_error);
                }
            });
            return;
        }
        if (i == 2) {
            TLRPC.TL_messages_getFavedStickers tL_messages_getFavedStickers = new TLRPC.TL_messages_getFavedStickers();
            tL_messages_getFavedStickers.hash = calcDocumentsHash(this.recentStickers[i]);
            tLObject = tL_messages_getFavedStickers;
        } else {
            TLRPC.TL_messages_getRecentStickers tL_messages_getRecentStickers = new TLRPC.TL_messages_getRecentStickers();
            tL_messages_getRecentStickers.hash = calcDocumentsHash(this.recentStickers[i]);
            tL_messages_getRecentStickers.attached = i == 1;
            tLObject = tL_messages_getRecentStickers;
        }
        getConnectionsManager().sendRequest(tLObject, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$0FSHH8JwlONF51kKmCJOmM3--LM
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject2, TLRPC.TL_error tL_error) {
                this.f$0.lambda$loadRecents$15$MediaDataController(i, z, tLObject2, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$loadRecents$13$MediaDataController(final boolean gif, final int type) {
        int cacheType;
        if (gif) {
            cacheType = 2;
        } else if (type == 0) {
            cacheType = 3;
        } else if (type == 1) {
            cacheType = 4;
        } else {
            cacheType = 5;
        }
        try {
            SQLiteCursor cursor = getMessagesStorage().getDatabase().queryFinalized("SELECT document FROM web_recent_v3 WHERE type = " + cacheType + " ORDER BY date DESC", new Object[0]);
            final ArrayList<TLRPC.Document> arrayList = new ArrayList<>();
            while (cursor.next()) {
                if (!cursor.isNull(0)) {
                    NativeByteBuffer data = cursor.byteBufferValue(0);
                    if (data != null) {
                        TLRPC.Document document = TLRPC.Document.TLdeserialize(data, data.readInt32(false), false);
                        if (document != null) {
                            arrayList.add(document);
                        }
                        data.reuse();
                    }
                }
            }
            cursor.dispose();
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$pfbpH8AOKxc7U0GU0ucz2yl1pzY
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$12$MediaDataController(gif, arrayList, type);
                }
            });
        } catch (Throwable e) {
            FileLog.e(e);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public /* synthetic */ void lambda$null$12$MediaDataController(boolean gif, ArrayList arrayList, int type) {
        if (gif) {
            this.recentGifs = arrayList;
            this.loadingRecentGifs = false;
            this.recentGifsLoaded = true;
        } else {
            this.recentStickers[type] = arrayList;
            this.loadingRecentStickers[type] = false;
            this.recentStickersLoaded[type] = true;
        }
        getNotificationCenter().postNotificationName(NotificationCenter.recentDocumentsDidLoad, Boolean.valueOf(gif), Integer.valueOf(type));
        loadRecents(type, gif, false, false);
    }

    public /* synthetic */ void lambda$loadRecents$14$MediaDataController(int type, boolean gif, TLObject response, TLRPC.TL_error error) {
        ArrayList<TLRPC.Document> arrayList = null;
        if (response instanceof TLRPC.TL_messages_savedGifs) {
            TLRPC.TL_messages_savedGifs res = (TLRPC.TL_messages_savedGifs) response;
            arrayList = res.gifs;
        }
        processLoadedRecentDocuments(type, arrayList, gif, 0, true);
    }

    public /* synthetic */ void lambda$loadRecents$15$MediaDataController(int type, boolean gif, TLObject response, TLRPC.TL_error error) {
        ArrayList<TLRPC.Document> arrayList = null;
        if (type == 2) {
            if (response instanceof TLRPC.TL_messages_favedStickers) {
                TLRPC.TL_messages_favedStickers res = (TLRPC.TL_messages_favedStickers) response;
                arrayList = res.stickers;
            }
        } else if (response instanceof TLRPC.TL_messages_recentStickers) {
            TLRPC.TL_messages_recentStickers res2 = (TLRPC.TL_messages_recentStickers) response;
            arrayList = res2.stickers;
        }
        processLoadedRecentDocuments(type, arrayList, gif, 0, true);
    }

    protected void processLoadedRecentDocuments(final int type, final ArrayList<TLRPC.Document> documents, final boolean gif, final int date, final boolean replace) {
        if (documents != null) {
            getMessagesStorage().getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$-I6AD5KyhOw1u62Al-2x4os1sOE
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$processLoadedRecentDocuments$16$MediaDataController(gif, type, documents, replace, date);
                }
            });
        }
        if (date == 0) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$6zNHAKxT_2_FNmz95uIX6d9kDlU
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$processLoadedRecentDocuments$17$MediaDataController(gif, type, documents);
                }
            });
        }
    }

    public /* synthetic */ void lambda$processLoadedRecentDocuments$16$MediaDataController(boolean gif, int type, ArrayList documents, boolean replace, int date) {
        SQLiteDatabase database = getMessagesStorage().getDatabase();
        if (database == null) {
            return;
        }
        int maxCount = gif ? getMessagesController().maxRecentGifsCount : type == 2 ? getMessagesController().maxFaveStickersCount : getMessagesController().maxRecentStickersCount;
        try {
            database.beginTransaction();
        } catch (Exception e) {
            FileLog.e("processLoadedRecentDocuments ---> exception 1 ", e);
        }
        NativeByteBuffer data = null;
        SQLitePreparedStatement state = null;
        try {
            try {
                SQLitePreparedStatement state2 = database.executeFast("REPLACE INTO web_recent_v3 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
                int count = documents.size();
                int cacheType = gif ? 2 : type == 0 ? 3 : type == 1 ? 4 : 5;
                if (replace) {
                    database.executeFast("DELETE FROM web_recent_v3 WHERE type = " + cacheType).stepThis().dispose();
                }
                for (int a = 0; a < count && a != maxCount; a++) {
                    TLRPC.Document document = (TLRPC.Document) documents.get(a);
                    state2.requery();
                    state2.bindString(1, "" + document.id);
                    state2.bindInteger(2, cacheType);
                    state2.bindString(3, "");
                    state2.bindString(4, "");
                    state2.bindString(5, "");
                    state2.bindInteger(6, 0);
                    state2.bindInteger(7, 0);
                    state2.bindInteger(8, 0);
                    state2.bindInteger(9, date != 0 ? date : count - a);
                    NativeByteBuffer data2 = new NativeByteBuffer(document.getObjectSize());
                    document.serializeToStream(data2);
                    state2.bindByteBuffer(10, data2);
                    state2.step();
                    data2.reuse();
                    data = null;
                }
                state2.dispose();
                state = null;
                database.commitTransaction();
                if (documents.size() >= maxCount) {
                    try {
                        database.beginTransaction();
                    } catch (Exception e2) {
                        FileLog.e("processLoadedRecentDocuments ---> exception 2 ", e2);
                    }
                    for (int a2 = maxCount; a2 < documents.size(); a2++) {
                        database.executeFast("DELETE FROM web_recent_v3 WHERE id = '" + ((TLRPC.Document) documents.get(a2)).id + "' AND type = " + cacheType).stepThis().dispose();
                    }
                    database.commitTransaction();
                }
                if (data != null) {
                    data.reuse();
                }
                if (0 == 0) {
                    return;
                }
            } catch (Exception e3) {
                FileLog.e("processLoadedRecentDocuments ---> exception 3 ", e3);
                if (data != null) {
                    data.reuse();
                }
                if (state == null) {
                    return;
                }
            }
            state.dispose();
        } catch (Throwable th) {
            if (data != null) {
                data.reuse();
            }
            if (state != null) {
                state.dispose();
            }
            throw th;
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public /* synthetic */ void lambda$processLoadedRecentDocuments$17$MediaDataController(boolean gif, int type, ArrayList documents) {
        SharedPreferences.Editor editor = MessagesController.getEmojiSettings(this.currentAccount).edit();
        if (!gif) {
            this.loadingRecentStickers[type] = false;
            this.recentStickersLoaded[type] = true;
            if (type == 0) {
                editor.putLong("lastStickersLoadTime", System.currentTimeMillis()).commit();
            } else if (type == 1) {
                editor.putLong("lastStickersLoadTimeMask", System.currentTimeMillis()).commit();
            } else {
                editor.putLong("lastStickersLoadTimeFavs", System.currentTimeMillis()).commit();
            }
        } else {
            this.loadingRecentGifs = false;
            this.recentGifsLoaded = true;
            editor.putLong("lastGifLoadTime", System.currentTimeMillis()).commit();
        }
        if (documents != null) {
            if (gif) {
                this.recentGifs = documents;
            } else {
                this.recentStickers[type] = documents;
            }
            getNotificationCenter().postNotificationName(NotificationCenter.recentDocumentsDidLoad, Boolean.valueOf(gif), Integer.valueOf(type));
        }
    }

    public void reorderStickers(int type, final ArrayList<Long> order) {
        Collections.sort(this.stickerSets[type], new Comparator() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$tz_E0WsDFcssCMdSnI0QRuisNEQ
            @Override // java.util.Comparator
            public final int compare(Object obj, Object obj2) {
                return MediaDataController.lambda$reorderStickers$18(order, (TLRPC.TL_messages_stickerSet) obj, (TLRPC.TL_messages_stickerSet) obj2);
            }
        });
        this.loadHash[type] = calcStickersHash(this.stickerSets[type]);
        getNotificationCenter().postNotificationName(NotificationCenter.stickersDidLoad, Integer.valueOf(type));
        loadStickers(type, false, true);
    }

    static /* synthetic */ int lambda$reorderStickers$18(ArrayList order, TLRPC.TL_messages_stickerSet lhs, TLRPC.TL_messages_stickerSet rhs) {
        int index1 = order.indexOf(Long.valueOf(lhs.set.id));
        int index2 = order.indexOf(Long.valueOf(rhs.set.id));
        if (index1 > index2) {
            return 1;
        }
        if (index1 < index2) {
            return -1;
        }
        return 0;
    }

    public void calcNewHash(int type) {
        this.loadHash[type] = calcStickersHash(this.stickerSets[type]);
    }

    public void addNewStickerSet(TLRPC.TL_messages_stickerSet tL_messages_stickerSet) {
        if (this.stickerSetsById.indexOfKey(tL_messages_stickerSet.set.id) >= 0 || this.stickerSetsByName.containsKey(tL_messages_stickerSet.set.short_name)) {
            return;
        }
        boolean z = tL_messages_stickerSet.set.masks;
        this.stickerSets[z ? 1 : 0].add(0, tL_messages_stickerSet);
        this.stickerSetsById.put(tL_messages_stickerSet.set.id, tL_messages_stickerSet);
        this.installedStickerSetsById.put(tL_messages_stickerSet.set.id, tL_messages_stickerSet);
        this.stickerSetsByName.put(tL_messages_stickerSet.set.short_name, tL_messages_stickerSet);
        LongSparseArray longSparseArray = new LongSparseArray();
        for (int i = 0; i < tL_messages_stickerSet.documents.size(); i++) {
            TLRPC.Document document = tL_messages_stickerSet.documents.get(i);
            longSparseArray.put(document.id, document);
        }
        for (int i2 = 0; i2 < tL_messages_stickerSet.packs.size(); i2++) {
            TLRPC.TL_stickerPack tL_stickerPack = tL_messages_stickerSet.packs.get(i2);
            tL_stickerPack.emoticon = tL_stickerPack.emoticon.replace("️", "");
            ArrayList<TLRPC.Document> arrayList = this.allStickers.get(tL_stickerPack.emoticon);
            if (arrayList == null) {
                arrayList = new ArrayList<>();
                this.allStickers.put(tL_stickerPack.emoticon, arrayList);
            }
            for (int i3 = 0; i3 < tL_stickerPack.documents.size(); i3++) {
                Long l = tL_stickerPack.documents.get(i3);
                if (this.stickersByEmoji.indexOfKey(l.longValue()) < 0) {
                    this.stickersByEmoji.put(l.longValue(), tL_stickerPack.emoticon);
                }
                TLRPC.Document document2 = (TLRPC.Document) longSparseArray.get(l.longValue());
                if (document2 != null) {
                    arrayList.add(document2);
                }
            }
        }
        this.loadHash[z ? 1 : 0] = calcStickersHash(this.stickerSets[z ? 1 : 0]);
        getNotificationCenter().postNotificationName(NotificationCenter.stickersDidLoad, Integer.valueOf(z ? 1 : 0));
        loadStickers(z ? 1 : 0, false, true);
    }

    public void loadFeaturedStickers(boolean cache, boolean force) {
        if (this.loadingFeaturedStickers) {
            return;
        }
        this.loadingFeaturedStickers = true;
        if (cache) {
            getMessagesStorage().getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$_yBfqEOdolZycDiuebQ0GHbPoJ0
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$loadFeaturedStickers$19$MediaDataController();
                }
            });
            return;
        }
        final TLRPC.TL_messages_getFeaturedStickers req = new TLRPC.TL_messages_getFeaturedStickers();
        req.hash = force ? 0 : this.loadFeaturedHash;
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$1ll6y8qpTlO9rEWNYKXlasCL9bg
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$loadFeaturedStickers$21$MediaDataController(req, tLObject, tL_error);
            }
        });
    }

    /* JADX WARN: Removed duplicated region for block: B:24:0x007a A[DONT_GENERATE, PHI: r0 r2 r3 r4
      0x007a: PHI (r0v2 'newStickerArray' java.util.ArrayList<im.uwrkaxlmjj.tgnet.TLRPC$StickerSetCovered>) = 
      (r0v1 'newStickerArray' java.util.ArrayList<im.uwrkaxlmjj.tgnet.TLRPC$StickerSetCovered>)
      (r0v4 'newStickerArray' java.util.ArrayList<im.uwrkaxlmjj.tgnet.TLRPC$StickerSetCovered>)
     binds: [B:23:0x0078, B:19:0x0071] A[DONT_GENERATE, DONT_INLINE]
      0x007a: PHI (r2v2 'date' int) = (r2v1 'date' int), (r2v5 'date' int) binds: [B:23:0x0078, B:19:0x0071] A[DONT_GENERATE, DONT_INLINE]
      0x007a: PHI (r3v1 'hash' int) = (r3v0 'hash' int), (r3v4 'hash' int) binds: [B:23:0x0078, B:19:0x0071] A[DONT_GENERATE, DONT_INLINE]
      0x007a: PHI (r4v2 'cursor' im.uwrkaxlmjj.sqlite.SQLiteCursor) = (r4v1 'cursor' im.uwrkaxlmjj.sqlite.SQLiteCursor), (r4v5 'cursor' im.uwrkaxlmjj.sqlite.SQLiteCursor) binds: [B:23:0x0078, B:19:0x0071] A[DONT_GENERATE, DONT_INLINE]] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public /* synthetic */ void lambda$loadFeaturedStickers$19$MediaDataController() {
        /*
            r11 = this;
            r0 = 0
            java.util.ArrayList r1 = new java.util.ArrayList
            r1.<init>()
            r2 = 0
            r3 = 0
            r4 = 0
            im.uwrkaxlmjj.messenger.MessagesStorage r5 = r11.getMessagesStorage()     // Catch: java.lang.Throwable -> L74
            im.uwrkaxlmjj.sqlite.SQLiteDatabase r5 = r5.getDatabase()     // Catch: java.lang.Throwable -> L74
            java.lang.String r6 = "SELECT data, unread, date, hash FROM stickers_featured WHERE 1"
            r7 = 0
            java.lang.Object[] r8 = new java.lang.Object[r7]     // Catch: java.lang.Throwable -> L74
            im.uwrkaxlmjj.sqlite.SQLiteCursor r5 = r5.queryFinalized(r6, r8)     // Catch: java.lang.Throwable -> L74
            r4 = r5
            boolean r5 = r4.next()     // Catch: java.lang.Throwable -> L74
            if (r5 == 0) goto L71
            im.uwrkaxlmjj.tgnet.NativeByteBuffer r5 = r4.byteBufferValue(r7)     // Catch: java.lang.Throwable -> L74
            if (r5 == 0) goto L46
            java.util.ArrayList r6 = new java.util.ArrayList     // Catch: java.lang.Throwable -> L74
            r6.<init>()     // Catch: java.lang.Throwable -> L74
            r0 = r6
            int r6 = r5.readInt32(r7)     // Catch: java.lang.Throwable -> L74
            r8 = 0
        L32:
            if (r8 >= r6) goto L43
            int r9 = r5.readInt32(r7)     // Catch: java.lang.Throwable -> L74
            im.uwrkaxlmjj.tgnet.TLRPC$StickerSetCovered r9 = im.uwrkaxlmjj.tgnet.TLRPC.StickerSetCovered.TLdeserialize(r5, r9, r7)     // Catch: java.lang.Throwable -> L74
            r0.add(r9)     // Catch: java.lang.Throwable -> L74
            int r8 = r8 + 1
            goto L32
        L43:
            r5.reuse()     // Catch: java.lang.Throwable -> L74
        L46:
            r6 = 1
            im.uwrkaxlmjj.tgnet.NativeByteBuffer r6 = r4.byteBufferValue(r6)     // Catch: java.lang.Throwable -> L74
            r5 = r6
            if (r5 == 0) goto L66
            int r6 = r5.readInt32(r7)     // Catch: java.lang.Throwable -> L74
            r8 = 0
        L53:
            if (r8 >= r6) goto L63
            long r9 = r5.readInt64(r7)     // Catch: java.lang.Throwable -> L74
            java.lang.Long r9 = java.lang.Long.valueOf(r9)     // Catch: java.lang.Throwable -> L74
            r1.add(r9)     // Catch: java.lang.Throwable -> L74
            int r8 = r8 + 1
            goto L53
        L63:
            r5.reuse()     // Catch: java.lang.Throwable -> L74
        L66:
            r6 = 2
            int r6 = r4.intValue(r6)     // Catch: java.lang.Throwable -> L74
            r2 = r6
            int r6 = r11.calcFeaturedStickersHash(r0)     // Catch: java.lang.Throwable -> L74
            r3 = r6
        L71:
            if (r4 == 0) goto L7d
            goto L7a
        L74:
            r5 = move-exception
            im.uwrkaxlmjj.messenger.FileLog.e(r5)     // Catch: java.lang.Throwable -> L8a
            if (r4 == 0) goto L7d
        L7a:
            r4.dispose()
        L7d:
            r8 = r2
            r9 = r3
            r10 = r4
            r5 = 1
            r2 = r11
            r3 = r0
            r4 = r1
            r6 = r8
            r7 = r9
            r2.processLoadedFeaturedStickers(r3, r4, r5, r6, r7)
            return
        L8a:
            r5 = move-exception
            if (r4 == 0) goto L90
            r4.dispose()
        L90:
            throw r5
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MediaDataController.lambda$loadFeaturedStickers$19$MediaDataController():void");
    }

    public /* synthetic */ void lambda$loadFeaturedStickers$21$MediaDataController(final TLRPC.TL_messages_getFeaturedStickers req, final TLObject response, TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$_PcaYGyW0L_vD-ovi8kRXzwIpEM
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$20$MediaDataController(response, req);
            }
        });
    }

    public /* synthetic */ void lambda$null$20$MediaDataController(TLObject response, TLRPC.TL_messages_getFeaturedStickers req) {
        if (response instanceof TLRPC.TL_messages_featuredStickers) {
            TLRPC.TL_messages_featuredStickers res = (TLRPC.TL_messages_featuredStickers) response;
            processLoadedFeaturedStickers(res.sets, res.unread, false, (int) (System.currentTimeMillis() / 1000), res.hash);
        } else {
            processLoadedFeaturedStickers(null, null, false, (int) (System.currentTimeMillis() / 1000), req.hash);
        }
    }

    private void processLoadedFeaturedStickers(final ArrayList<TLRPC.StickerSetCovered> res, final ArrayList<Long> unreadStickers, final boolean cache, final int date, final int hash) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$FKoWBKxv4Wv9rhEHGp0FqCcn5zQ
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$processLoadedFeaturedStickers$22$MediaDataController();
            }
        });
        Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$V1SALhaG43BkRxXQvNYCZbQcjII
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$processLoadedFeaturedStickers$26$MediaDataController(cache, res, date, hash, unreadStickers);
            }
        });
    }

    public /* synthetic */ void lambda$processLoadedFeaturedStickers$22$MediaDataController() {
        this.loadingFeaturedStickers = false;
        this.featuredStickersLoaded = true;
    }

    public /* synthetic */ void lambda$processLoadedFeaturedStickers$26$MediaDataController(boolean cache, final ArrayList res, final int date, final int hash, final ArrayList unreadStickers) {
        if ((cache && (res == null || Math.abs((System.currentTimeMillis() / 1000) - ((long) date)) >= 3600)) || (!cache && res == null && hash == 0)) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$_WBc9OAHG7GM5XQkW9rclevaPz4
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$23$MediaDataController(res, hash);
                }
            }, (res != null || cache) ? 0L : 1000L);
            if (res == null) {
                return;
            }
        }
        if (res != null) {
            try {
                final ArrayList<TLRPC.StickerSetCovered> stickerSetsNew = new ArrayList<>();
                final LongSparseArray<TLRPC.StickerSetCovered> stickerSetsByIdNew = new LongSparseArray<>();
                for (int a = 0; a < res.size(); a++) {
                    TLRPC.StickerSetCovered stickerSet = (TLRPC.StickerSetCovered) res.get(a);
                    stickerSetsNew.add(stickerSet);
                    stickerSetsByIdNew.put(stickerSet.set.id, stickerSet);
                }
                if (!cache) {
                    putFeaturedStickersToCache(stickerSetsNew, unreadStickers, date, hash);
                }
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$fjnMrAUn4jfwjs-W9G19qJj4DLw
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$24$MediaDataController(unreadStickers, stickerSetsByIdNew, stickerSetsNew, hash, date);
                    }
                });
                return;
            } catch (Throwable e) {
                FileLog.e(e);
                return;
            }
        }
        if (!cache) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$FxbfdAGUzwdO72uJxhWxigahjaQ
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$25$MediaDataController(date);
                }
            });
            putFeaturedStickersToCache(null, null, date, 0);
        }
    }

    public /* synthetic */ void lambda$null$23$MediaDataController(ArrayList res, int hash) {
        if (res != null && hash != 0) {
            this.loadFeaturedHash = hash;
        }
        loadFeaturedStickers(false, false);
    }

    public /* synthetic */ void lambda$null$24$MediaDataController(ArrayList unreadStickers, LongSparseArray stickerSetsByIdNew, ArrayList stickerSetsNew, int hash, int date) {
        this.unreadStickerSets = unreadStickers;
        this.featuredStickerSetsById = stickerSetsByIdNew;
        this.featuredStickerSets = stickerSetsNew;
        this.loadFeaturedHash = hash;
        this.loadFeaturedDate = date;
        loadStickers(3, true, false);
        getNotificationCenter().postNotificationName(NotificationCenter.featuredStickersDidLoad, new Object[0]);
    }

    public /* synthetic */ void lambda$null$25$MediaDataController(int date) {
        this.loadFeaturedDate = date;
    }

    private void putFeaturedStickersToCache(ArrayList<TLRPC.StickerSetCovered> stickers, final ArrayList<Long> unreadStickers, final int date, final int hash) {
        final ArrayList<TLRPC.StickerSetCovered> stickersFinal = stickers != null ? new ArrayList<>(stickers) : null;
        getMessagesStorage().getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$_UMpkiiHYpLo-oUfpeR7UHfwHe8
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$putFeaturedStickersToCache$27$MediaDataController(stickersFinal, unreadStickers, date, hash);
            }
        });
    }

    public /* synthetic */ void lambda$putFeaturedStickersToCache$27$MediaDataController(ArrayList stickersFinal, ArrayList unreadStickers, int date, int hash) {
        try {
            if (stickersFinal != null) {
                SQLitePreparedStatement state = getMessagesStorage().getDatabase().executeFast("REPLACE INTO stickers_featured VALUES(?, ?, ?, ?, ?)");
                state.requery();
                int size = 4;
                for (int a = 0; a < stickersFinal.size(); a++) {
                    size += ((TLRPC.StickerSetCovered) stickersFinal.get(a)).getObjectSize();
                }
                NativeByteBuffer data = new NativeByteBuffer(size);
                NativeByteBuffer data2 = new NativeByteBuffer((unreadStickers.size() * 8) + 4);
                data.writeInt32(stickersFinal.size());
                for (int a2 = 0; a2 < stickersFinal.size(); a2++) {
                    ((TLRPC.StickerSetCovered) stickersFinal.get(a2)).serializeToStream(data);
                }
                int a3 = unreadStickers.size();
                data2.writeInt32(a3);
                for (int a4 = 0; a4 < unreadStickers.size(); a4++) {
                    data2.writeInt64(((Long) unreadStickers.get(a4)).longValue());
                }
                state.bindInteger(1, 1);
                state.bindByteBuffer(2, data);
                state.bindByteBuffer(3, data2);
                state.bindInteger(4, date);
                state.bindInteger(5, hash);
                state.step();
                data.reuse();
                data2.reuse();
                state.dispose();
                return;
            }
            SQLitePreparedStatement state2 = getMessagesStorage().getDatabase().executeFast("UPDATE stickers_featured SET date = ?");
            state2.requery();
            state2.bindInteger(1, date);
            state2.step();
            state2.dispose();
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    private int calcFeaturedStickersHash(ArrayList<TLRPC.StickerSetCovered> sets) {
        long acc = 0;
        for (int a = 0; a < sets.size(); a++) {
            TLRPC.StickerSet set = sets.get(a).set;
            if (!set.archived) {
                int high_id = (int) (set.id >> 32);
                int lower_id = (int) set.id;
                acc = (((((((acc * 20261) + 2147483648L) + ((long) high_id)) % 2147483648L) * 20261) + 2147483648L) + ((long) lower_id)) % 2147483648L;
                if (this.unreadStickerSets.contains(Long.valueOf(set.id))) {
                    acc = (((20261 * acc) + 2147483648L) + 1) % 2147483648L;
                }
            }
        }
        int a2 = (int) acc;
        return a2;
    }

    public void markFaturedStickersAsRead(boolean query) {
        if (this.unreadStickerSets.isEmpty()) {
            return;
        }
        this.unreadStickerSets.clear();
        this.loadFeaturedHash = calcFeaturedStickersHash(this.featuredStickerSets);
        getNotificationCenter().postNotificationName(NotificationCenter.featuredStickersDidLoad, new Object[0]);
        putFeaturedStickersToCache(this.featuredStickerSets, this.unreadStickerSets, this.loadFeaturedDate, this.loadFeaturedHash);
        if (query) {
            TLRPC.TL_messages_readFeaturedStickers req = new TLRPC.TL_messages_readFeaturedStickers();
            getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$5hD_3JwbKx5FP68lBfk6gRZ5FO8
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    MediaDataController.lambda$markFaturedStickersAsRead$28(tLObject, tL_error);
                }
            });
        }
    }

    static /* synthetic */ void lambda$markFaturedStickersAsRead$28(TLObject response, TLRPC.TL_error error) {
    }

    public int getFeaturesStickersHashWithoutUnread() {
        long acc = 0;
        for (int a = 0; a < this.featuredStickerSets.size(); a++) {
            TLRPC.StickerSet set = this.featuredStickerSets.get(a).set;
            if (!set.archived) {
                int high_id = (int) (set.id >> 32);
                int lower_id = (int) set.id;
                acc = (((20261 * ((((acc * 20261) + 2147483648L) + ((long) high_id)) % 2147483648L)) + 2147483648L) + ((long) lower_id)) % 2147483648L;
            }
        }
        int a2 = (int) acc;
        return a2;
    }

    public void markFaturedStickersByIdAsRead(final long id) {
        if (!this.unreadStickerSets.contains(Long.valueOf(id)) || this.readingStickerSets.contains(Long.valueOf(id))) {
            return;
        }
        this.readingStickerSets.add(Long.valueOf(id));
        TLRPC.TL_messages_readFeaturedStickers req = new TLRPC.TL_messages_readFeaturedStickers();
        req.id.add(Long.valueOf(id));
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$MR9vEPn6WkFi3bahP-LqifgjR74
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                MediaDataController.lambda$markFaturedStickersByIdAsRead$29(tLObject, tL_error);
            }
        });
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$J9bkwjOxTP8XVqirixKdrMa1oyc
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$markFaturedStickersByIdAsRead$30$MediaDataController(id);
            }
        }, 1000L);
    }

    static /* synthetic */ void lambda$markFaturedStickersByIdAsRead$29(TLObject response, TLRPC.TL_error error) {
    }

    public /* synthetic */ void lambda$markFaturedStickersByIdAsRead$30$MediaDataController(long id) {
        this.unreadStickerSets.remove(Long.valueOf(id));
        this.readingStickerSets.remove(Long.valueOf(id));
        this.loadFeaturedHash = calcFeaturedStickersHash(this.featuredStickerSets);
        getNotificationCenter().postNotificationName(NotificationCenter.featuredStickersDidLoad, new Object[0]);
        putFeaturedStickersToCache(this.featuredStickerSets, this.unreadStickerSets, this.loadFeaturedDate, this.loadFeaturedHash);
    }

    public int getArchivedStickersCount(int type) {
        return this.archivedStickersCount[type];
    }

    public void loadArchivedStickersCount(final int type, boolean cache) {
        if (cache) {
            SharedPreferences preferences = MessagesController.getNotificationsSettings(this.currentAccount);
            int count = preferences.getInt("archivedStickersCount" + type, -1);
            if (count == -1) {
                loadArchivedStickersCount(type, false);
                return;
            } else {
                this.archivedStickersCount[type] = count;
                getNotificationCenter().postNotificationName(NotificationCenter.archivedStickersCountDidLoad, Integer.valueOf(type));
                return;
            }
        }
        TLRPC.TL_messages_getArchivedStickers req = new TLRPC.TL_messages_getArchivedStickers();
        req.limit = 0;
        req.masks = type == 1;
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$eG_8M_KG3f0XmUxYKQvrP_PECWk
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$loadArchivedStickersCount$32$MediaDataController(type, tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$loadArchivedStickersCount$32$MediaDataController(final int type, final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$VUTYdCQ1McD8RvT6WnQJRjs3OF0
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$31$MediaDataController(error, response, type);
            }
        });
    }

    public /* synthetic */ void lambda$null$31$MediaDataController(TLRPC.TL_error error, TLObject response, int type) {
        if (error == null) {
            TLRPC.TL_messages_archivedStickers res = (TLRPC.TL_messages_archivedStickers) response;
            this.archivedStickersCount[type] = res.count;
            SharedPreferences preferences = MessagesController.getNotificationsSettings(this.currentAccount);
            preferences.edit().putInt("archivedStickersCount" + type, res.count).commit();
            getNotificationCenter().postNotificationName(NotificationCenter.archivedStickersCountDidLoad, Integer.valueOf(type));
        }
    }

    private void processLoadStickersResponse(final int type, final TLRPC.TL_messages_allStickers res) {
        TLRPC.TL_messages_allStickers tL_messages_allStickers = res;
        final ArrayList<TLRPC.TL_messages_stickerSet> newStickerArray = new ArrayList<>();
        long j = 1000;
        if (tL_messages_allStickers.sets.isEmpty()) {
            processLoadedStickers(type, newStickerArray, false, (int) (System.currentTimeMillis() / 1000), tL_messages_allStickers.hash);
            return;
        }
        final LongSparseArray<TLRPC.TL_messages_stickerSet> newStickerSets = new LongSparseArray<>();
        int a = 0;
        while (a < tL_messages_allStickers.sets.size()) {
            final TLRPC.StickerSet stickerSet = tL_messages_allStickers.sets.get(a);
            TLRPC.TL_messages_stickerSet oldSet = this.stickerSetsById.get(stickerSet.id);
            if (oldSet != null && oldSet.set.hash == stickerSet.hash) {
                oldSet.set.archived = stickerSet.archived;
                oldSet.set.installed = stickerSet.installed;
                oldSet.set.official = stickerSet.official;
                newStickerSets.put(oldSet.set.id, oldSet);
                newStickerArray.add(oldSet);
                if (newStickerSets.size() == tL_messages_allStickers.sets.size()) {
                    processLoadedStickers(type, newStickerArray, false, (int) (System.currentTimeMillis() / j), tL_messages_allStickers.hash);
                }
            } else {
                newStickerArray.add(null);
                final int index = a;
                TLRPC.TL_messages_getStickerSet req = new TLRPC.TL_messages_getStickerSet();
                req.stickerset = new TLRPC.TL_inputStickerSetID();
                req.stickerset.id = stickerSet.id;
                req.stickerset.access_hash = stickerSet.access_hash;
                getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$Mg2rb1fzntJLqTxedAzC6YLHcdU
                    @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                    public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                        this.f$0.lambda$processLoadStickersResponse$34$MediaDataController(newStickerArray, index, newStickerSets, stickerSet, res, type, tLObject, tL_error);
                    }
                });
            }
            a++;
            tL_messages_allStickers = res;
            j = 1000;
        }
    }

    public /* synthetic */ void lambda$processLoadStickersResponse$34$MediaDataController(final ArrayList newStickerArray, final int index, final LongSparseArray newStickerSets, final TLRPC.StickerSet stickerSet, final TLRPC.TL_messages_allStickers res, final int type, final TLObject response, TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$Fm3My2FhmRMNK2QfSDhXxYW-h-0
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$33$MediaDataController(response, newStickerArray, index, newStickerSets, stickerSet, res, type);
            }
        });
    }

    public /* synthetic */ void lambda$null$33$MediaDataController(TLObject response, ArrayList newStickerArray, int index, LongSparseArray newStickerSets, TLRPC.StickerSet stickerSet, TLRPC.TL_messages_allStickers res, int type) {
        TLRPC.TL_messages_stickerSet res1 = (TLRPC.TL_messages_stickerSet) response;
        newStickerArray.set(index, res1);
        newStickerSets.put(stickerSet.id, res1);
        if (newStickerSets.size() == res.sets.size()) {
            Iterator<TLRPC.TL_messages_stickerSet> iterator = newStickerArray.iterator();
            while (iterator.hasNext()) {
                TLRPC.TL_messages_stickerSet set = iterator.next();
                if (set == null) {
                    iterator.remove();
                } else if (!isStickerPackInstalled(set.set.id) && set.set.id != installingStickerSetId) {
                    iterator.remove();
                }
            }
            processLoadedStickers(type, newStickerArray, false, (int) (System.currentTimeMillis() / 1000), res.hash);
        }
    }

    public void installStickerSet(Context context, final int type, TLRPC.StickerSetCovered stickerSet) {
        if (stickerSet.set == null || !isStickerPackInstalled(stickerSet.set.id)) {
            installingStickerSetId = stickerSet.set.id;
            TLRPC.TL_messages_installStickerSet req = new TLRPC.TL_messages_installStickerSet();
            TLRPC.InputStickerSet inputStickerSet = new TLRPC.TL_inputStickerSetID();
            inputStickerSet.id = stickerSet.set.id;
            inputStickerSet.access_hash = stickerSet.set.access_hash;
            req.stickerset = inputStickerSet;
            ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$MtpXNYcR4zRNgjxT0vaaanWS9Sw
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$installStickerSet$36$MediaDataController(type, tLObject, tL_error);
                }
            });
        }
    }

    public /* synthetic */ void lambda$installStickerSet$36$MediaDataController(final int type, final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$W_aG8iDFq2RQUXbeRQEjhdCdbgw
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$35$MediaDataController(error, response, type);
            }
        });
    }

    public /* synthetic */ void lambda$null$35$MediaDataController(TLRPC.TL_error error, TLObject response, int type) {
        try {
            if (error == null) {
                if (response instanceof TLRPC.TL_messages_stickerSetInstallResultArchive) {
                    NotificationCenter.getInstance(this.currentAccount).postNotificationName(NotificationCenter.needReloadArchivedStickers, new Object[0]);
                }
            } else {
                ToastUtils.show(mpEIGo.juqQQs.esbSDO.R.string.ErrorOccurred);
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
        loadStickers(type, false, true);
    }

    public void loadStickers(final int type, boolean cache, boolean force) {
        TLObject req;
        final int hash;
        if (this.loadingStickers[type]) {
            return;
        }
        if (type == 3) {
            if (this.featuredStickerSets.isEmpty() || !getMessagesController().preloadFeaturedStickers) {
                return;
            }
        } else if (type != 4) {
            loadArchivedStickersCount(type, cache);
        }
        this.loadingStickers[type] = true;
        if (cache) {
            getMessagesStorage().getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$eZQteeDPFji5kiRAUUL4Jecv5oQ
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$loadStickers$37$MediaDataController(type);
                }
            });
            return;
        }
        if (type != 3) {
            if (type == 4) {
                TLRPC.TL_messages_getStickerSet req2 = new TLRPC.TL_messages_getStickerSet();
                req2.stickerset = new TLRPC.TL_inputStickerSetAnimatedEmoji();
                getConnectionsManager().sendRequest(req2, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$G-Md57lY7fZXWrgeJZ5BHSx4GuI
                    @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                    public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                        this.f$0.lambda$loadStickers$38$MediaDataController(type, tLObject, tL_error);
                    }
                });
                return;
            }
            if (type == 0) {
                req = new TLRPC.TL_messages_getAllStickers();
                TLRPC.TL_messages_getAllStickers tL_messages_getAllStickers = (TLRPC.TL_messages_getAllStickers) req;
                hash = force ? 0 : this.loadHash[type];
                tL_messages_getAllStickers.hash = hash;
            } else {
                req = new TLRPC.TL_messages_getMaskStickers();
                TLRPC.TL_messages_getMaskStickers tL_messages_getMaskStickers = (TLRPC.TL_messages_getMaskStickers) req;
                hash = force ? 0 : this.loadHash[type];
                tL_messages_getMaskStickers.hash = hash;
            }
            getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$HruNK_rVd7aij5rEriA63o9S5dI
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$loadStickers$40$MediaDataController(type, hash, tLObject, tL_error);
                }
            });
            return;
        }
        TLRPC.TL_messages_allStickers response = new TLRPC.TL_messages_allStickers();
        response.hash = this.loadFeaturedHash;
        int size = this.featuredStickerSets.size();
        for (int a = 0; a < size; a++) {
            response.sets.add(this.featuredStickerSets.get(a).set);
        }
        processLoadStickersResponse(type, response);
    }

    public /* synthetic */ void lambda$loadStickers$37$MediaDataController(int type) {
        ArrayList<TLRPC.TL_messages_stickerSet> newStickerArray = null;
        int date = 0;
        int hash = 0;
        SQLiteCursor cursor = null;
        try {
            cursor = getMessagesStorage().getDatabase().queryFinalized("SELECT data, date, hash FROM stickers_v2 WHERE id = " + (type + 1), new Object[0]);
            if (cursor.next()) {
                NativeByteBuffer data = cursor.byteBufferValue(0);
                if (data != null) {
                    newStickerArray = new ArrayList<>();
                    int count = data.readInt32(false);
                    for (int a = 0; a < count; a++) {
                        TLRPC.TL_messages_stickerSet stickerSet = TLRPC.TL_messages_stickerSet.TLdeserialize(data, data.readInt32(false), false);
                        newStickerArray.add(stickerSet);
                    }
                    data.reuse();
                }
                date = cursor.intValue(1);
                hash = calcStickersHash(newStickerArray);
            }
        } catch (Throwable e) {
            try {
                FileLog.e(e);
                if (cursor != null) {
                }
            } finally {
                if (cursor != null) {
                    cursor.dispose();
                }
            }
        }
        processLoadedStickers(type, newStickerArray, true, date, hash);
    }

    public /* synthetic */ void lambda$loadStickers$38$MediaDataController(int type, TLObject response, TLRPC.TL_error error) {
        if (response instanceof TLRPC.TL_messages_stickerSet) {
            ArrayList<TLRPC.TL_messages_stickerSet> newStickerArray = new ArrayList<>();
            newStickerArray.add((TLRPC.TL_messages_stickerSet) response);
            processLoadedStickers(type, newStickerArray, false, (int) (System.currentTimeMillis() / 1000), calcStickersHash(newStickerArray));
            return;
        }
        processLoadedStickers(type, null, false, (int) (System.currentTimeMillis() / 1000), 0);
    }

    public /* synthetic */ void lambda$loadStickers$40$MediaDataController(final int type, final int hash, final TLObject response, TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$fCcm7g3WEeKAVAJJvVlYamy86ww
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$39$MediaDataController(response, type, hash);
            }
        });
    }

    public /* synthetic */ void lambda$null$39$MediaDataController(TLObject response, int type, int hash) {
        if (response instanceof TLRPC.TL_messages_allStickers) {
            processLoadStickersResponse(type, (TLRPC.TL_messages_allStickers) response);
        } else {
            processLoadedStickers(type, null, false, (int) (System.currentTimeMillis() / 1000), hash);
        }
    }

    private void putStickersToCache(final int type, ArrayList<TLRPC.TL_messages_stickerSet> stickers, final int date, final int hash) {
        final ArrayList<TLRPC.TL_messages_stickerSet> stickersFinal = stickers != null ? new ArrayList<>(stickers) : null;
        getMessagesStorage().getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$Qx49y318j0NbpqidYfbJkDql7Cw
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$putStickersToCache$41$MediaDataController(stickersFinal, type, date, hash);
            }
        });
    }

    public /* synthetic */ void lambda$putStickersToCache$41$MediaDataController(ArrayList stickersFinal, int type, int date, int hash) {
        try {
            if (stickersFinal != null) {
                SQLitePreparedStatement state = getMessagesStorage().getDatabase().executeFast("REPLACE INTO stickers_v2 VALUES(?, ?, ?, ?)");
                state.requery();
                int size = 4;
                for (int a = 0; a < stickersFinal.size(); a++) {
                    size += ((TLRPC.TL_messages_stickerSet) stickersFinal.get(a)).getObjectSize();
                }
                NativeByteBuffer data = new NativeByteBuffer(size);
                data.writeInt32(stickersFinal.size());
                for (int a2 = 0; a2 < stickersFinal.size(); a2++) {
                    ((TLRPC.TL_messages_stickerSet) stickersFinal.get(a2)).serializeToStream(data);
                }
                int a3 = type + 1;
                state.bindInteger(1, a3);
                state.bindByteBuffer(2, data);
                state.bindInteger(3, date);
                state.bindInteger(4, hash);
                state.step();
                data.reuse();
                state.dispose();
                return;
            }
            SQLitePreparedStatement state2 = getMessagesStorage().getDatabase().executeFast("UPDATE stickers_v2 SET date = ?");
            state2.requery();
            state2.bindInteger(1, date);
            state2.step();
            state2.dispose();
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public String getStickerSetName(long setId) {
        TLRPC.TL_messages_stickerSet stickerSet = this.stickerSetsById.get(setId);
        if (stickerSet != null) {
            return stickerSet.set.short_name;
        }
        TLRPC.StickerSetCovered stickerSetCovered = this.featuredStickerSetsById.get(setId);
        if (stickerSetCovered != null) {
            return stickerSetCovered.set.short_name;
        }
        return null;
    }

    public static long getStickerSetId(TLRPC.Document document) {
        for (int a = 0; a < document.attributes.size(); a++) {
            TLRPC.DocumentAttribute attribute = document.attributes.get(a);
            if (attribute instanceof TLRPC.TL_documentAttributeSticker) {
                if (attribute.stickerset instanceof TLRPC.TL_inputStickerSetID) {
                    return attribute.stickerset.id;
                }
                return -1L;
            }
        }
        return -1L;
    }

    public static TLRPC.InputStickerSet getInputStickerSet(TLRPC.Document document) {
        for (int a = 0; a < document.attributes.size(); a++) {
            TLRPC.DocumentAttribute attribute = document.attributes.get(a);
            if (attribute instanceof TLRPC.TL_documentAttributeSticker) {
                if (attribute.stickerset instanceof TLRPC.TL_inputStickerSetEmpty) {
                    return null;
                }
                return attribute.stickerset;
            }
        }
        return null;
    }

    private static int calcStickersHash(ArrayList<TLRPC.TL_messages_stickerSet> sets) {
        long acc = 0;
        for (int a = 0; a < sets.size(); a++) {
            TLRPC.StickerSet set = sets.get(a).set;
            if (!set.archived) {
                acc = (((20261 * acc) + 2147483648L) + ((long) set.hash)) % 2147483648L;
            }
        }
        int a2 = (int) acc;
        return a2;
    }

    private void processLoadedStickers(final int type, final ArrayList<TLRPC.TL_messages_stickerSet> res, final boolean cache, final int date, final int hash) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$HwZCvHNLs27_ofYCWtUDCn37m5I
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$processLoadedStickers$42$MediaDataController(type);
            }
        });
        Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$x0_wKSjxfWiopb-_OcT7KnLd87g
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$processLoadedStickers$46$MediaDataController(cache, res, date, hash, type);
            }
        });
    }

    public /* synthetic */ void lambda$processLoadedStickers$42$MediaDataController(int type) {
        this.loadingStickers[type] = false;
        this.stickersLoaded[type] = true;
    }

    public /* synthetic */ void lambda$processLoadedStickers$46$MediaDataController(boolean cache, final ArrayList res, final int date, final int hash, final int type) {
        HashMap<String, TLRPC.TL_messages_stickerSet> stickerSetsByNameNew;
        LongSparseArray<TLRPC.TL_messages_stickerSet> stickerSetsByIdNew;
        TLRPC.TL_messages_stickerSet stickerSet;
        TLRPC.TL_messages_stickerSet stickerSet2;
        HashMap<String, TLRPC.TL_messages_stickerSet> stickerSetsByNameNew2;
        LongSparseArray<TLRPC.TL_messages_stickerSet> stickerSetsByIdNew2;
        final int i = type;
        if ((cache && (res == null || Math.abs((System.currentTimeMillis() / 1000) - ((long) date)) >= 3600)) || (!cache && res == null && hash == 0)) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$gWGDFUec76qRf4TgVGpsmv5fOSE
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$43$MediaDataController(res, hash, i);
                }
            }, (res != null || cache) ? 0L : 1000L);
            if (res == null) {
                return;
            }
        }
        if (res == null) {
            if (!cache) {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$-zlWcZjIqxPNCnhnUkq-mK3bqPc
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$45$MediaDataController(i, date);
                    }
                });
                putStickersToCache(i, null, date, 0);
                return;
            }
            return;
        }
        try {
            final ArrayList<TLRPC.TL_messages_stickerSet> stickerSetsNew = new ArrayList<>();
            LongSparseArray<TLRPC.TL_messages_stickerSet> stickerSetsByIdNew3 = new LongSparseArray<>();
            HashMap<String, TLRPC.TL_messages_stickerSet> stickerSetsByNameNew3 = new HashMap<>();
            final LongSparseArray<String> stickersByEmojiNew = new LongSparseArray<>();
            final LongSparseArray<TLRPC.Document> stickersByIdNew = new LongSparseArray<>();
            final HashMap<String, ArrayList<TLRPC.Document>> allStickersNew = new HashMap<>();
            int a = 0;
            while (a < res.size()) {
                try {
                    TLRPC.TL_messages_stickerSet stickerSet3 = (TLRPC.TL_messages_stickerSet) res.get(a);
                    if (stickerSet3 == null) {
                        stickerSetsByNameNew = stickerSetsByNameNew3;
                        stickerSetsByIdNew = stickerSetsByIdNew3;
                    } else {
                        stickerSetsNew.add(stickerSet3);
                        stickerSetsByIdNew3.put(stickerSet3.set.id, stickerSet3);
                        stickerSetsByNameNew3.put(stickerSet3.set.short_name, stickerSet3);
                        int b = 0;
                        while (b < stickerSet3.documents.size()) {
                            TLRPC.Document document = stickerSet3.documents.get(b);
                            if (document == null) {
                                stickerSetsByNameNew2 = stickerSetsByNameNew3;
                                stickerSetsByIdNew2 = stickerSetsByIdNew3;
                            } else if (document instanceof TLRPC.TL_documentEmpty) {
                                stickerSetsByNameNew2 = stickerSetsByNameNew3;
                                stickerSetsByIdNew2 = stickerSetsByIdNew3;
                            } else {
                                stickerSetsByNameNew2 = stickerSetsByNameNew3;
                                stickerSetsByIdNew2 = stickerSetsByIdNew3;
                                stickersByIdNew.put(document.id, document);
                            }
                            b++;
                            stickerSetsByIdNew3 = stickerSetsByIdNew2;
                            stickerSetsByNameNew3 = stickerSetsByNameNew2;
                        }
                        stickerSetsByNameNew = stickerSetsByNameNew3;
                        stickerSetsByIdNew = stickerSetsByIdNew3;
                        if (!stickerSet3.set.archived) {
                            int b2 = 0;
                            while (b2 < stickerSet3.packs.size()) {
                                TLRPC.TL_stickerPack stickerPack = stickerSet3.packs.get(b2);
                                if (stickerPack == null) {
                                    stickerSet = stickerSet3;
                                } else if (stickerPack.emoticon == null) {
                                    stickerSet = stickerSet3;
                                } else {
                                    stickerPack.emoticon = stickerPack.emoticon.replace("️", "");
                                    ArrayList<TLRPC.Document> arrayList = allStickersNew.get(stickerPack.emoticon);
                                    if (arrayList == null) {
                                        arrayList = new ArrayList<>();
                                        allStickersNew.put(stickerPack.emoticon, arrayList);
                                    }
                                    int c = 0;
                                    while (c < stickerPack.documents.size()) {
                                        Long id = stickerPack.documents.get(c);
                                        if (stickersByEmojiNew.indexOfKey(id.longValue()) >= 0) {
                                            stickerSet2 = stickerSet3;
                                        } else {
                                            stickerSet2 = stickerSet3;
                                            stickersByEmojiNew.put(id.longValue(), stickerPack.emoticon);
                                        }
                                        TLRPC.Document sticker = stickersByIdNew.get(id.longValue());
                                        if (sticker != null) {
                                            arrayList.add(sticker);
                                        }
                                        c++;
                                        stickerSet3 = stickerSet2;
                                    }
                                    stickerSet = stickerSet3;
                                }
                                b2++;
                                stickerSet3 = stickerSet;
                            }
                        }
                    }
                    a++;
                    stickerSetsByIdNew3 = stickerSetsByIdNew;
                    stickerSetsByNameNew3 = stickerSetsByNameNew;
                } catch (Throwable th) {
                    e = th;
                    FileLog.e(e);
                }
            }
            final HashMap<String, TLRPC.TL_messages_stickerSet> stickerSetsByNameNew4 = stickerSetsByNameNew3;
            final LongSparseArray<TLRPC.TL_messages_stickerSet> stickerSetsByIdNew4 = stickerSetsByIdNew3;
            if (cache) {
                i = type;
            } else {
                i = type;
                putStickersToCache(i, stickerSetsNew, date, hash);
            }
            try {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$eXe7qbw2vGThMfL51RAqxgZ08iU
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$44$MediaDataController(type, stickerSetsByIdNew4, stickerSetsByNameNew4, stickerSetsNew, hash, date, stickersByIdNew, allStickersNew, stickersByEmojiNew);
                    }
                });
            } catch (Throwable th2) {
                e = th2;
                FileLog.e(e);
            }
        } catch (Throwable th3) {
            e = th3;
        }
    }

    public /* synthetic */ void lambda$null$43$MediaDataController(ArrayList res, int hash, int type) {
        if (res != null && hash != 0) {
            this.loadHash[type] = hash;
        }
    }

    /* JADX WARN: Type inference incomplete: some casts might be missing */
    public /* synthetic */ void lambda$null$44$MediaDataController(int i, LongSparseArray longSparseArray, HashMap map, ArrayList arrayList, int i2, int i3, LongSparseArray longSparseArray2, HashMap map2, LongSparseArray longSparseArray3) {
        for (int i4 = 0; i4 < this.stickerSets[i].size(); i4++) {
            TLRPC.StickerSet stickerSet = this.stickerSets[i].get(i4).set;
            this.stickerSetsById.remove(stickerSet.id);
            this.stickerSetsByName.remove(stickerSet.short_name);
            if (i != 3 && i != 4) {
                this.installedStickerSetsById.remove(stickerSet.id);
            }
        }
        for (int i5 = 0; i5 < longSparseArray.size(); i5++) {
            this.stickerSetsById.put(longSparseArray.keyAt(i5), (TLRPC.TL_messages_stickerSet) longSparseArray.valueAt(i5));
            if (i != 3 && i != 4) {
                this.installedStickerSetsById.put(longSparseArray.keyAt(i5), (TLRPC.TL_messages_stickerSet) longSparseArray.valueAt(i5));
            }
        }
        this.stickerSetsByName.putAll(map);
        this.stickerSets[i] = arrayList;
        this.loadHash[i] = i2;
        this.loadDate[i] = i3;
        this.stickersByIds[i] = longSparseArray2;
        if (i == 0) {
            this.allStickers = map2;
            this.stickersByEmoji = longSparseArray3;
        } else if (i == 3) {
            this.allStickersFeatured = map2;
        }
        getNotificationCenter().postNotificationName(NotificationCenter.stickersDidLoad, Integer.valueOf(i));
    }

    public /* synthetic */ void lambda$null$45$MediaDataController(int type, int date) {
        this.loadDate[type] = date;
    }

    public void removeStickersSet(Context context, final TLRPC.StickerSet stickerSet, int i, BaseFragment baseFragment, boolean z) {
        boolean z2 = stickerSet.masks;
        TLRPC.TL_inputStickerSetID tL_inputStickerSetID = new TLRPC.TL_inputStickerSetID();
        tL_inputStickerSetID.access_hash = stickerSet.access_hash;
        tL_inputStickerSetID.id = stickerSet.id;
        if (i != 0) {
            stickerSet.archived = i == 1;
            int i2 = 0;
            while (true) {
                if (i2 >= this.stickerSets[z2 ? 1 : 0].size()) {
                    break;
                }
                TLRPC.TL_messages_stickerSet tL_messages_stickerSet = this.stickerSets[z2 ? 1 : 0].get(i2);
                if (tL_messages_stickerSet.set.id != stickerSet.id) {
                    i2++;
                } else {
                    this.stickerSets[z2 ? 1 : 0].remove(i2);
                    if (i == 2) {
                        this.stickerSets[z2 ? 1 : 0].add(0, tL_messages_stickerSet);
                    } else {
                        this.stickerSetsById.remove(tL_messages_stickerSet.set.id);
                        this.installedStickerSetsById.remove(tL_messages_stickerSet.set.id);
                        this.stickerSetsByName.remove(tL_messages_stickerSet.set.short_name);
                    }
                }
            }
            this.loadHash[z2 ? 1 : 0] = calcStickersHash(this.stickerSets[z2 ? 1 : 0]);
            putStickersToCache(z2 ? 1 : 0, this.stickerSets[z2 ? 1 : 0], this.loadDate[z2 ? 1 : 0], this.loadHash[z2 ? 1 : 0]);
            getNotificationCenter().postNotificationName(NotificationCenter.stickersDidLoad, Integer.valueOf(z2 ? 1 : 0));
            return;
        }
        TLRPC.TL_messages_uninstallStickerSet tL_messages_uninstallStickerSet = new TLRPC.TL_messages_uninstallStickerSet();
        tL_messages_uninstallStickerSet.stickerset = tL_inputStickerSetID;
        ConnectionsManager connectionsManager = getConnectionsManager();
        final int i3 = z2 ? 1 : 0;
        connectionsManager.sendRequest(tL_messages_uninstallStickerSet, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$e4UWqRN7jmR0gOg3ThIUHf2hKEY
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$removeStickersSet$48$MediaDataController(stickerSet, i3, tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$removeStickersSet$48$MediaDataController(final TLRPC.StickerSet stickerSet, final int type, TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$X8bcZyilG6j11gvHCD5XriOqX1s
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$47$MediaDataController(error, stickerSet, type);
            }
        });
    }

    public /* synthetic */ void lambda$null$47$MediaDataController(TLRPC.TL_error error, TLRPC.StickerSet stickerSet, int type) {
        try {
            if (error == null) {
                if (stickerSet.masks) {
                    ToastUtils.show(mpEIGo.juqQQs.esbSDO.R.string.MasksRemoved);
                } else {
                    ToastUtils.show(mpEIGo.juqQQs.esbSDO.R.string.StickersRemoved);
                }
            } else {
                ToastUtils.show(mpEIGo.juqQQs.esbSDO.R.string.ErrorOccurred);
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
        loadStickers(type, false, true);
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x0018  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private int getMask() {
        /*
            r4 = this;
            r0 = 0
            int r1 = r4.lastReturnedNum
            java.util.ArrayList<im.uwrkaxlmjj.messenger.MessageObject> r2 = r4.searchResultMessages
            int r2 = r2.size()
            r3 = 1
            int r2 = r2 - r3
            if (r1 < r2) goto L18
            boolean[] r1 = r4.messagesSearchEndReached
            r2 = 0
            boolean r2 = r1[r2]
            if (r2 == 0) goto L18
            boolean r1 = r1[r3]
            if (r1 != 0) goto L1a
        L18:
            r0 = r0 | 1
        L1a:
            int r1 = r4.lastReturnedNum
            if (r1 <= 0) goto L20
            r0 = r0 | 2
        L20:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MediaDataController.getMask():int");
    }

    public boolean isMessageFound(int i, boolean z) {
        return this.searchResultMessagesMap[z ? 1 : 0].indexOfKey(i) >= 0;
    }

    public void searchMessagesInChat(String query, long dialog_id, long mergeDialogId, int guid, int direction, TLRPC.User user) {
        searchMessagesInChat(query, dialog_id, mergeDialogId, guid, direction, false, user);
    }

    private void searchMessagesInChat(String query, final long dialog_id, final long mergeDialogId, final int guid, final int direction, boolean internal, final TLRPC.User user) {
        String query2;
        int max_id;
        boolean firstQuery;
        long queryWithDialog;
        long queryWithDialog2;
        int max_id2;
        String query3;
        int max_id3;
        long queryWithDialog3 = dialog_id;
        boolean firstQuery2 = !internal;
        if (this.reqId != 0) {
            getConnectionsManager().cancelRequest(this.reqId, true);
            this.reqId = 0;
        }
        if (this.mergeReqId != 0) {
            getConnectionsManager().cancelRequest(this.mergeReqId, true);
            this.mergeReqId = 0;
        }
        if (query == null) {
            if (this.searchResultMessages.isEmpty()) {
                return;
            }
            if (direction == 1) {
                int i = this.lastReturnedNum + 1;
                this.lastReturnedNum = i;
                if (i < this.searchResultMessages.size()) {
                    MessageObject messageObject = this.searchResultMessages.get(this.lastReturnedNum);
                    NotificationCenter notificationCenter = getNotificationCenter();
                    int i2 = NotificationCenter.chatSearchResultsAvailable;
                    int[] iArr = this.messagesSearchCount;
                    notificationCenter.postNotificationName(i2, Integer.valueOf(guid), Integer.valueOf(messageObject.getId()), Integer.valueOf(getMask()), Long.valueOf(messageObject.getDialogId()), Integer.valueOf(this.lastReturnedNum), Integer.valueOf(iArr[0] + iArr[1]));
                    return;
                }
                boolean[] zArr = this.messagesSearchEndReached;
                if (zArr[0] && mergeDialogId == 0 && zArr[1]) {
                    this.lastReturnedNum--;
                    return;
                }
                String query4 = this.lastSearchQuery;
                ArrayList<MessageObject> arrayList = this.searchResultMessages;
                MessageObject messageObject2 = arrayList.get(arrayList.size() - 1);
                if (messageObject2.getDialogId() == dialog_id && !this.messagesSearchEndReached[0]) {
                    max_id3 = messageObject2.getId();
                    queryWithDialog3 = dialog_id;
                } else {
                    max_id3 = messageObject2.getDialogId() == mergeDialogId ? messageObject2.getId() : 0;
                    queryWithDialog3 = mergeDialogId;
                    this.messagesSearchEndReached[1] = false;
                }
                max_id = max_id3;
                firstQuery = false;
                query2 = query4;
            } else {
                if (direction == 2) {
                    int i3 = this.lastReturnedNum - 1;
                    this.lastReturnedNum = i3;
                    if (i3 < 0) {
                        this.lastReturnedNum = 0;
                        return;
                    }
                    if (i3 >= this.searchResultMessages.size()) {
                        this.lastReturnedNum = this.searchResultMessages.size() - 1;
                    }
                    MessageObject messageObject3 = this.searchResultMessages.get(this.lastReturnedNum);
                    NotificationCenter notificationCenter2 = getNotificationCenter();
                    int i4 = NotificationCenter.chatSearchResultsAvailable;
                    int[] iArr2 = this.messagesSearchCount;
                    notificationCenter2.postNotificationName(i4, Integer.valueOf(guid), Integer.valueOf(messageObject3.getId()), Integer.valueOf(getMask()), Long.valueOf(messageObject3.getDialogId()), Integer.valueOf(this.lastReturnedNum), Integer.valueOf(iArr2[0] + iArr2[1]));
                    return;
                }
                return;
            }
        } else {
            if (firstQuery2) {
                getNotificationCenter().postNotificationName(NotificationCenter.chatSearchResultsLoading, Integer.valueOf(guid));
                boolean[] zArr2 = this.messagesSearchEndReached;
                zArr2[1] = false;
                zArr2[0] = false;
                int[] iArr3 = this.messagesSearchCount;
                iArr3[1] = 0;
                iArr3[0] = 0;
                this.searchResultMessages.clear();
                this.searchResultMessagesMap[0].clear();
                this.searchResultMessagesMap[1].clear();
            }
            query2 = query;
            max_id = 0;
            firstQuery = firstQuery2;
        }
        boolean[] zArr3 = this.messagesSearchEndReached;
        if (zArr3[0] && !zArr3[1] && mergeDialogId != 0) {
            queryWithDialog = mergeDialogId;
        } else {
            queryWithDialog = queryWithDialog3;
        }
        if (queryWithDialog != dialog_id || !firstQuery) {
            queryWithDialog2 = queryWithDialog;
            max_id2 = max_id;
            query3 = query2;
        } else {
            if (mergeDialogId != 0) {
                TLRPC.InputPeer inputPeer = getMessagesController().getInputPeer((int) mergeDialogId);
                if (inputPeer == null) {
                    return;
                }
                final TLRPC.TL_messages_search req = new TLRPC.TL_messages_search();
                req.peer = inputPeer;
                this.lastMergeDialogId = mergeDialogId;
                req.limit = 1;
                req.q = query2 != null ? query2 : "";
                if (user != null) {
                    req.from_id = getMessagesController().getInputUser(user);
                    req.flags |= 1;
                }
                req.filter = new TLRPC.TL_inputMessagesFilterEmpty();
                this.mergeReqId = getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$4RyXt4Y7XYq28q8-uKf5pdohyJ8
                    @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                    public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                        this.f$0.lambda$searchMessagesInChat$50$MediaDataController(mergeDialogId, req, dialog_id, guid, direction, user, tLObject, tL_error);
                    }
                }, 2);
                return;
            }
            queryWithDialog2 = queryWithDialog;
            max_id2 = max_id;
            query3 = query2;
            this.lastMergeDialogId = 0L;
            this.messagesSearchEndReached[1] = true;
            this.messagesSearchCount[1] = 0;
        }
        final TLRPC.TL_messages_search req2 = new TLRPC.TL_messages_search();
        final long queryWithDialog4 = queryWithDialog2;
        req2.peer = getMessagesController().getInputPeer((int) queryWithDialog4);
        if (req2.peer == null) {
            return;
        }
        req2.limit = 21;
        req2.q = query3 != null ? query3 : "";
        req2.offset_id = max_id2;
        String query5 = query3;
        if (user != null) {
            req2.from_id = getMessagesController().getInputUser(user);
            req2.flags |= 1;
        }
        req2.filter = new TLRPC.TL_inputMessagesFilterEmpty();
        final int currentReqId = this.lastReqId + 1;
        this.lastReqId = currentReqId;
        this.lastSearchQuery = query5;
        this.reqId = getConnectionsManager().sendRequest(req2, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$4WIp0ayVq8hBEHMyI5uYYNV1TBs
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$searchMessagesInChat$52$MediaDataController(currentReqId, req2, queryWithDialog4, dialog_id, guid, mergeDialogId, user, tLObject, tL_error);
            }
        }, 2);
    }

    public /* synthetic */ void lambda$searchMessagesInChat$50$MediaDataController(final long mergeDialogId, final TLRPC.TL_messages_search req, final long dialog_id, final int guid, final int direction, final TLRPC.User user, final TLObject response, TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$h2bVmNhyO2dyOy5WE45hXj-eS_w
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$49$MediaDataController(mergeDialogId, response, req, dialog_id, guid, direction, user);
            }
        });
    }

    public /* synthetic */ void lambda$null$49$MediaDataController(long mergeDialogId, TLObject response, TLRPC.TL_messages_search req, long dialog_id, int guid, int direction, TLRPC.User user) {
        if (this.lastMergeDialogId == mergeDialogId) {
            this.mergeReqId = 0;
            if (response != null) {
                TLRPC.messages_Messages res = (TLRPC.messages_Messages) response;
                this.messagesSearchEndReached[1] = res.messages.isEmpty();
                this.messagesSearchCount[1] = res instanceof TLRPC.TL_messages_messagesSlice ? res.count : res.messages.size();
                searchMessagesInChat(req.q, dialog_id, mergeDialogId, guid, direction, true, user);
            }
        }
    }

    public /* synthetic */ void lambda$searchMessagesInChat$52$MediaDataController(final int currentReqId, final TLRPC.TL_messages_search req, final long queryWithDialogFinal, final long dialog_id, final int guid, final long mergeDialogId, final TLRPC.User user, final TLObject response, TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$y0hYaEc6p0tU-PqCur4-E2tguGI
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$51$MediaDataController(currentReqId, response, req, queryWithDialogFinal, dialog_id, guid, mergeDialogId, user);
            }
        });
    }

    public /* synthetic */ void lambda$null$51$MediaDataController(int currentReqId, TLObject response, TLRPC.TL_messages_search req, long queryWithDialogFinal, long dialog_id, int guid, long mergeDialogId, TLRPC.User user) {
        if (currentReqId == this.lastReqId) {
            this.reqId = 0;
            if (response != null) {
                TLRPC.messages_Messages res = (TLRPC.messages_Messages) response;
                int a = 0;
                while (a < res.messages.size()) {
                    TLRPC.Message message = res.messages.get(a);
                    if ((message instanceof TLRPC.TL_messageEmpty) || (message.action instanceof TLRPC.TL_messageActionHistoryClear)) {
                        res.messages.remove(a);
                        a--;
                    }
                    a++;
                }
                getMessagesStorage().putUsersAndChats(res.users, res.chats, true, true);
                getMessagesController().putUsers(res.users, false);
                getMessagesController().putChats(res.chats, false);
                if (req.offset_id == 0 && queryWithDialogFinal == dialog_id) {
                    this.lastReturnedNum = 0;
                    this.searchResultMessages.clear();
                    this.searchResultMessagesMap[0].clear();
                    this.searchResultMessagesMap[1].clear();
                    this.messagesSearchCount[0] = 0;
                }
                boolean added = false;
                for (int a2 = 0; a2 < Math.min(res.messages.size(), 20); a2++) {
                    added = true;
                    MessageObject messageObject = new MessageObject(this.currentAccount, res.messages.get(a2), false);
                    this.searchResultMessages.add(messageObject);
                    this.searchResultMessagesMap[queryWithDialogFinal == dialog_id ? (char) 0 : (char) 1].put(messageObject.getId(), messageObject);
                }
                this.messagesSearchEndReached[queryWithDialogFinal == dialog_id ? (char) 0 : (char) 1] = res.messages.size() != 21;
                this.messagesSearchCount[queryWithDialogFinal == dialog_id ? (char) 0 : (char) 1] = ((res instanceof TLRPC.TL_messages_messagesSlice) || (res instanceof TLRPC.TL_messages_channelMessages)) ? res.count : res.messages.size();
                if (this.searchResultMessages.isEmpty()) {
                    getNotificationCenter().postNotificationName(NotificationCenter.chatSearchResultsAvailable, Integer.valueOf(guid), 0, Integer.valueOf(getMask()), 0L, 0, 0);
                } else if (added) {
                    if (this.lastReturnedNum >= this.searchResultMessages.size()) {
                        this.lastReturnedNum = this.searchResultMessages.size() - 1;
                    }
                    MessageObject messageObject2 = this.searchResultMessages.get(this.lastReturnedNum);
                    NotificationCenter notificationCenter = getNotificationCenter();
                    int i = NotificationCenter.chatSearchResultsAvailable;
                    int[] iArr = this.messagesSearchCount;
                    notificationCenter.postNotificationName(i, Integer.valueOf(guid), Integer.valueOf(messageObject2.getId()), Integer.valueOf(getMask()), Long.valueOf(messageObject2.getDialogId()), Integer.valueOf(this.lastReturnedNum), Integer.valueOf(iArr[0] + iArr[1]));
                }
                if (queryWithDialogFinal == dialog_id) {
                    boolean[] zArr = this.messagesSearchEndReached;
                    if (zArr[0] && mergeDialogId != 0 && !zArr[1]) {
                        searchMessagesInChat(this.lastSearchQuery, dialog_id, mergeDialogId, guid, 0, true, user);
                    }
                }
            }
        }
    }

    public String getLastSearchQuery() {
        return this.lastSearchQuery;
    }

    public void loadMedia(final long uid, final int count, final int max_id, final int type, int fromCache, final int classGuid) {
        final boolean isChannel = ((int) uid) < 0 && ChatObject.isChannel(-((int) uid), this.currentAccount);
        int lower_part = (int) uid;
        if (fromCache != 0 || lower_part == 0) {
            int lower_part2 = lower_part;
            loadMediaDatabase(uid, count, max_id, type, classGuid, isChannel, fromCache);
            return;
        }
        TLRPC.TL_messages_search req = new TLRPC.TL_messages_search();
        req.limit = count;
        req.offset_id = max_id;
        if (type == 0) {
            req.filter = new TLRPC.TL_inputMessagesFilterPhotoVideo();
        } else if (type == 1) {
            req.filter = new TLRPC.TL_inputMessagesFilterDocument();
        } else if (type == 2) {
            req.filter = new TLRPC.TL_inputMessagesFilterRoundVoice();
        } else if (type == 3) {
            req.filter = new TLRPC.TL_inputMessagesFilterUrl();
        } else if (type == 4) {
            req.filter = new TLRPC.TL_inputMessagesFilterMusic();
        }
        req.q = "";
        req.peer = getMessagesController().getInputPeer(lower_part);
        if (req.peer == null) {
            return;
        }
        int reqId = getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$Z_YG19mYS7Jn5zDhLKsUf84gFik
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$loadMedia$53$MediaDataController(uid, count, max_id, type, classGuid, isChannel, tLObject, tL_error);
            }
        });
        getConnectionsManager().bindRequestToGuid(reqId, classGuid);
    }

    public /* synthetic */ void lambda$loadMedia$53$MediaDataController(long uid, int count, int max_id, int type, int classGuid, boolean isChannel, TLObject response, TLRPC.TL_error error) {
        if (error == null) {
            TLRPC.messages_Messages res = (TLRPC.messages_Messages) response;
            getMessagesController().removeDeletedMessagesFromArray(uid, res.messages);
            processLoadedMedia(res, uid, count, max_id, type, 0, classGuid, isChannel, res.messages.size() == 0);
        }
    }

    public void getMediaCounts(final long uid, final int classGuid) {
        getMessagesStorage().getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$1ShWXgwaK65xT4sMUdYKmVPhkYU
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$getMediaCounts$58$MediaDataController(uid, classGuid);
            }
        });
    }

    public /* synthetic */ void lambda$getMediaCounts$58$MediaDataController(final long uid, int classGuid) {
        int a;
        SQLiteCursor cursor;
        int[] counts;
        int[] countsFinal;
        try {
            int i = -1;
            int i2 = 0;
            int i3 = 2;
            int i4 = 3;
            final int[] counts2 = {-1, -1, -1, -1, -1};
            int[] countsFinal2 = {-1, -1, -1, -1, -1};
            int[] old = new int[5];
            old[0] = 0;
            old[1] = 0;
            old[2] = 0;
            old[3] = 0;
            old[4] = 0;
            SQLiteCursor cursor2 = getMessagesStorage().getDatabase().queryFinalized(String.format(Locale.US, "SELECT type, count, old FROM media_counts_v2 WHERE uid = %d", Long.valueOf(uid)), new Object[0]);
            while (cursor2.next()) {
                int type = cursor2.intValue(0);
                if (type >= 0 && type < 5) {
                    int iIntValue = cursor2.intValue(1);
                    counts2[type] = iIntValue;
                    countsFinal2[type] = iIntValue;
                    old[type] = cursor2.intValue(2);
                }
            }
            cursor2.dispose();
            int lower_part = (int) uid;
            if (lower_part == 0) {
                for (int a2 = 0; a2 < counts2.length; a2++) {
                    if (counts2[a2] == -1) {
                        SQLiteCursor cursor3 = getMessagesStorage().getDatabase().queryFinalized(String.format(Locale.US, "SELECT COUNT(mid) FROM media_v2 WHERE uid = %d AND type = %d LIMIT 1", Long.valueOf(uid), Integer.valueOf(a2)), new Object[0]);
                        if (cursor3.next()) {
                            counts2[a2] = cursor3.intValue(0);
                        } else {
                            counts2[a2] = 0;
                        }
                        cursor3.dispose();
                        putMediaCountDatabase(uid, a2, counts2[a2]);
                    }
                }
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$t_L69aOP_reFcY8sSfQaGsj8Tk0
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$54$MediaDataController(uid, counts2);
                    }
                });
                return;
            }
            int a3 = 0;
            boolean missing = false;
            while (a3 < counts2.length) {
                if (counts2[a3] == i || old[a3] == 1) {
                    final int type2 = a3;
                    TLRPC.TL_messages_search req = new TLRPC.TL_messages_search();
                    req.limit = 1;
                    req.offset_id = i2;
                    if (a3 == 0) {
                        req.filter = new TLRPC.TL_inputMessagesFilterPhotoVideo();
                    } else if (a3 == 1) {
                        req.filter = new TLRPC.TL_inputMessagesFilterDocument();
                    } else if (a3 == i3) {
                        req.filter = new TLRPC.TL_inputMessagesFilterRoundVoice();
                    } else if (a3 == i4) {
                        req.filter = new TLRPC.TL_inputMessagesFilterUrl();
                    } else if (a3 == 4) {
                        req.filter = new TLRPC.TL_inputMessagesFilterMusic();
                    }
                    req.q = "";
                    req.peer = getMessagesController().getInputPeer(lower_part);
                    if (req.peer == null) {
                        counts2[a3] = i2;
                        a = a3;
                        cursor = cursor2;
                        counts = counts2;
                        countsFinal = countsFinal2;
                    } else {
                        a = a3;
                        cursor = cursor2;
                        final int[] iArr = counts2;
                        counts = counts2;
                        countsFinal = countsFinal2;
                        int reqId = getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$x4wIif7cMwFNC9Er9bVvCMI6HWc
                            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                                this.f$0.lambda$null$56$MediaDataController(iArr, type2, uid, tLObject, tL_error);
                            }
                        });
                        try {
                            getConnectionsManager().bindRequestToGuid(reqId, classGuid);
                            if (counts[a] == -1) {
                                missing = true;
                            } else if (old[a] == 1) {
                                counts[a] = -1;
                            }
                        } catch (Exception e) {
                            e = e;
                            FileLog.e(e);
                            return;
                        }
                    }
                } else {
                    a = a3;
                    cursor = cursor2;
                    counts = counts2;
                    countsFinal = countsFinal2;
                }
                a3 = a + 1;
                countsFinal2 = countsFinal;
                cursor2 = cursor;
                counts2 = counts;
                i = -1;
                i2 = 0;
                i3 = 2;
                i4 = 3;
            }
            final int[] countsFinal3 = countsFinal2;
            if (!missing) {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$5ebSZctw-T9ALctMVVvuUABr6nQ
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$57$MediaDataController(uid, countsFinal3);
                    }
                });
            }
        } catch (Exception e2) {
            e = e2;
        }
    }

    public /* synthetic */ void lambda$null$54$MediaDataController(long uid, int[] counts) {
        getNotificationCenter().postNotificationName(NotificationCenter.mediaCountsDidLoad, Long.valueOf(uid), counts);
    }

    public /* synthetic */ void lambda$null$56$MediaDataController(final int[] counts, int type, final long uid, TLObject response, TLRPC.TL_error error) {
        if (error == null) {
            TLRPC.messages_Messages res = (TLRPC.messages_Messages) response;
            if (res instanceof TLRPC.TL_messages_messages) {
                counts[type] = res.messages.size();
            } else {
                counts[type] = res.count;
            }
            putMediaCountDatabase(uid, type, counts[type]);
        } else {
            counts[type] = 0;
        }
        boolean finished = true;
        int b = 0;
        while (true) {
            if (b >= counts.length) {
                break;
            }
            if (counts[b] != -1) {
                b++;
            } else {
                finished = false;
                break;
            }
        }
        if (finished) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$YzOu3kkwaa8mWyRHiDx5SbJF9Vk
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$55$MediaDataController(uid, counts);
                }
            });
        }
    }

    public /* synthetic */ void lambda$null$55$MediaDataController(long uid, int[] counts) {
        getNotificationCenter().postNotificationName(NotificationCenter.mediaCountsDidLoad, Long.valueOf(uid), counts);
    }

    public /* synthetic */ void lambda$null$57$MediaDataController(long uid, int[] countsFinal) {
        getNotificationCenter().postNotificationName(NotificationCenter.mediaCountsDidLoad, Long.valueOf(uid), countsFinal);
    }

    public void getMediaCount(final long uid, final int type, final int classGuid, boolean fromCache) {
        int lower_part = (int) uid;
        if (fromCache || lower_part == 0) {
            getMediaCountDatabase(uid, type, classGuid);
            return;
        }
        TLRPC.TL_messages_search req = new TLRPC.TL_messages_search();
        req.limit = 1;
        req.offset_id = 0;
        if (type == 0) {
            req.filter = new TLRPC.TL_inputMessagesFilterPhotoVideo();
        } else if (type == 1) {
            req.filter = new TLRPC.TL_inputMessagesFilterDocument();
        } else if (type == 2) {
            req.filter = new TLRPC.TL_inputMessagesFilterRoundVoice();
        } else if (type == 3) {
            req.filter = new TLRPC.TL_inputMessagesFilterUrl();
        } else if (type == 4) {
            req.filter = new TLRPC.TL_inputMessagesFilterMusic();
        }
        req.q = "";
        req.peer = getMessagesController().getInputPeer(lower_part);
        if (req.peer == null) {
            return;
        }
        int reqId = getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$VNS4Mc6tk1P6H3n8EQ_udYSVwq8
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$getMediaCount$60$MediaDataController(uid, type, classGuid, tLObject, tL_error);
            }
        });
        getConnectionsManager().bindRequestToGuid(reqId, classGuid);
    }

    public /* synthetic */ void lambda$getMediaCount$60$MediaDataController(long uid, int type, int classGuid, TLObject response, TLRPC.TL_error error) {
        int count;
        if (error == null) {
            final TLRPC.messages_Messages res = (TLRPC.messages_Messages) response;
            getMessagesStorage().putUsersAndChats(res.users, res.chats, true, true);
            if (res instanceof TLRPC.TL_messages_messages) {
                count = res.messages.size();
            } else {
                count = res.count;
            }
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$DiKlzrWhAJu-CbYGQm3s97_9EJI
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$59$MediaDataController(res);
                }
            });
            processLoadedMediaCount(count, uid, type, classGuid, false, 0);
        }
    }

    public /* synthetic */ void lambda$null$59$MediaDataController(TLRPC.messages_Messages res) {
        getMessagesController().putUsers(res.users, false);
        getMessagesController().putChats(res.chats, false);
    }

    public static int getMediaType(TLRPC.Message message) {
        if (message == null) {
            return -1;
        }
        if (message.media instanceof TLRPC.TL_messageMediaPhoto) {
            return 0;
        }
        if (message.media instanceof TLRPC.TL_messageMediaDocument) {
            if (MessageObject.isVoiceMessage(message) || MessageObject.isRoundVideoMessage(message)) {
                return 2;
            }
            if (MessageObject.isVideoMessage(message)) {
                return 0;
            }
            if (MessageObject.isStickerMessage(message) || MessageObject.isAnimatedStickerMessage(message)) {
                return -1;
            }
            if (MessageObject.isMusicMessage(message)) {
                return 4;
            }
            return 1;
        }
        if (!message.entities.isEmpty()) {
            for (int a = 0; a < message.entities.size(); a++) {
                TLRPC.MessageEntity entity = message.entities.get(a);
                if ((entity instanceof TLRPC.TL_messageEntityUrl) || (entity instanceof TLRPC.TL_messageEntityTextUrl) || (entity instanceof TLRPC.TL_messageEntityEmail)) {
                    return 3;
                }
            }
        }
        return -1;
    }

    public static boolean canAddMessageToMedia(TLRPC.Message message) {
        if ((message instanceof TLRPC.TL_message_secret) && (((message.media instanceof TLRPC.TL_messageMediaPhoto) || MessageObject.isVideoMessage(message) || MessageObject.isGifMessage(message)) && message.media.ttl_seconds != 0 && message.media.ttl_seconds <= 60)) {
            return false;
        }
        if (!(message instanceof TLRPC.TL_message_secret) && (message instanceof TLRPC.TL_message) && (((message.media instanceof TLRPC.TL_messageMediaPhoto) || (message.media instanceof TLRPC.TL_messageMediaDocument)) && message.media.ttl_seconds != 0)) {
            return false;
        }
        if ((message.media instanceof TLRPC.TL_messageMediaPhoto) || ((message.media instanceof TLRPC.TL_messageMediaDocument) && !MessageObject.isGifDocument(message.media.document))) {
            return true;
        }
        if (!message.entities.isEmpty()) {
            for (int a = 0; a < message.entities.size(); a++) {
                TLRPC.MessageEntity entity = message.entities.get(a);
                if ((entity instanceof TLRPC.TL_messageEntityUrl) || (entity instanceof TLRPC.TL_messageEntityTextUrl) || (entity instanceof TLRPC.TL_messageEntityEmail)) {
                    return true;
                }
            }
        }
        return false;
    }

    private void processLoadedMedia(final TLRPC.messages_Messages res, final long uid, int count, int max_id, final int type, final int fromCache, final int classGuid, boolean isChannel, final boolean topReached) {
        int lower_part = (int) uid;
        if (fromCache != 0 && res.messages.isEmpty() && lower_part != 0) {
            if (fromCache == 2) {
                return;
            }
            loadMedia(uid, count, max_id, type, 0, classGuid);
            return;
        }
        if (fromCache == 0) {
            ImageLoader.saveMessagesThumbs(res.messages);
            getMessagesStorage().putUsersAndChats(res.users, res.chats, true, true);
            putMediaDatabase(uid, type, res.messages, max_id, topReached);
        }
        SparseArray<TLRPC.User> usersDict = new SparseArray<>();
        for (int a = 0; a < res.users.size(); a++) {
            TLRPC.User u = res.users.get(a);
            usersDict.put(u.id, u);
        }
        final ArrayList<MessageObject> objects = new ArrayList<>();
        for (int a2 = 0; a2 < res.messages.size(); a2++) {
            TLRPC.Message message = res.messages.get(a2);
            objects.add(new MessageObject(this.currentAccount, message, usersDict, true));
        }
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$zrdcMKdP_rc5eAB5vmcT3j6cVkQ
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$processLoadedMedia$61$MediaDataController(res, fromCache, uid, objects, classGuid, type, topReached);
            }
        });
    }

    public /* synthetic */ void lambda$processLoadedMedia$61$MediaDataController(TLRPC.messages_Messages res, int fromCache, long uid, ArrayList objects, int classGuid, int type, boolean topReached) {
        int totalCount = res.count;
        getMessagesController().putUsers(res.users, fromCache != 0);
        getMessagesController().putChats(res.chats, fromCache != 0);
        getNotificationCenter().postNotificationName(NotificationCenter.mediaDidLoad, Long.valueOf(uid), Integer.valueOf(totalCount), objects, Integer.valueOf(classGuid), Integer.valueOf(type), Boolean.valueOf(topReached));
    }

    private void processLoadedMediaCount(final int count, final long uid, final int type, final int classGuid, final boolean fromCache, final int old) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$GkrauzjtnhLY8XGXrmNYfWu07Ao
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$processLoadedMediaCount$62$MediaDataController(uid, fromCache, count, type, old, classGuid);
            }
        });
    }

    public /* synthetic */ void lambda$processLoadedMediaCount$62$MediaDataController(long uid, boolean fromCache, int count, int type, int old, int classGuid) {
        int lower_part = (int) uid;
        boolean reload = fromCache && (count == -1 || (count == 0 && type == 2)) && lower_part != 0;
        if (reload || (old == 1 && lower_part != 0)) {
            getMediaCount(uid, type, classGuid, false);
        }
        if (!reload) {
            if (!fromCache) {
                putMediaCountDatabase(uid, type, count);
            }
            NotificationCenter notificationCenter = getNotificationCenter();
            int i = NotificationCenter.mediaCountDidLoad;
            Object[] objArr = new Object[4];
            objArr[0] = Long.valueOf(uid);
            objArr[1] = Integer.valueOf((fromCache && count == -1) ? 0 : count);
            objArr[2] = Boolean.valueOf(fromCache);
            objArr[3] = Integer.valueOf(type);
            notificationCenter.postNotificationName(i, objArr);
        }
    }

    private void putMediaCountDatabase(final long uid, final int type, final int count) {
        getMessagesStorage().getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$wv88TW5eGhdTa8_9I6KtI7oNSAs
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$putMediaCountDatabase$63$MediaDataController(uid, type, count);
            }
        });
    }

    public /* synthetic */ void lambda$putMediaCountDatabase$63$MediaDataController(long uid, int type, int count) {
        try {
            SQLitePreparedStatement state2 = getMessagesStorage().getDatabase().executeFast("REPLACE INTO media_counts_v2 VALUES(?, ?, ?, ?)");
            state2.requery();
            state2.bindLong(1, uid);
            state2.bindInteger(2, type);
            state2.bindInteger(3, count);
            state2.bindInteger(4, 0);
            state2.step();
            state2.dispose();
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    private void getMediaCountDatabase(final long uid, final int type, final int classGuid) {
        getMessagesStorage().getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$n2Cu1uMmvLIJV4zYt6n-ey8zVX0
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$getMediaCountDatabase$64$MediaDataController(uid, type, classGuid);
            }
        });
    }

    public /* synthetic */ void lambda$getMediaCountDatabase$64$MediaDataController(long uid, int type, int classGuid) {
        int old;
        int count = -1;
        try {
            SQLiteCursor cursor = getMessagesStorage().getDatabase().queryFinalized(String.format(Locale.US, "SELECT count, old FROM media_counts_v2 WHERE uid = %d AND type = %d LIMIT 1", Long.valueOf(uid), Integer.valueOf(type)), new Object[0]);
            if (!cursor.next()) {
                old = 0;
            } else {
                count = cursor.intValue(0);
                int old2 = cursor.intValue(1);
                old = old2;
            }
            cursor.dispose();
            int lower_part = (int) uid;
            if (count == -1 && lower_part == 0) {
                cursor = getMessagesStorage().getDatabase().queryFinalized(String.format(Locale.US, "SELECT COUNT(mid) FROM media_v2 WHERE uid = %d AND type = %d LIMIT 1", Long.valueOf(uid), Integer.valueOf(type)), new Object[0]);
                if (cursor.next()) {
                    count = cursor.intValue(0);
                }
                cursor.dispose();
                if (count != -1) {
                    try {
                        putMediaCountDatabase(uid, type, count);
                    } catch (Exception e) {
                        e = e;
                        FileLog.e(e);
                        return;
                    }
                }
            }
            processLoadedMediaCount(count, uid, type, classGuid, true, old);
        } catch (Exception e2) {
            e = e2;
        }
    }

    private void loadMediaDatabase(final long uid, final int count, final int max_id, final int type, final int classGuid, final boolean isChannel, final int fromCache) {
        getMessagesStorage().getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$CgHpaVxSCtRNvk3__5bjHv5b10I
            @Override // java.lang.Runnable
            public final void run() throws Throwable {
                this.f$0.lambda$loadMediaDatabase$65$MediaDataController(count, uid, max_id, isChannel, type, fromCache, classGuid);
            }
        });
    }

    public /* synthetic */ void lambda$loadMediaDatabase$65$MediaDataController(int count, long uid, int max_id, boolean isChannel, int type, int fromCache, int classGuid) throws Throwable {
        boolean topReached;
        TLRPC.TL_messages_messages res;
        TLRPC.TL_messages_messages res2;
        ArrayList<Integer> usersToLoad;
        ArrayList<Integer> chatsToLoad;
        boolean isEnd;
        SQLiteCursor cursor;
        TLRPC.TL_messages_messages res3;
        boolean topReached2;
        ArrayList<Integer> usersToLoad2;
        boolean isEnd2;
        long holeMessageId;
        TLRPC.TL_messages_messages res4 = new TLRPC.TL_messages_messages();
        try {
            ArrayList<Integer> usersToLoad3 = new ArrayList<>();
            ArrayList<Integer> chatsToLoad2 = new ArrayList<>();
            int countToLoad = count + 1;
            SQLiteDatabase database = getMessagesStorage().getDatabase();
            try {
                if (((int) uid) != 0) {
                    res2 = res4;
                    long messageMaxId = max_id;
                    int channelId = isChannel ? -((int) uid) : 0;
                    if (messageMaxId == 0 || channelId == 0) {
                        usersToLoad = usersToLoad3;
                        topReached = false;
                    } else {
                        usersToLoad = usersToLoad3;
                        topReached = false;
                        messageMaxId |= ((long) channelId) << 32;
                    }
                    SQLiteCursor cursor2 = database.queryFinalized(String.format(Locale.US, "SELECT start FROM media_holes_v2 WHERE uid = %d AND type = %d AND start IN (0, 1)", Long.valueOf(uid), Integer.valueOf(type)), new Object[0]);
                    if (cursor2.next()) {
                        isEnd = cursor2.intValue(0) == 1;
                        cursor2.dispose();
                    } else {
                        cursor2.dispose();
                        cursor2 = database.queryFinalized(String.format(Locale.US, "SELECT min(mid) FROM media_v2 WHERE uid = %d AND type = %d AND mid > 0", Long.valueOf(uid), Integer.valueOf(type)), new Object[0]);
                        if (cursor2.next()) {
                            try {
                                int mid = cursor2.intValue(0);
                                if (mid != 0) {
                                    SQLitePreparedStatement state = database.executeFast("REPLACE INTO media_holes_v2 VALUES(?, ?, ?, ?)");
                                    state.requery();
                                    state.bindLong(1, uid);
                                    state.bindInteger(2, type);
                                    isEnd2 = false;
                                    state.bindInteger(3, 0);
                                    state.bindInteger(4, mid);
                                    state.step();
                                    state.dispose();
                                } else {
                                    isEnd2 = false;
                                }
                            } catch (Exception e) {
                                e = e;
                                res = res2;
                                try {
                                    res.messages.clear();
                                    res.chats.clear();
                                    res.users.clear();
                                    FileLog.e(e);
                                    processLoadedMedia(res, uid, count, max_id, type, fromCache, classGuid, isChannel, topReached);
                                    return;
                                } catch (Throwable th) {
                                    th = th;
                                    processLoadedMedia(res, uid, count, max_id, type, fromCache, classGuid, isChannel, topReached);
                                    throw th;
                                }
                            } catch (Throwable th2) {
                                th = th2;
                                res = res2;
                                processLoadedMedia(res, uid, count, max_id, type, fromCache, classGuid, isChannel, topReached);
                                throw th;
                            }
                        } else {
                            isEnd2 = false;
                        }
                        cursor2.dispose();
                        isEnd = isEnd2;
                    }
                    if (messageMaxId != 0) {
                        long holeMessageId2 = 0;
                        SQLiteCursor cursor3 = database.queryFinalized(String.format(Locale.US, "SELECT end FROM media_holes_v2 WHERE uid = %d AND type = %d AND end <= %d ORDER BY end DESC LIMIT 1", Long.valueOf(uid), Integer.valueOf(type), Integer.valueOf(max_id)), new Object[0]);
                        if (cursor3.next()) {
                            long holeMessageId3 = cursor3.intValue(0);
                            if (channelId != 0) {
                                chatsToLoad = chatsToLoad2;
                                holeMessageId2 = holeMessageId3 | (((long) channelId) << 32);
                            } else {
                                chatsToLoad = chatsToLoad2;
                                holeMessageId2 = holeMessageId3;
                            }
                        } else {
                            chatsToLoad = chatsToLoad2;
                        }
                        cursor3.dispose();
                        cursor = holeMessageId2 > 1 ? database.queryFinalized(String.format(Locale.US, "SELECT data, mid FROM media_v2 WHERE uid = %d AND mid > 0 AND mid < %d AND mid >= %d AND type = %d ORDER BY date DESC, mid DESC LIMIT %d", Long.valueOf(uid), Long.valueOf(messageMaxId), Long.valueOf(holeMessageId2), Integer.valueOf(type), Integer.valueOf(countToLoad)), new Object[0]) : database.queryFinalized(String.format(Locale.US, "SELECT data, mid FROM media_v2 WHERE uid = %d AND mid > 0 AND mid < %d AND type = %d ORDER BY date DESC, mid DESC LIMIT %d", Long.valueOf(uid), Long.valueOf(messageMaxId), Integer.valueOf(type), Integer.valueOf(countToLoad)), new Object[0]);
                    } else {
                        chatsToLoad = chatsToLoad2;
                        SQLiteCursor cursor4 = database.queryFinalized(String.format(Locale.US, "SELECT max(end) FROM media_holes_v2 WHERE uid = %d AND type = %d", Long.valueOf(uid), Integer.valueOf(type)), new Object[0]);
                        if (cursor4.next()) {
                            holeMessageId = cursor4.intValue(0);
                            if (channelId != 0) {
                                holeMessageId |= ((long) channelId) << 32;
                            }
                        } else {
                            holeMessageId = 0;
                        }
                        cursor4.dispose();
                        cursor = holeMessageId > 1 ? database.queryFinalized(String.format(Locale.US, "SELECT data, mid FROM media_v2 WHERE uid = %d AND mid >= %d AND type = %d ORDER BY date DESC, mid DESC LIMIT %d", Long.valueOf(uid), Long.valueOf(holeMessageId), Integer.valueOf(type), Integer.valueOf(countToLoad)), new Object[0]) : database.queryFinalized(String.format(Locale.US, "SELECT data, mid FROM media_v2 WHERE uid = %d AND mid > 0 AND type = %d ORDER BY date DESC, mid DESC LIMIT %d", Long.valueOf(uid), Integer.valueOf(type), Integer.valueOf(countToLoad)), new Object[0]);
                    }
                } else {
                    usersToLoad = usersToLoad3;
                    topReached = false;
                    chatsToLoad = chatsToLoad2;
                    res2 = res4;
                    isEnd = true;
                    if (max_id != 0) {
                        cursor = database.queryFinalized(String.format(Locale.US, "SELECT m.data, m.mid, r.random_id FROM media_v2 as m LEFT JOIN randoms as r ON r.mid = m.mid WHERE m.uid = %d AND m.mid > %d AND type = %d ORDER BY m.mid ASC LIMIT %d", Long.valueOf(uid), Integer.valueOf(max_id), Integer.valueOf(type), Integer.valueOf(countToLoad)), new Object[0]);
                    } else {
                        try {
                            cursor = database.queryFinalized(String.format(Locale.US, "SELECT m.data, m.mid, r.random_id FROM media_v2 as m LEFT JOIN randoms as r ON r.mid = m.mid WHERE m.uid = %d AND type = %d ORDER BY m.mid ASC LIMIT %d", Long.valueOf(uid), Integer.valueOf(type), Integer.valueOf(countToLoad)), new Object[0]);
                        } catch (Exception e2) {
                            e = e2;
                            res = res2;
                            res.messages.clear();
                            res.chats.clear();
                            res.users.clear();
                            FileLog.e(e);
                            processLoadedMedia(res, uid, count, max_id, type, fromCache, classGuid, isChannel, topReached);
                            return;
                        } catch (Throwable th3) {
                            th = th3;
                            res = res2;
                            processLoadedMedia(res, uid, count, max_id, type, fromCache, classGuid, isChannel, topReached);
                            throw th;
                        }
                    }
                }
                while (cursor.next()) {
                    try {
                        NativeByteBuffer data = cursor.byteBufferValue(0);
                        if (data != null) {
                            TLRPC.Message message = TLRPC.Message.TLdeserialize(data, data.readInt32(false), false);
                            message.readAttachPath(data, getUserConfig().clientUserId);
                            data.reuse();
                            message.id = cursor.intValue(1);
                            message.dialog_id = uid;
                            if (((int) uid) == 0) {
                                message.random_id = cursor.longValue(2);
                            }
                            res3 = res2;
                            try {
                                res3.messages.add(message);
                                usersToLoad2 = usersToLoad;
                                MessagesStorage.addUsersAndChatsFromMessage(message, usersToLoad2, chatsToLoad);
                            } catch (Exception e3) {
                                e = e3;
                                res = res3;
                                res.messages.clear();
                                res.chats.clear();
                                res.users.clear();
                                FileLog.e(e);
                                processLoadedMedia(res, uid, count, max_id, type, fromCache, classGuid, isChannel, topReached);
                                return;
                            } catch (Throwable th4) {
                                th = th4;
                                res = res3;
                                processLoadedMedia(res, uid, count, max_id, type, fromCache, classGuid, isChannel, topReached);
                                throw th;
                            }
                        } else {
                            res3 = res2;
                            usersToLoad2 = usersToLoad;
                        }
                        usersToLoad = usersToLoad2;
                        res2 = res3;
                    } catch (Exception e4) {
                        e = e4;
                        res = res2;
                        res.messages.clear();
                        res.chats.clear();
                        res.users.clear();
                        FileLog.e(e);
                        processLoadedMedia(res, uid, count, max_id, type, fromCache, classGuid, isChannel, topReached);
                        return;
                    } catch (Throwable th5) {
                        th = th5;
                        res = res2;
                        processLoadedMedia(res, uid, count, max_id, type, fromCache, classGuid, isChannel, topReached);
                        throw th;
                    }
                }
                res3 = res2;
                ArrayList<Integer> usersToLoad4 = usersToLoad;
                try {
                    cursor.dispose();
                    if (!usersToLoad4.isEmpty()) {
                        getMessagesStorage().getUsersInternal(TextUtils.join(",", usersToLoad4), res3.users);
                    }
                    if (!chatsToLoad.isEmpty()) {
                        getMessagesStorage().getChatsInternal(TextUtils.join(",", chatsToLoad), res3.chats);
                    }
                    if (res3.messages.size() > count) {
                        try {
                            res3.messages.remove(res3.messages.size() - 1);
                            topReached2 = false;
                        } catch (Exception e5) {
                            e = e5;
                            topReached = false;
                            res = res3;
                            res.messages.clear();
                            res.chats.clear();
                            res.users.clear();
                            FileLog.e(e);
                            processLoadedMedia(res, uid, count, max_id, type, fromCache, classGuid, isChannel, topReached);
                            return;
                        } catch (Throwable th6) {
                            th = th6;
                            topReached = false;
                            res = res3;
                            processLoadedMedia(res, uid, count, max_id, type, fromCache, classGuid, isChannel, topReached);
                            throw th;
                        }
                    } else {
                        boolean topReached3 = isEnd;
                        topReached2 = topReached3;
                    }
                    processLoadedMedia(res3, uid, count, max_id, type, fromCache, classGuid, isChannel, topReached2);
                } catch (Exception e6) {
                    e = e6;
                    res = res3;
                } catch (Throwable th7) {
                    th = th7;
                    res = res3;
                }
            } catch (Exception e7) {
                e = e7;
            } catch (Throwable th8) {
                th = th8;
            }
        } catch (Exception e8) {
            e = e8;
            topReached = false;
            res = res4;
        } catch (Throwable th9) {
            th = th9;
            topReached = false;
            res = res4;
        }
    }

    private void putMediaDatabase(final long uid, final int type, final ArrayList<TLRPC.Message> messages, final int max_id, final boolean topReached) {
        getMessagesStorage().getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$QGefBcGYgk4F693AdJ7sDyQjXqY
            @Override // java.lang.Runnable
            public final void run() throws Throwable {
                this.f$0.lambda$putMediaDatabase$66$MediaDataController(messages, topReached, uid, max_id, type);
            }
        });
    }

    /* JADX WARN: Removed duplicated region for block: B:62:0x0117  */
    /* JADX WARN: Removed duplicated region for block: B:64:0x011c  */
    /* JADX WARN: Removed duplicated region for block: B:68:0x0125  */
    /* JADX WARN: Removed duplicated region for block: B:70:0x012a  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public /* synthetic */ void lambda$putMediaDatabase$66$MediaDataController(java.util.ArrayList r18, boolean r19, long r20, int r22, int r23) throws java.lang.Throwable {
        /*
            Method dump skipped, instruction units count: 302
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MediaDataController.lambda$putMediaDatabase$66$MediaDataController(java.util.ArrayList, boolean, long, int, int):void");
    }

    public void loadMusic(final long uid, final long max_id) {
        getMessagesStorage().getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$wM4iq_-W4digKlfjNdnJedwD1ig
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$loadMusic$68$MediaDataController(uid, max_id);
            }
        });
    }

    public /* synthetic */ void lambda$loadMusic$68$MediaDataController(final long uid, long max_id) {
        SQLiteCursor cursor;
        final ArrayList<MessageObject> arrayList = new ArrayList<>();
        int lower_id = (int) uid;
        try {
            if (lower_id != 0) {
                cursor = getMessagesStorage().getDatabase().queryFinalized(String.format(Locale.US, "SELECT data, mid FROM media_v2 WHERE uid = %d AND mid < %d AND type = %d ORDER BY date DESC, mid DESC LIMIT 1000", Long.valueOf(uid), Long.valueOf(max_id), 4), new Object[0]);
            } else {
                cursor = getMessagesStorage().getDatabase().queryFinalized(String.format(Locale.US, "SELECT data, mid FROM media_v2 WHERE uid = %d AND mid > %d AND type = %d ORDER BY date DESC, mid DESC LIMIT 1000", Long.valueOf(uid), Long.valueOf(max_id), 4), new Object[0]);
            }
            while (cursor.next()) {
                NativeByteBuffer data = cursor.byteBufferValue(0);
                if (data != null) {
                    TLRPC.Message message = TLRPC.Message.TLdeserialize(data, data.readInt32(false), false);
                    message.readAttachPath(data, getUserConfig().clientUserId);
                    data.reuse();
                    if (MessageObject.isMusicMessage(message)) {
                        message.id = cursor.intValue(1);
                        message.dialog_id = uid;
                        arrayList.add(0, new MessageObject(this.currentAccount, message, false));
                    }
                }
            }
            cursor.dispose();
        } catch (Exception e) {
            FileLog.e(e);
        }
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$X1O29XKEiVWFt-cms4HjILlmBO0
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$67$MediaDataController(uid, arrayList);
            }
        });
    }

    public /* synthetic */ void lambda$null$67$MediaDataController(long uid, ArrayList arrayList) {
        getNotificationCenter().postNotificationName(NotificationCenter.musicDidLoad, Long.valueOf(uid), arrayList);
    }

    public void buildShortcuts() {
        if (Build.VERSION.SDK_INT < 25) {
            return;
        }
        final ArrayList<TLRPC.TL_topPeer> hintsFinal = new ArrayList<>();
        for (int a = 0; a < this.hints.size(); a++) {
            hintsFinal.add(this.hints.get(a));
            if (hintsFinal.size() == 3) {
                break;
            }
        }
        Utilities.globalQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$L_gaS__BZ641yYRrpQJdFXcqA-8
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$buildShortcuts$69$MediaDataController(hintsFinal);
            }
        });
    }

    public /* synthetic */ void lambda$buildShortcuts$69$MediaDataController(ArrayList hintsFinal) {
        long did;
        TLRPC.User user;
        List<ShortcutInfo> currentShortcuts;
        ArrayList<String> newShortcutsIds;
        ArrayList<String> shortcutsToDelete;
        Intent intent;
        TLRPC.FileLocation photo;
        String name;
        String name2;
        Path path;
        long did2;
        ArrayList arrayList = hintsFinal;
        try {
            ShortcutManager shortcutManager = (ShortcutManager) ApplicationLoader.applicationContext.getSystemService(ShortcutManager.class);
            List<ShortcutInfo> currentShortcuts2 = shortcutManager.getDynamicShortcuts();
            ArrayList<String> shortcutsToUpdate = new ArrayList<>();
            ArrayList<String> newShortcutsIds2 = new ArrayList<>();
            ArrayList<String> shortcutsToDelete2 = new ArrayList<>();
            if (currentShortcuts2 != null && !currentShortcuts2.isEmpty()) {
                newShortcutsIds2.add("compose");
                for (int a = 0; a < hintsFinal.size(); a++) {
                    TLRPC.TL_topPeer hint = (TLRPC.TL_topPeer) arrayList.get(a);
                    if (hint.peer.user_id != 0) {
                        did2 = hint.peer.user_id;
                    } else {
                        did2 = -hint.peer.chat_id;
                        if (did2 == 0) {
                            did2 = -hint.peer.channel_id;
                        }
                    }
                    newShortcutsIds2.add("did" + did2);
                }
                for (int a2 = 0; a2 < currentShortcuts2.size(); a2++) {
                    String id = currentShortcuts2.get(a2).getId();
                    if (!newShortcutsIds2.remove(id)) {
                        shortcutsToDelete2.add(id);
                    }
                    shortcutsToUpdate.add(id);
                }
                if (newShortcutsIds2.isEmpty() && shortcutsToDelete2.isEmpty()) {
                    return;
                }
            }
            Intent intent2 = new Intent(ApplicationLoader.applicationContext, (Class<?>) LaunchActivity.class);
            intent2.setAction("new_dialog");
            ArrayList<ShortcutInfo> arrayList2 = new ArrayList<>();
            arrayList2.add(new ShortcutInfo.Builder(ApplicationLoader.applicationContext, "compose").setShortLabel(LocaleController.getString("NewConversationShortcut", mpEIGo.juqQQs.esbSDO.R.string.NewConversationShortcut)).setLongLabel(LocaleController.getString("NewConversationShortcut", mpEIGo.juqQQs.esbSDO.R.string.NewConversationShortcut)).setIcon(Icon.createWithResource(ApplicationLoader.applicationContext, mpEIGo.juqQQs.esbSDO.R.drawable.shortcut_compose)).setIntent(intent2).build());
            if (shortcutsToUpdate.contains("compose")) {
                shortcutManager.updateShortcuts(arrayList2);
            } else {
                shortcutManager.addDynamicShortcuts(arrayList2);
            }
            arrayList2.clear();
            if (!shortcutsToDelete2.isEmpty()) {
                shortcutManager.removeDynamicShortcuts(shortcutsToDelete2);
            }
            int a3 = 0;
            while (a3 < hintsFinal.size()) {
                Intent shortcutIntent = new Intent(ApplicationLoader.applicationContext, (Class<?>) OpenChatReceiver.class);
                TLRPC.TL_topPeer hint2 = (TLRPC.TL_topPeer) arrayList.get(a3);
                TLRPC.Chat chat = null;
                if (hint2.peer.user_id != 0) {
                    shortcutIntent.putExtra("userId", hint2.peer.user_id);
                    TLRPC.User user2 = getMessagesController().getUser(Integer.valueOf(hint2.peer.user_id));
                    did = hint2.peer.user_id;
                    user = user2;
                } else {
                    int chat_id = hint2.peer.chat_id;
                    if (chat_id == 0) {
                        chat_id = hint2.peer.channel_id;
                    }
                    chat = getMessagesController().getChat(Integer.valueOf(chat_id));
                    shortcutIntent.putExtra("chatId", chat_id);
                    did = -chat_id;
                    user = null;
                }
                if ((user == null || UserObject.isDeleted(user)) && chat == null) {
                    currentShortcuts = currentShortcuts2;
                    newShortcutsIds = newShortcutsIds2;
                    shortcutsToDelete = shortcutsToDelete2;
                    intent = intent2;
                } else {
                    if (user != null) {
                        currentShortcuts = currentShortcuts2;
                        String name3 = ContactsController.formatName(user.first_name, user.last_name);
                        if (user.photo == null) {
                            photo = null;
                            name = name3;
                        } else {
                            photo = user.photo.photo_small;
                            name = name3;
                        }
                    } else {
                        currentShortcuts = currentShortcuts2;
                        String name4 = chat.title;
                        if (chat.photo == null) {
                            photo = null;
                            name = name4;
                        } else {
                            photo = chat.photo.photo_small;
                            name = name4;
                        }
                    }
                    newShortcutsIds = newShortcutsIds2;
                    shortcutIntent.putExtra("currentAccount", this.currentAccount);
                    shortcutIntent.setAction("com.tmessages.openchat" + did);
                    shortcutIntent.addFlags(ConnectionsManager.FileTypeFile);
                    Bitmap bitmap = null;
                    if (photo != null) {
                        try {
                            File path2 = FileLoader.getPathToAttach(photo, true);
                            bitmap = BitmapFactory.decodeFile(path2.toString());
                            if (bitmap != null) {
                                int size = AndroidUtilities.dp(48.0f);
                                Bitmap result = Bitmap.createBitmap(size, size, Bitmap.Config.ARGB_8888);
                                try {
                                    Canvas canvas = new Canvas(result);
                                    if (roundPaint == null) {
                                        shortcutsToDelete = shortcutsToDelete2;
                                        try {
                                            roundPaint = new Paint(3);
                                            bitmapRect = new RectF();
                                            Paint paint = new Paint(1);
                                            erasePaint = paint;
                                            intent = intent2;
                                            try {
                                                paint.setXfermode(new PorterDuffXfermode(PorterDuff.Mode.CLEAR));
                                                path = new Path();
                                                roundPath = path;
                                            } catch (Throwable th) {
                                                e = th;
                                                FileLog.e(e);
                                            }
                                        } catch (Throwable th2) {
                                            e = th2;
                                            intent = intent2;
                                        }
                                        try {
                                            path.addCircle(size / 2, size / 2, (size / 2) - AndroidUtilities.dp(2.0f), Path.Direction.CW);
                                            roundPath.toggleInverseFillType();
                                        } catch (Throwable th3) {
                                            e = th3;
                                            FileLog.e(e);
                                        }
                                    } else {
                                        shortcutsToDelete = shortcutsToDelete2;
                                        intent = intent2;
                                    }
                                    bitmapRect.set(AndroidUtilities.dp(2.0f), AndroidUtilities.dp(2.0f), AndroidUtilities.dp(46.0f), AndroidUtilities.dp(46.0f));
                                    canvas.drawBitmap(bitmap, (Rect) null, bitmapRect, roundPaint);
                                    canvas.drawPath(roundPath, erasePaint);
                                    try {
                                        canvas.setBitmap(null);
                                    } catch (Exception e) {
                                    }
                                    bitmap = result;
                                } catch (Throwable th4) {
                                    e = th4;
                                    shortcutsToDelete = shortcutsToDelete2;
                                    intent = intent2;
                                }
                            } else {
                                shortcutsToDelete = shortcutsToDelete2;
                                intent = intent2;
                            }
                        } catch (Throwable th5) {
                            e = th5;
                            shortcutsToDelete = shortcutsToDelete2;
                            intent = intent2;
                        }
                    } else {
                        shortcutsToDelete = shortcutsToDelete2;
                        intent = intent2;
                    }
                    String id2 = "did" + did;
                    if (!TextUtils.isEmpty(name)) {
                        name2 = name;
                    } else {
                        name2 = " ";
                    }
                    ShortcutInfo.Builder builder = new ShortcutInfo.Builder(ApplicationLoader.applicationContext, id2).setShortLabel(name2).setLongLabel(name2).setIntent(shortcutIntent);
                    if (bitmap != null) {
                        builder.setIcon(Icon.createWithBitmap(bitmap));
                    } else {
                        builder.setIcon(Icon.createWithResource(ApplicationLoader.applicationContext, mpEIGo.juqQQs.esbSDO.R.drawable.shortcut_user));
                    }
                    arrayList2.add(builder.build());
                    if (shortcutsToUpdate.contains(id2)) {
                        shortcutManager.updateShortcuts(arrayList2);
                    } else {
                        shortcutManager.addDynamicShortcuts(arrayList2);
                    }
                    arrayList2.clear();
                }
                a3++;
                arrayList = hintsFinal;
                currentShortcuts2 = currentShortcuts;
                newShortcutsIds2 = newShortcutsIds;
                intent2 = intent;
                shortcutsToDelete2 = shortcutsToDelete;
            }
        } catch (Throwable th6) {
        }
    }

    public void loadHints(boolean cache) {
        if (this.loading || !getUserConfig().suggestContacts) {
            return;
        }
        if (cache) {
            if (this.loaded) {
                return;
            }
            this.loading = true;
            getMessagesStorage().getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$v5ZR77VAjHpY6KhONEUnthtbJ5c
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$loadHints$71$MediaDataController();
                }
            });
            this.loaded = true;
            return;
        }
        this.loading = true;
        TLRPC.TL_contacts_getTopPeers req = new TLRPC.TL_contacts_getTopPeers();
        req.hash = 0;
        req.bots_pm = false;
        req.correspondents = true;
        req.groups = false;
        req.channels = false;
        req.bots_inline = true;
        req.offset = 0;
        req.limit = 20;
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$TXV_t9kwKeY6g7p0Lvr3hkt5tHM
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$loadHints$76$MediaDataController(tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$loadHints$71$MediaDataController() {
        final ArrayList<TLRPC.TL_topPeer> hintsNew = new ArrayList<>();
        final ArrayList<TLRPC.TL_topPeer> inlineBotsNew = new ArrayList<>();
        final ArrayList<TLRPC.User> users = new ArrayList<>();
        final ArrayList<TLRPC.Chat> chats = new ArrayList<>();
        int selfUserId = getUserConfig().getClientUserId();
        try {
            ArrayList<Integer> usersToLoad = new ArrayList<>();
            ArrayList<Integer> chatsToLoad = new ArrayList<>();
            SQLiteCursor cursor = getMessagesStorage().getDatabase().queryFinalized("SELECT did, type, rating FROM chat_hints WHERE 1 ORDER BY rating DESC", new Object[0]);
            while (cursor.next()) {
                int did = cursor.intValue(0);
                if (did != selfUserId) {
                    int type = cursor.intValue(1);
                    TLRPC.TL_topPeer peer = new TLRPC.TL_topPeer();
                    peer.rating = cursor.doubleValue(2);
                    if (did > 0) {
                        peer.peer = new TLRPC.TL_peerUser();
                        peer.peer.user_id = did;
                        usersToLoad.add(Integer.valueOf(did));
                    } else {
                        peer.peer = new TLRPC.TL_peerChat();
                        peer.peer.chat_id = -did;
                        chatsToLoad.add(Integer.valueOf(-did));
                    }
                    if (type == 0) {
                        hintsNew.add(peer);
                    } else if (type == 1) {
                        inlineBotsNew.add(peer);
                    }
                }
            }
            cursor.dispose();
            if (!usersToLoad.isEmpty()) {
                getMessagesStorage().getUsersInternal(TextUtils.join(",", usersToLoad), users);
            }
            if (!chatsToLoad.isEmpty()) {
                getMessagesStorage().getChatsInternal(TextUtils.join(",", chatsToLoad), chats);
            }
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$0a3ZKQzxtMwSs10BhqqE-GIjEP8
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$70$MediaDataController(users, chats, hintsNew, inlineBotsNew);
                }
            });
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public /* synthetic */ void lambda$null$70$MediaDataController(ArrayList users, ArrayList chats, ArrayList hintsNew, ArrayList inlineBotsNew) {
        getMessagesController().putUsers(users, true);
        getMessagesController().putChats(chats, true);
        this.loading = false;
        this.loaded = true;
        this.hints = hintsNew;
        this.inlineBots = inlineBotsNew;
        buildShortcuts();
        getNotificationCenter().postNotificationName(NotificationCenter.reloadHints, new Object[0]);
        getNotificationCenter().postNotificationName(NotificationCenter.reloadInlineHints, new Object[0]);
        if (Math.abs(getUserConfig().lastHintsSyncTime - ((int) (System.currentTimeMillis() / 1000))) >= 86400) {
            loadHints(false);
        }
    }

    public /* synthetic */ void lambda$loadHints$76$MediaDataController(final TLObject response, TLRPC.TL_error error) {
        if (response instanceof TLRPC.TL_contacts_topPeers) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$X3Qn6pGtd_IeM-z3ic_MWeDp3qY
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$74$MediaDataController(response);
                }
            });
        } else if (response instanceof TLRPC.TL_contacts_topPeersDisabled) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$XXm5OZFx0DU98EUa40VVKRawESk
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$75$MediaDataController();
                }
            });
        }
    }

    public /* synthetic */ void lambda$null$74$MediaDataController(TLObject response) {
        final TLRPC.TL_contacts_topPeers topPeers = (TLRPC.TL_contacts_topPeers) response;
        getMessagesController().putUsers(topPeers.users, false);
        getMessagesController().putChats(topPeers.chats, false);
        for (int a = 0; a < topPeers.categories.size(); a++) {
            TLRPC.TL_topPeerCategoryPeers category = topPeers.categories.get(a);
            if (category.category instanceof TLRPC.TL_topPeerCategoryBotsInline) {
                this.inlineBots = category.peers;
                getUserConfig().botRatingLoadTime = (int) (System.currentTimeMillis() / 1000);
            } else {
                this.hints = category.peers;
                int selfUserId = getUserConfig().getClientUserId();
                int b = 0;
                while (true) {
                    if (b >= this.hints.size()) {
                        break;
                    }
                    TLRPC.TL_topPeer topPeer = this.hints.get(b);
                    if (topPeer.peer.user_id != selfUserId) {
                        b++;
                    } else {
                        this.hints.remove(b);
                        break;
                    }
                }
                getUserConfig().ratingLoadTime = (int) (System.currentTimeMillis() / 1000);
            }
        }
        getUserConfig().saveConfig(false);
        buildShortcuts();
        getNotificationCenter().postNotificationName(NotificationCenter.reloadHints, new Object[0]);
        getNotificationCenter().postNotificationName(NotificationCenter.reloadInlineHints, new Object[0]);
        getMessagesStorage().getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$g2Gg88oihCCp7HX87JpKplw95WI
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$73$MediaDataController(topPeers);
            }
        });
    }

    public /* synthetic */ void lambda$null$73$MediaDataController(TLRPC.TL_contacts_topPeers topPeers) {
        SQLitePreparedStatement state = null;
        try {
            try {
                getMessagesStorage().getDatabase().executeFast("DELETE FROM chat_hints WHERE 1").stepThis().dispose();
                try {
                    getMessagesStorage().getDatabase().beginTransaction();
                } catch (Exception e) {
                    FileLog.e("loadHints ---> exception 1 ", e);
                }
                getMessagesStorage().putUsersAndChats(topPeers.users, topPeers.chats, false, true);
                SQLitePreparedStatement state2 = getMessagesStorage().getDatabase().executeFast("REPLACE INTO chat_hints VALUES(?, ?, ?, ?)");
                for (int a = 0; a < topPeers.categories.size(); a++) {
                    TLRPC.TL_topPeerCategoryPeers category = topPeers.categories.get(a);
                    int type = category.category instanceof TLRPC.TL_topPeerCategoryBotsInline ? 1 : 0;
                    for (int b = 0; b < category.peers.size(); b++) {
                        TLRPC.TL_topPeer peer = category.peers.get(b);
                        int did = peer.peer instanceof TLRPC.TL_peerUser ? peer.peer.user_id : peer.peer instanceof TLRPC.TL_peerChat ? -peer.peer.chat_id : -peer.peer.channel_id;
                        state2.requery();
                        state2.bindInteger(1, did);
                        state2.bindInteger(2, type);
                        state2.bindDouble(3, peer.rating);
                        state2.bindInteger(4, 0);
                        state2.step();
                    }
                }
                state2.dispose();
                state = null;
                getMessagesStorage().getDatabase().commitTransaction();
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$qd9G8u-NDp0jmyRnPOb3MagZUVI
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$72$MediaDataController();
                    }
                });
                if (0 == 0) {
                    return;
                }
            } catch (Exception e2) {
                FileLog.e("loadHints ---> exception 2 ", e2);
                if (state == null) {
                    return;
                }
            }
            state.dispose();
        } catch (Throwable th) {
            if (state != null) {
                state.dispose();
            }
            throw th;
        }
    }

    public /* synthetic */ void lambda$null$72$MediaDataController() {
        getUserConfig().suggestContacts = true;
        getUserConfig().lastHintsSyncTime = (int) (System.currentTimeMillis() / 1000);
        getUserConfig().saveConfig(false);
    }

    public /* synthetic */ void lambda$null$75$MediaDataController() {
        getUserConfig().suggestContacts = false;
        getUserConfig().lastHintsSyncTime = (int) (System.currentTimeMillis() / 1000);
        getUserConfig().saveConfig(false);
        clearTopPeers();
    }

    public void clearTopPeers() {
        this.hints.clear();
        this.inlineBots.clear();
        getNotificationCenter().postNotificationName(NotificationCenter.reloadHints, new Object[0]);
        getNotificationCenter().postNotificationName(NotificationCenter.reloadInlineHints, new Object[0]);
        getMessagesStorage().getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$bvdZgOi3ca8NZ0jzwAZbrRHOd8A
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$clearTopPeers$77$MediaDataController();
            }
        });
        buildShortcuts();
    }

    public /* synthetic */ void lambda$clearTopPeers$77$MediaDataController() {
        try {
            getMessagesStorage().getDatabase().executeFast("DELETE FROM chat_hints WHERE 1").stepThis().dispose();
        } catch (Exception e) {
        }
    }

    public void increaseInlineRaiting(int uid) {
        int dt;
        if (!getUserConfig().suggestContacts) {
            return;
        }
        if (getUserConfig().botRatingLoadTime != 0) {
            dt = Math.max(1, ((int) (System.currentTimeMillis() / 1000)) - getUserConfig().botRatingLoadTime);
        } else {
            dt = 60;
        }
        TLRPC.TL_topPeer peer = null;
        int a = 0;
        while (true) {
            if (a >= this.inlineBots.size()) {
                break;
            }
            TLRPC.TL_topPeer p = this.inlineBots.get(a);
            if (p.peer.user_id != uid) {
                a++;
            } else {
                peer = p;
                break;
            }
        }
        if (peer == null) {
            peer = new TLRPC.TL_topPeer();
            peer.peer = new TLRPC.TL_peerUser();
            peer.peer.user_id = uid;
            this.inlineBots.add(peer);
        }
        peer.rating += Math.exp(dt / getMessagesController().ratingDecay);
        Collections.sort(this.inlineBots, new Comparator() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$UbOWzdD7ISsvBZqDP5UJPJltpdU
            @Override // java.util.Comparator
            public final int compare(Object obj, Object obj2) {
                return MediaDataController.lambda$increaseInlineRaiting$78((TLRPC.TL_topPeer) obj, (TLRPC.TL_topPeer) obj2);
            }
        });
        if (this.inlineBots.size() > 20) {
            ArrayList<TLRPC.TL_topPeer> arrayList = this.inlineBots;
            arrayList.remove(arrayList.size() - 1);
        }
        savePeer(uid, 1, peer.rating);
        getNotificationCenter().postNotificationName(NotificationCenter.reloadInlineHints, new Object[0]);
    }

    static /* synthetic */ int lambda$increaseInlineRaiting$78(TLRPC.TL_topPeer lhs, TLRPC.TL_topPeer rhs) {
        if (lhs.rating > rhs.rating) {
            return -1;
        }
        if (lhs.rating < rhs.rating) {
            return 1;
        }
        return 0;
    }

    public void removeInline(int uid) {
        for (int a = 0; a < this.inlineBots.size(); a++) {
            if (this.inlineBots.get(a).peer.user_id == uid) {
                this.inlineBots.remove(a);
                TLRPC.TL_contacts_resetTopPeerRating req = new TLRPC.TL_contacts_resetTopPeerRating();
                req.category = new TLRPC.TL_topPeerCategoryBotsInline();
                req.peer = getMessagesController().getInputPeer(uid);
                getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$Dgnrc4esAjWf8mfO7wVB3ZYYrZg
                    @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                    public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                        MediaDataController.lambda$removeInline$79(tLObject, tL_error);
                    }
                });
                deletePeer(uid, 1);
                getNotificationCenter().postNotificationName(NotificationCenter.reloadInlineHints, new Object[0]);
                return;
            }
        }
    }

    static /* synthetic */ void lambda$removeInline$79(TLObject response, TLRPC.TL_error error) {
    }

    public void removePeer(int uid) {
        for (int a = 0; a < this.hints.size(); a++) {
            if (this.hints.get(a).peer.user_id == uid) {
                this.hints.remove(a);
                getNotificationCenter().postNotificationName(NotificationCenter.reloadHints, new Object[0]);
                TLRPC.TL_contacts_resetTopPeerRating req = new TLRPC.TL_contacts_resetTopPeerRating();
                req.category = new TLRPC.TL_topPeerCategoryCorrespondents();
                req.peer = getMessagesController().getInputPeer(uid);
                deletePeer(uid, 0);
                getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$Ah8BQ39DdW2yDFJDhV7jAeo7z1U
                    @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                    public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                        MediaDataController.lambda$removePeer$80(tLObject, tL_error);
                    }
                });
                return;
            }
        }
    }

    static /* synthetic */ void lambda$removePeer$80(TLObject response, TLRPC.TL_error error) {
    }

    public void increasePeerRaiting(final long did) {
        final int lower_id;
        if (!getUserConfig().suggestContacts || (lower_id = (int) did) <= 0) {
            return;
        }
        TLRPC.User user = lower_id > 0 ? getMessagesController().getUser(Integer.valueOf(lower_id)) : null;
        if (user == null || user.bot || user.self) {
            return;
        }
        getMessagesStorage().getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$7choSq5TGnGCBpi0R81inDz8awM
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$increasePeerRaiting$83$MediaDataController(did, lower_id);
            }
        });
    }

    public /* synthetic */ void lambda$increasePeerRaiting$83$MediaDataController(final long did, final int lower_id) {
        double dt = FirebaseRemoteConfig.DEFAULT_VALUE_FOR_DOUBLE;
        int lastTime = 0;
        int lastMid = 0;
        try {
            SQLiteCursor cursor = getMessagesStorage().getDatabase().queryFinalized(String.format(Locale.US, "SELECT MAX(mid), MAX(date) FROM messages WHERE uid = %d AND out = 1", Long.valueOf(did)), new Object[0]);
            if (cursor.next()) {
                lastMid = cursor.intValue(0);
                lastTime = cursor.intValue(1);
            }
            cursor.dispose();
            if (lastMid > 0 && getUserConfig().ratingLoadTime != 0) {
                dt = lastTime - getUserConfig().ratingLoadTime;
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
        final double dtFinal = dt;
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$GWtq4xdvIObnBxZmzxFCnb94cyQ
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$82$MediaDataController(lower_id, dtFinal, did);
            }
        });
    }

    public /* synthetic */ void lambda$null$82$MediaDataController(int lower_id, double dtFinal, long did) {
        TLRPC.TL_topPeer peer = null;
        for (int a = 0; a < this.hints.size(); a++) {
            TLRPC.TL_topPeer p = this.hints.get(a);
            if ((lower_id < 0 && (p.peer.chat_id == (-lower_id) || p.peer.channel_id == (-lower_id))) || (lower_id > 0 && p.peer.user_id == lower_id)) {
                peer = p;
                break;
            }
        }
        if (peer == null) {
            peer = new TLRPC.TL_topPeer();
            if (lower_id > 0) {
                peer.peer = new TLRPC.TL_peerUser();
                peer.peer.user_id = lower_id;
            } else {
                peer.peer = new TLRPC.TL_peerChat();
                peer.peer.chat_id = -lower_id;
            }
            this.hints.add(peer);
        }
        peer.rating += Math.exp(dtFinal / ((double) getMessagesController().ratingDecay));
        Collections.sort(this.hints, new Comparator() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$5XywY5v9J2xbL2Yb4YBicPq4Kp0
            @Override // java.util.Comparator
            public final int compare(Object obj, Object obj2) {
                return MediaDataController.lambda$null$81((TLRPC.TL_topPeer) obj, (TLRPC.TL_topPeer) obj2);
            }
        });
        savePeer((int) did, 0, peer.rating);
        getNotificationCenter().postNotificationName(NotificationCenter.reloadHints, new Object[0]);
    }

    static /* synthetic */ int lambda$null$81(TLRPC.TL_topPeer lhs, TLRPC.TL_topPeer rhs) {
        if (lhs.rating > rhs.rating) {
            return -1;
        }
        if (lhs.rating < rhs.rating) {
            return 1;
        }
        return 0;
    }

    private void savePeer(final int did, final int type, final double rating) {
        getMessagesStorage().getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$U5t5XSKyFw_ItEQ44FsUxbul3Lo
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$savePeer$84$MediaDataController(did, type, rating);
            }
        });
    }

    public /* synthetic */ void lambda$savePeer$84$MediaDataController(int did, int type, double rating) {
        try {
            SQLitePreparedStatement state = getMessagesStorage().getDatabase().executeFast("REPLACE INTO chat_hints VALUES(?, ?, ?, ?)");
            state.requery();
            state.bindInteger(1, did);
            state.bindInteger(2, type);
            state.bindDouble(3, rating);
            state.bindInteger(4, ((int) System.currentTimeMillis()) / 1000);
            state.step();
            state.dispose();
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    private void deletePeer(final int did, final int type) {
        getMessagesStorage().getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$_gSWlW-05weLb4m_S0tu3VRZOy4
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$deletePeer$85$MediaDataController(did, type);
            }
        });
    }

    public /* synthetic */ void lambda$deletePeer$85$MediaDataController(int did, int type) {
        try {
            getMessagesStorage().getDatabase().executeFast(String.format(Locale.US, "DELETE FROM chat_hints WHERE did = %d AND type = %d", Integer.valueOf(did), Integer.valueOf(type))).stepThis().dispose();
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    private Intent createIntrnalShortcutIntent(long did) {
        Intent shortcutIntent = new Intent(ApplicationLoader.applicationContext, (Class<?>) OpenChatReceiver.class);
        int lower_id = (int) did;
        int high_id = (int) (did >> 32);
        if (lower_id == 0) {
            shortcutIntent.putExtra("encId", high_id);
            TLRPC.EncryptedChat encryptedChat = getMessagesController().getEncryptedChat(Integer.valueOf(high_id));
            if (encryptedChat == null) {
                return null;
            }
        } else if (lower_id > 0) {
            shortcutIntent.putExtra("userId", lower_id);
        } else {
            if (lower_id >= 0) {
                return null;
            }
            shortcutIntent.putExtra("chatId", -lower_id);
        }
        shortcutIntent.putExtra("currentAccount", this.currentAccount);
        shortcutIntent.setAction("com.tmessages.openchat" + did);
        shortcutIntent.addFlags(ConnectionsManager.FileTypeFile);
        return shortcutIntent;
    }

    /* JADX WARN: Removed duplicated region for block: B:100:0x0258 A[Catch: Exception -> 0x02bc, TryCatch #4 {Exception -> 0x02bc, blocks: (B:3:0x0002, B:5:0x0011, B:8:0x0020, B:18:0x005e, B:20:0x0064, B:82:0x01cf, B:84:0x01e1, B:86:0x0203, B:99:0x0244, B:88:0x020d, B:90:0x0211, B:91:0x021b, B:93:0x0227, B:95:0x022d, B:97:0x0231, B:98:0x023b, B:100:0x0258, B:102:0x025f, B:117:0x02a0, B:106:0x0269, B:108:0x026d, B:109:0x0277, B:111:0x0283, B:113:0x0289, B:115:0x028d, B:116:0x0297, B:81:0x01cc, B:21:0x0072, B:23:0x007e, B:25:0x008b, B:27:0x0091, B:10:0x0034, B:12:0x0046), top: B:129:0x0002 }] */
    /* JADX WARN: Removed duplicated region for block: B:134:0x00ef A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:45:0x00d9  */
    /* JADX WARN: Removed duplicated region for block: B:56:0x0118  */
    /* JADX WARN: Removed duplicated region for block: B:84:0x01e1 A[Catch: Exception -> 0x02bc, TryCatch #4 {Exception -> 0x02bc, blocks: (B:3:0x0002, B:5:0x0011, B:8:0x0020, B:18:0x005e, B:20:0x0064, B:82:0x01cf, B:84:0x01e1, B:86:0x0203, B:99:0x0244, B:88:0x020d, B:90:0x0211, B:91:0x021b, B:93:0x0227, B:95:0x022d, B:97:0x0231, B:98:0x023b, B:100:0x0258, B:102:0x025f, B:117:0x02a0, B:106:0x0269, B:108:0x026d, B:109:0x0277, B:111:0x0283, B:113:0x0289, B:115:0x028d, B:116:0x0297, B:81:0x01cc, B:21:0x0072, B:23:0x007e, B:25:0x008b, B:27:0x0091, B:10:0x0034, B:12:0x0046), top: B:129:0x0002 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void installShortcut(long r21) {
        /*
            Method dump skipped, instruction units count: 705
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MediaDataController.installShortcut(long):void");
    }

    public void uninstallShortcut(long did) {
        String name;
        try {
            if (Build.VERSION.SDK_INT >= 26) {
                ShortcutManager shortcutManager = (ShortcutManager) ApplicationLoader.applicationContext.getSystemService(ShortcutManager.class);
                ArrayList<String> arrayList = new ArrayList<>();
                arrayList.add("sdid_" + did);
                shortcutManager.removeDynamicShortcuts(arrayList);
                return;
            }
            int lower_id = (int) did;
            int high_id = (int) (did >> 32);
            TLRPC.User user = null;
            TLRPC.Chat chat = null;
            if (lower_id == 0) {
                TLRPC.EncryptedChat encryptedChat = getMessagesController().getEncryptedChat(Integer.valueOf(high_id));
                if (encryptedChat == null) {
                    return;
                } else {
                    user = getMessagesController().getUser(Integer.valueOf(encryptedChat.user_id));
                }
            } else if (lower_id > 0) {
                user = getMessagesController().getUser(Integer.valueOf(lower_id));
            } else if (lower_id < 0) {
                chat = getMessagesController().getChat(Integer.valueOf(-lower_id));
            } else {
                return;
            }
            if (user == null && chat == null) {
                return;
            }
            if (user != null) {
                name = ContactsController.formatName(user.first_name, user.last_name);
            } else {
                name = chat.title;
            }
            Intent addIntent = new Intent();
            addIntent.putExtra("android.intent.extra.shortcut.INTENT", createIntrnalShortcutIntent(did));
            addIntent.putExtra("android.intent.extra.shortcut.NAME", name);
            addIntent.putExtra("duplicate", false);
            addIntent.setAction("com.android.launcher.action.UNINSTALL_SHORTCUT");
            ApplicationLoader.applicationContext.sendBroadcast(addIntent);
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    static /* synthetic */ int lambda$static$86(TLRPC.MessageEntity entity1, TLRPC.MessageEntity entity2) {
        if (entity1.offset > entity2.offset) {
            return 1;
        }
        if (entity1.offset < entity2.offset) {
            return -1;
        }
        return 0;
    }

    public MessageObject loadPinnedMessage(final long dialogId, final int channelId, final int mid, boolean useQueue) {
        if (useQueue) {
            getMessagesStorage().getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$mbpqnQMgCeoSqXXrutVU8Mkmt0A
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$loadPinnedMessage$87$MediaDataController(dialogId, channelId, mid);
                }
            });
            return null;
        }
        return loadPinnedMessageInternal(dialogId, channelId, mid, true);
    }

    public /* synthetic */ void lambda$loadPinnedMessage$87$MediaDataController(long dialogId, int channelId, int mid) {
        loadPinnedMessageInternal(dialogId, channelId, mid, false);
    }

    private MessageObject loadPinnedMessageInternal(long dialogId, final int channelId, int mid, boolean returnValue) {
        long messageId;
        TLRPC.Message result;
        TLRPC.Message result2;
        ArrayList<Integer> usersToLoad;
        ArrayList<Integer> chatsToLoad;
        TLRPC.Message result3;
        NativeByteBuffer data;
        NativeByteBuffer data2;
        if (channelId != 0) {
            messageId = ((long) mid) | (((long) channelId) << 32);
        } else {
            long messageId2 = mid;
            messageId = messageId2;
        }
        try {
            ArrayList<TLRPC.User> users = new ArrayList<>();
            ArrayList<TLRPC.Chat> chats = new ArrayList<>();
            ArrayList<Integer> usersToLoad2 = new ArrayList<>();
            ArrayList<Integer> chatsToLoad2 = new ArrayList<>();
            SQLiteCursor cursor = getMessagesStorage().getDatabase().queryFinalized(String.format(Locale.US, "SELECT data, mid, date FROM messages WHERE mid = %d", Long.valueOf(messageId)), new Object[0]);
            if (cursor.next() && (data2 = cursor.byteBufferValue(0)) != null) {
                result = TLRPC.Message.TLdeserialize(data2, data2.readInt32(false), false);
                result.readAttachPath(data2, getUserConfig().clientUserId);
                data2.reuse();
                if (result.action instanceof TLRPC.TL_messageActionHistoryClear) {
                    result = null;
                } else {
                    result.id = cursor.intValue(1);
                    result.date = cursor.intValue(2);
                    result.dialog_id = dialogId;
                    MessagesStorage.addUsersAndChatsFromMessage(result, usersToLoad2, chatsToLoad2);
                }
            } else {
                result = null;
            }
            cursor.dispose();
            if (result == null) {
                TLRPC.Message result4 = result;
                SQLiteCursor cursor2 = getMessagesStorage().getDatabase().queryFinalized(String.format(Locale.US, "SELECT data FROM chat_pinned WHERE uid = %d", Long.valueOf(dialogId)), new Object[0]);
                if (cursor2.next() && (data = cursor2.byteBufferValue(0)) != null) {
                    TLRPC.Message result5 = TLRPC.Message.TLdeserialize(data, data.readInt32(false), false);
                    result5.readAttachPath(data, getUserConfig().clientUserId);
                    data.reuse();
                    if (result5.id != mid || (result5.action instanceof TLRPC.TL_messageActionHistoryClear)) {
                        result3 = null;
                    } else {
                        result5.dialog_id = dialogId;
                        MessagesStorage.addUsersAndChatsFromMessage(result5, usersToLoad2, chatsToLoad2);
                        result3 = result5;
                    }
                } else {
                    result3 = result4;
                }
                cursor2.dispose();
                result2 = result3;
            } else {
                result2 = result;
            }
            if (result2 == null) {
                if (channelId != 0) {
                    TLRPC.TL_channels_getMessages req = new TLRPC.TL_channels_getMessages();
                    req.channel = getMessagesController().getInputChannel(channelId);
                    req.id.add(Integer.valueOf(mid));
                    getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$hQrmlucYp6UgK7ZF1n-OuOcXi1E
                        @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                        public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                            this.f$0.lambda$loadPinnedMessageInternal$88$MediaDataController(channelId, tLObject, tL_error);
                        }
                    });
                    return null;
                }
                TLRPC.TL_messages_getMessages req2 = new TLRPC.TL_messages_getMessages();
                req2.id.add(Integer.valueOf(mid));
                getConnectionsManager().sendRequest(req2, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$NIcGcJXKKxlo5wB0gy8_4c0p0bY
                    @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                    public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                        this.f$0.lambda$loadPinnedMessageInternal$89$MediaDataController(channelId, tLObject, tL_error);
                    }
                });
                return null;
            }
            if (returnValue) {
                return broadcastPinnedMessage(result2, users, chats, true, returnValue);
            }
            if (usersToLoad2.isEmpty()) {
                usersToLoad = usersToLoad2;
            } else {
                usersToLoad = usersToLoad2;
                getMessagesStorage().getUsersInternal(TextUtils.join(",", usersToLoad), users);
            }
            if (!chatsToLoad2.isEmpty()) {
                chatsToLoad = chatsToLoad2;
                getMessagesStorage().getChatsInternal(TextUtils.join(",", chatsToLoad), chats);
            } else {
                chatsToLoad = chatsToLoad2;
            }
            broadcastPinnedMessage(result2, users, chats, true, false);
            return null;
        } catch (Exception e) {
            FileLog.e(e);
            return null;
        }
    }

    public /* synthetic */ void lambda$loadPinnedMessageInternal$88$MediaDataController(int channelId, TLObject response, TLRPC.TL_error error) {
        boolean ok = false;
        if (error == null) {
            TLRPC.messages_Messages messagesRes = (TLRPC.messages_Messages) response;
            removeEmptyMessages(messagesRes.messages);
            if (!messagesRes.messages.isEmpty()) {
                ImageLoader.saveMessagesThumbs(messagesRes.messages);
                broadcastPinnedMessage(messagesRes.messages.get(0), messagesRes.users, messagesRes.chats, false, false);
                getMessagesStorage().putUsersAndChats(messagesRes.users, messagesRes.chats, true, true);
                savePinnedMessage(messagesRes.messages.get(0));
                ok = true;
            }
        }
        if (!ok) {
            getMessagesStorage().updateChatPinnedMessage(channelId, 0);
        }
    }

    public /* synthetic */ void lambda$loadPinnedMessageInternal$89$MediaDataController(int channelId, TLObject response, TLRPC.TL_error error) {
        boolean ok = false;
        if (error == null) {
            TLRPC.messages_Messages messagesRes = (TLRPC.messages_Messages) response;
            removeEmptyMessages(messagesRes.messages);
            if (!messagesRes.messages.isEmpty()) {
                ImageLoader.saveMessagesThumbs(messagesRes.messages);
                broadcastPinnedMessage(messagesRes.messages.get(0), messagesRes.users, messagesRes.chats, false, false);
                getMessagesStorage().putUsersAndChats(messagesRes.users, messagesRes.chats, true, true);
                savePinnedMessage(messagesRes.messages.get(0));
                ok = true;
            }
        }
        if (!ok) {
            getMessagesStorage().updateChatPinnedMessage(channelId, 0);
        }
    }

    private void savePinnedMessage(final TLRPC.Message result) {
        getMessagesStorage().getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$koIjXxZ3gApvayMBwYmYhiGn2P0
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$savePinnedMessage$90$MediaDataController(result);
            }
        });
    }

    public /* synthetic */ void lambda$savePinnedMessage$90$MediaDataController(TLRPC.Message result) {
        long dialogId;
        NativeByteBuffer data = null;
        SQLitePreparedStatement state = null;
        try {
            try {
                if (result.to_id.channel_id != 0) {
                    dialogId = -result.to_id.channel_id;
                } else if (result.to_id.chat_id != 0) {
                    dialogId = -result.to_id.chat_id;
                } else {
                    if (result.to_id.user_id == 0) {
                        if (0 != 0) {
                            data.reuse();
                        }
                        if (0 != 0) {
                            state.dispose();
                            return;
                        }
                        return;
                    }
                    dialogId = result.to_id.user_id;
                }
                try {
                    getMessagesStorage().getDatabase().beginTransaction();
                } catch (Exception e) {
                    FileLog.e("savePinnedMessage ---> exception 1 ", e);
                }
                SQLitePreparedStatement state2 = getMessagesStorage().getDatabase().executeFast("REPLACE INTO chat_pinned VALUES(?, ?, ?)");
                NativeByteBuffer data2 = new NativeByteBuffer(result.getObjectSize());
                result.serializeToStream(data2);
                state2.requery();
                state2.bindLong(1, dialogId);
                state2.bindInteger(2, result.id);
                state2.bindByteBuffer(3, data2);
                state2.step();
                data2.reuse();
                data = null;
                state2.dispose();
                state = null;
                getMessagesStorage().getDatabase().commitTransaction();
                if (0 != 0) {
                    data.reuse();
                }
                if (0 == 0) {
                    return;
                }
            } catch (Exception e2) {
                FileLog.e("savePinnedMessage ---> exception 2 ", e2);
                if (data != null) {
                    data.reuse();
                }
                if (state == null) {
                    return;
                }
            }
            state.dispose();
        } catch (Throwable th) {
            if (data != null) {
                data.reuse();
            }
            if (state != null) {
                state.dispose();
            }
            throw th;
        }
    }

    private MessageObject broadcastPinnedMessage(final TLRPC.Message result, final ArrayList<TLRPC.User> users, final ArrayList<TLRPC.Chat> chats, final boolean isCache, boolean returnValue) {
        final SparseArray<TLRPC.User> usersDict = new SparseArray<>();
        for (int a = 0; a < users.size(); a++) {
            TLRPC.User user = users.get(a);
            usersDict.put(user.id, user);
        }
        final SparseArray<TLRPC.Chat> chatsDict = new SparseArray<>();
        for (int a2 = 0; a2 < chats.size(); a2++) {
            TLRPC.Chat chat = chats.get(a2);
            chatsDict.put(chat.id, chat);
        }
        if (returnValue) {
            return new MessageObject(this.currentAccount, result, usersDict, chatsDict, false);
        }
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$mSXdDLxpmiS8GQiiMl5V0I696Gc
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$broadcastPinnedMessage$91$MediaDataController(users, isCache, chats, result, usersDict, chatsDict);
            }
        });
        return null;
    }

    public /* synthetic */ void lambda$broadcastPinnedMessage$91$MediaDataController(ArrayList users, boolean isCache, ArrayList chats, TLRPC.Message result, SparseArray usersDict, SparseArray chatsDict) {
        getMessagesController().putUsers(users, isCache);
        getMessagesController().putChats(chats, isCache);
        getNotificationCenter().postNotificationName(NotificationCenter.pinnedMessageDidLoad, new MessageObject(this.currentAccount, result, (SparseArray<TLRPC.User>) usersDict, (SparseArray<TLRPC.Chat>) chatsDict, false));
    }

    private static void removeEmptyMessages(ArrayList<TLRPC.Message> messages) {
        int a = 0;
        while (a < messages.size()) {
            TLRPC.Message message = messages.get(a);
            if (message == null || (message instanceof TLRPC.TL_messageEmpty) || (message.action instanceof TLRPC.TL_messageActionHistoryClear)) {
                messages.remove(a);
                a--;
            }
            a++;
        }
    }

    /* JADX WARN: Incorrect condition in loop: B:24:0x008f */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void loadReplyMessagesForMessages(java.util.ArrayList<im.uwrkaxlmjj.messenger.MessageObject> r17, final long r18, final boolean r20) {
        /*
            Method dump skipped, instruction units count: 288
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MediaDataController.loadReplyMessagesForMessages(java.util.ArrayList, long, boolean):void");
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r11v0 */
    /* JADX WARN: Type inference failed for: r11v1, types: [boolean, int] */
    /* JADX WARN: Type inference failed for: r11v3 */
    public /* synthetic */ void lambda$loadReplyMessagesForMessages$93$MediaDataController(ArrayList replyMessages, final long dialogId, LongSparseArray replyMessageRandomOwners) {
        SQLiteDatabase database;
        Locale locale;
        int i;
        Object[] objArr;
        try {
            database = getMessagesStorage().getDatabase();
            locale = Locale.US;
            i = 1;
            objArr = new Object[1];
        } catch (Exception e) {
            e = e;
        }
        try {
            ?? r11 = 0;
            objArr[0] = TextUtils.join(",", replyMessages);
            SQLiteCursor sQLiteCursorQueryFinalized = database.queryFinalized(String.format(locale, "SELECT m.data, m.mid, m.date, r.random_id FROM randoms as r INNER JOIN messages as m ON r.mid = m.mid WHERE r.random_id IN(%s)", objArr), new Object[0]);
            while (sQLiteCursorQueryFinalized.next()) {
                NativeByteBuffer nativeByteBufferByteBufferValue = sQLiteCursorQueryFinalized.byteBufferValue(r11);
                if (nativeByteBufferByteBufferValue != 0) {
                    TLRPC.Message messageTLdeserialize = TLRPC.Message.TLdeserialize(nativeByteBufferByteBufferValue, nativeByteBufferByteBufferValue.readInt32(r11), r11);
                    messageTLdeserialize.readAttachPath(nativeByteBufferByteBufferValue, getUserConfig().clientUserId);
                    nativeByteBufferByteBufferValue.reuse();
                    messageTLdeserialize.id = sQLiteCursorQueryFinalized.intValue(i);
                    messageTLdeserialize.date = sQLiteCursorQueryFinalized.intValue(2);
                    messageTLdeserialize.dialog_id = dialogId;
                    long value = sQLiteCursorQueryFinalized.longValue(3);
                    ArrayList<MessageObject> arrayList = (ArrayList) replyMessageRandomOwners.get(value);
                    replyMessageRandomOwners.remove(value);
                    if (arrayList != null) {
                        MessageObject messageObject = new MessageObject(this.currentAccount, messageTLdeserialize, r11);
                        for (int b = 0; b < arrayList.size(); b++) {
                            MessageObject object = arrayList.get(b);
                            object.replyMessageObject = messageObject;
                            object.messageOwner.reply_to_msg_id = messageObject.getId();
                            if (object.isMegagroup()) {
                                object.replyMessageObject.messageOwner.flags |= Integer.MIN_VALUE;
                            }
                        }
                    }
                }
                i = 1;
                r11 = 0;
            }
            sQLiteCursorQueryFinalized.dispose();
            if (replyMessageRandomOwners.size() != 0) {
                for (int b2 = 0; b2 < replyMessageRandomOwners.size(); b2++) {
                    ArrayList<MessageObject> arrayList2 = (ArrayList) replyMessageRandomOwners.valueAt(b2);
                    for (int a = 0; a < arrayList2.size(); a++) {
                        arrayList2.get(a).messageOwner.reply_to_random_id = 0L;
                    }
                }
            }
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$9Sl4BxJHlCa0krGnjBc2uPTF0Q4
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$92$MediaDataController(dialogId);
                }
            });
        } catch (Exception e2) {
            e = e2;
            FileLog.e(e);
        }
    }

    public /* synthetic */ void lambda$null$92$MediaDataController(long dialogId) {
        getNotificationCenter().postNotificationName(NotificationCenter.replyMessagesDidLoad, Long.valueOf(dialogId));
    }

    public /* synthetic */ void lambda$loadReplyMessagesForMessages$96$MediaDataController(StringBuilder stringBuilder, final long dialogId, ArrayList replyMessages, final SparseArray replyMessageOwners, int channelIdFinal, final boolean scheduled) {
        try {
            ArrayList<TLRPC.Message> result = new ArrayList<>();
            ArrayList<TLRPC.User> users = new ArrayList<>();
            ArrayList<TLRPC.Chat> chats = new ArrayList<>();
            ArrayList<Integer> usersToLoad = new ArrayList<>();
            ArrayList<Integer> chatsToLoad = new ArrayList<>();
            SQLiteCursor cursor = getMessagesStorage().getDatabase().queryFinalized(String.format(Locale.US, "SELECT data, mid, date FROM messages WHERE mid IN(%s)", stringBuilder.toString()), new Object[0]);
            while (cursor.next()) {
                try {
                    NativeByteBuffer data = cursor.byteBufferValue(0);
                    if (data != null) {
                        TLRPC.Message message = TLRPC.Message.TLdeserialize(data, data.readInt32(false), false);
                        message.readAttachPath(data, getUserConfig().clientUserId);
                        data.reuse();
                        message.id = cursor.intValue(1);
                        message.date = cursor.intValue(2);
                        message.dialog_id = dialogId;
                        MessagesStorage.addUsersAndChatsFromMessage(message, usersToLoad, chatsToLoad);
                        result.add(message);
                        replyMessages.remove(Integer.valueOf(message.id));
                    }
                } catch (Exception e) {
                    e = e;
                    FileLog.e(e);
                    return;
                }
            }
            cursor.dispose();
            if (!usersToLoad.isEmpty()) {
                getMessagesStorage().getUsersInternal(TextUtils.join(",", usersToLoad), users);
            }
            if (!chatsToLoad.isEmpty()) {
                getMessagesStorage().getChatsInternal(TextUtils.join(",", chatsToLoad), chats);
            }
            broadcastReplyMessages(result, replyMessageOwners, users, chats, dialogId, true);
            if (!replyMessages.isEmpty()) {
                if (channelIdFinal != 0) {
                    TLRPC.TL_channels_getMessages req = new TLRPC.TL_channels_getMessages();
                    req.channel = getMessagesController().getInputChannel(channelIdFinal);
                    req.id = replyMessages;
                    getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$_8jJyDdG49-1TIuVj4bY-5yqJvE
                        @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                        public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                            this.f$0.lambda$null$94$MediaDataController(replyMessageOwners, dialogId, scheduled, tLObject, tL_error);
                        }
                    });
                    return;
                }
                TLRPC.TL_messages_getMessages req2 = new TLRPC.TL_messages_getMessages();
                req2.id = replyMessages;
                getConnectionsManager().sendRequest(req2, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$uWWOQnKYxh5LqXs36k8jwV8Ankw
                    @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                    public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                        this.f$0.lambda$null$95$MediaDataController(replyMessageOwners, dialogId, scheduled, tLObject, tL_error);
                    }
                });
            }
        } catch (Exception e2) {
            e = e2;
        }
    }

    public /* synthetic */ void lambda$null$94$MediaDataController(SparseArray replyMessageOwners, long dialogId, boolean scheduled, TLObject response, TLRPC.TL_error error) {
        if (error == null) {
            TLRPC.messages_Messages messagesRes = (TLRPC.messages_Messages) response;
            removeEmptyMessages(messagesRes.messages);
            ImageLoader.saveMessagesThumbs(messagesRes.messages);
            broadcastReplyMessages(messagesRes.messages, replyMessageOwners, messagesRes.users, messagesRes.chats, dialogId, false);
            getMessagesStorage().putUsersAndChats(messagesRes.users, messagesRes.chats, true, true);
            saveReplyMessages(replyMessageOwners, messagesRes.messages, scheduled);
        }
    }

    public /* synthetic */ void lambda$null$95$MediaDataController(SparseArray replyMessageOwners, long dialogId, boolean scheduled, TLObject response, TLRPC.TL_error error) {
        if (error == null) {
            TLRPC.messages_Messages messagesRes = (TLRPC.messages_Messages) response;
            removeEmptyMessages(messagesRes.messages);
            ImageLoader.saveMessagesThumbs(messagesRes.messages);
            broadcastReplyMessages(messagesRes.messages, replyMessageOwners, messagesRes.users, messagesRes.chats, dialogId, false);
            getMessagesStorage().putUsersAndChats(messagesRes.users, messagesRes.chats, true, true);
            saveReplyMessages(replyMessageOwners, messagesRes.messages, scheduled);
        }
    }

    private void saveReplyMessages(final SparseArray<ArrayList<MessageObject>> replyMessageOwners, final ArrayList<TLRPC.Message> result, final boolean scheduled) {
        getMessagesStorage().getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$DUSV-zA4mgrpxBjiIOz62S3OtkY
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$saveReplyMessages$97$MediaDataController(scheduled, result, replyMessageOwners);
            }
        });
    }

    public /* synthetic */ void lambda$saveReplyMessages$97$MediaDataController(boolean scheduled, ArrayList result, SparseArray replyMessageOwners) {
        NativeByteBuffer data = null;
        SQLitePreparedStatement state = null;
        try {
            try {
                getMessagesStorage().getDatabase().beginTransaction();
            } catch (Exception e) {
                try {
                    FileLog.e("saveReplyMessages ---> exception 1 ", e);
                } catch (Exception e2) {
                    FileLog.e("saveReplyMessages ---> exception 2 ", e2);
                    if (data != null) {
                        data.reuse();
                    }
                    if (state == null) {
                        return;
                    }
                }
            }
            SQLitePreparedStatement state2 = scheduled ? getMessagesStorage().getDatabase().executeFast("UPDATE scheduled_messages SET replydata = ? WHERE mid = ?") : getMessagesStorage().getDatabase().executeFast("UPDATE messages SET replydata = ? WHERE mid = ?");
            for (int a = 0; a < result.size(); a++) {
                TLRPC.Message message = (TLRPC.Message) result.get(a);
                ArrayList<MessageObject> messageObjects = (ArrayList) replyMessageOwners.get(message.id);
                if (messageObjects != null) {
                    NativeByteBuffer data2 = new NativeByteBuffer(message.getObjectSize());
                    message.serializeToStream(data2);
                    for (int b = 0; b < messageObjects.size(); b++) {
                        MessageObject messageObject = messageObjects.get(b);
                        state2.requery();
                        long messageId = messageObject.getId();
                        if (messageObject.messageOwner.to_id.channel_id != 0) {
                            messageId |= ((long) messageObject.messageOwner.to_id.channel_id) << 32;
                        }
                        state2.bindByteBuffer(1, data2);
                        state2.bindLong(2, messageId);
                        state2.step();
                    }
                    data2.reuse();
                    data = null;
                }
            }
            state2.dispose();
            state = null;
            getMessagesStorage().getDatabase().commitTransaction();
            if (data != null) {
                data.reuse();
            }
            if (0 == 0) {
                return;
            }
            state.dispose();
        } catch (Throwable th) {
            if (data != null) {
                data.reuse();
            }
            if (state != null) {
                state.dispose();
            }
            throw th;
        }
    }

    private void broadcastReplyMessages(final ArrayList<TLRPC.Message> result, final SparseArray<ArrayList<MessageObject>> replyMessageOwners, final ArrayList<TLRPC.User> users, final ArrayList<TLRPC.Chat> chats, final long dialog_id, final boolean isCache) {
        final SparseArray<TLRPC.User> usersDict = new SparseArray<>();
        for (int a = 0; a < users.size(); a++) {
            TLRPC.User user = users.get(a);
            usersDict.put(user.id, user);
        }
        final SparseArray<TLRPC.Chat> chatsDict = new SparseArray<>();
        for (int a2 = 0; a2 < chats.size(); a2++) {
            TLRPC.Chat chat = chats.get(a2);
            chatsDict.put(chat.id, chat);
        }
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$MGTdR397vH9fb_r_JkXtRpcGCsg
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$broadcastReplyMessages$98$MediaDataController(users, isCache, chats, result, replyMessageOwners, usersDict, chatsDict, dialog_id);
            }
        });
    }

    public /* synthetic */ void lambda$broadcastReplyMessages$98$MediaDataController(ArrayList users, boolean isCache, ArrayList chats, ArrayList result, SparseArray replyMessageOwners, SparseArray usersDict, SparseArray chatsDict, long dialog_id) {
        getMessagesController().putUsers(users, isCache);
        getMessagesController().putChats(chats, isCache);
        boolean changed = false;
        for (int a = 0; a < result.size(); a++) {
            TLRPC.Message message = (TLRPC.Message) result.get(a);
            ArrayList<MessageObject> arrayList = (ArrayList) replyMessageOwners.get(message.id);
            if (arrayList != null) {
                MessageObject messageObject = new MessageObject(this.currentAccount, message, (SparseArray<TLRPC.User>) usersDict, (SparseArray<TLRPC.Chat>) chatsDict, false);
                for (int b = 0; b < arrayList.size(); b++) {
                    MessageObject m = arrayList.get(b);
                    m.replyMessageObject = messageObject;
                    if (m.messageOwner.action instanceof TLRPC.TL_messageActionPinMessage) {
                        m.generatePinMessageText(null, null);
                    } else if (m.messageOwner.action instanceof TLRPC.TL_messageActionGameScore) {
                        m.generateGameMessageText(null);
                    } else if (m.messageOwner.action instanceof TLRPC.TL_messageActionPaymentSent) {
                        m.generatePaymentSentMessageText(null);
                    }
                    if (m.isMegagroup()) {
                        m.replyMessageObject.messageOwner.flags |= Integer.MIN_VALUE;
                    }
                }
                changed = true;
            }
        }
        if (changed) {
            getNotificationCenter().postNotificationName(NotificationCenter.replyMessagesDidLoad, Long.valueOf(dialog_id));
        }
    }

    public static void sortEntities(ArrayList<TLRPC.MessageEntity> entities) {
        Collections.sort(entities, entityComparator);
    }

    private static boolean checkInclusion(int index, ArrayList<TLRPC.MessageEntity> entities) {
        if (entities == null || entities.isEmpty()) {
            return false;
        }
        int count = entities.size();
        for (int a = 0; a < count; a++) {
            TLRPC.MessageEntity entity = entities.get(a);
            if (entity.offset <= index && entity.offset + entity.length > index) {
                return true;
            }
        }
        return false;
    }

    private static boolean checkIntersection(int start, int end, ArrayList<TLRPC.MessageEntity> entities) {
        if (entities == null || entities.isEmpty()) {
            return false;
        }
        int count = entities.size();
        for (int a = 0; a < count; a++) {
            TLRPC.MessageEntity entity = entities.get(a);
            if (entity.offset > start && entity.offset + entity.length <= end) {
                return true;
            }
        }
        return false;
    }

    private static void removeOffsetAfter(int start, int countToRemove, ArrayList<TLRPC.MessageEntity> entities) {
        int count = entities.size();
        for (int a = 0; a < count; a++) {
            TLRPC.MessageEntity entity = entities.get(a);
            if (entity.offset > start) {
                entity.offset -= countToRemove;
            }
        }
    }

    public CharSequence substring(CharSequence source, int start, int end) {
        if (source instanceof SpannableStringBuilder) {
            return source.subSequence(start, end);
        }
        if (source instanceof SpannedString) {
            return source.subSequence(start, end);
        }
        return TextUtils.substring(source, start, end);
    }

    private static CharacterStyle createNewSpan(CharacterStyle baseSpan, TextStyleSpan.TextStyleRun textStyleRun, TextStyleSpan.TextStyleRun newStyleRun, boolean allowIntersection) {
        TextStyleSpan.TextStyleRun run = new TextStyleSpan.TextStyleRun(textStyleRun);
        if (newStyleRun != null) {
            if (allowIntersection) {
                run.merge(newStyleRun);
            } else {
                run.replace(newStyleRun);
            }
        }
        if (baseSpan instanceof TextStyleSpan) {
            return new TextStyleSpan(run);
        }
        if (baseSpan instanceof URLSpanReplacement) {
            URLSpanReplacement span = (URLSpanReplacement) baseSpan;
            return new URLSpanReplacement(span.getURL(), run);
        }
        return null;
    }

    /* JADX WARN: Unreachable blocks removed: 2, instructions: 3 */
    public static void addStyleToText(TextStyleSpan span, int start, int end, Spannable editable, boolean allowIntersection) {
        TextStyleSpan.TextStyleRun textStyleRun;
        int start2 = start;
        int end2 = end;
        try {
            CharacterStyle[] spans = (CharacterStyle[]) editable.getSpans(start2, end2, CharacterStyle.class);
            if (spans != null) {
                if (spans.length > 0) {
                    for (CharacterStyle oldSpan : spans) {
                        try {
                            TextStyleSpan.TextStyleRun newStyleRun = span != null ? span.getTextStyleRun() : new TextStyleSpan.TextStyleRun();
                            if (oldSpan instanceof TextStyleSpan) {
                                TextStyleSpan textStyleSpan = (TextStyleSpan) oldSpan;
                                textStyleRun = textStyleSpan.getTextStyleRun();
                            } else if (oldSpan instanceof URLSpanReplacement) {
                                URLSpanReplacement urlSpanReplacement = (URLSpanReplacement) oldSpan;
                                TextStyleSpan.TextStyleRun textStyleRun2 = urlSpanReplacement.getTextStyleRun();
                                if (textStyleRun2 != null) {
                                    textStyleRun = textStyleRun2;
                                } else {
                                    textStyleRun = new TextStyleSpan.TextStyleRun();
                                }
                            }
                            if (textStyleRun != null) {
                                int spanStart = editable.getSpanStart(oldSpan);
                                int spanEnd = editable.getSpanEnd(oldSpan);
                                editable.removeSpan(oldSpan);
                                if (spanStart > start2 && end2 > spanEnd) {
                                    editable.setSpan(createNewSpan(oldSpan, textStyleRun, newStyleRun, allowIntersection), spanStart, spanEnd, 33);
                                    if (span != null) {
                                        editable.setSpan(new TextStyleSpan(new TextStyleSpan.TextStyleRun(newStyleRun)), spanEnd, end2, 33);
                                    }
                                    end2 = spanStart;
                                } else {
                                    int startTemp = start2;
                                    if (spanStart <= start2) {
                                        if (spanStart != start2) {
                                            editable.setSpan(createNewSpan(oldSpan, textStyleRun, null, allowIntersection), spanStart, start2, 33);
                                        }
                                        if (spanEnd > start2) {
                                            if (span != null) {
                                                editable.setSpan(createNewSpan(oldSpan, textStyleRun, newStyleRun, allowIntersection), start2, Math.min(spanEnd, end2), 33);
                                            }
                                            start2 = spanEnd;
                                        }
                                    }
                                    if (spanEnd >= end2) {
                                        if (spanEnd != end2) {
                                            editable.setSpan(createNewSpan(oldSpan, textStyleRun, null, allowIntersection), end2, spanEnd, 33);
                                        }
                                        if (end2 > spanStart && spanEnd <= startTemp) {
                                            if (span != null) {
                                                editable.setSpan(createNewSpan(oldSpan, textStyleRun, newStyleRun, allowIntersection), spanStart, Math.min(spanEnd, end2), 33);
                                            }
                                            end2 = spanStart;
                                        }
                                    }
                                }
                            }
                        } catch (Exception e) {
                            e = e;
                            FileLog.e(e);
                            return;
                        }
                    }
                }
            }
            if (span != null && start2 < end2) {
                editable.setSpan(span, start2, end2, 33);
            }
        } catch (Exception e2) {
            e = e2;
        }
    }

    public static ArrayList<TextStyleSpan.TextStyleRun> getTextStyleRuns(ArrayList<TLRPC.MessageEntity> entities, CharSequence text) {
        ArrayList<TextStyleSpan.TextStyleRun> runs = new ArrayList<>();
        ArrayList<TLRPC.MessageEntity> entitiesCopy = new ArrayList<>(entities);
        Collections.sort(entitiesCopy, new Comparator() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$M_W-S8GqIUHeml-YEqNy-DUZCwY
            @Override // java.util.Comparator
            public final int compare(Object obj, Object obj2) {
                return MediaDataController.lambda$getTextStyleRuns$99((TLRPC.MessageEntity) obj, (TLRPC.MessageEntity) obj2);
            }
        });
        int N = entitiesCopy.size();
        for (int a = 0; a < N; a++) {
            TLRPC.MessageEntity entity = entitiesCopy.get(a);
            if (entity.length > 0 && entity.offset >= 0 && entity.offset < text.length()) {
                if (entity.offset + entity.length > text.length()) {
                    entity.length = text.length() - entity.offset;
                }
                TextStyleSpan.TextStyleRun newRun = new TextStyleSpan.TextStyleRun();
                newRun.start = entity.offset;
                newRun.end = newRun.start + entity.length;
                if (entity instanceof TLRPC.TL_messageEntityStrike) {
                    newRun.flags = 8;
                } else if (entity instanceof TLRPC.TL_messageEntityUnderline) {
                    newRun.flags = 16;
                } else if (entity instanceof TLRPC.TL_messageEntityBlockquote) {
                    newRun.flags = 32;
                } else if (entity instanceof TLRPC.TL_messageEntityBold) {
                    newRun.flags = 1;
                } else if (entity instanceof TLRPC.TL_messageEntityItalic) {
                    newRun.flags = 2;
                } else if ((entity instanceof TLRPC.TL_messageEntityCode) || (entity instanceof TLRPC.TL_messageEntityPre)) {
                    newRun.flags = 4;
                } else if ((entity instanceof TLRPC.TL_messageEntityMentionName) || (entity instanceof TLRPC.TL_inputMessageEntityMentionName)) {
                    newRun.flags = 64;
                    newRun.urlEntity = entity;
                } else {
                    newRun.flags = 128;
                    newRun.urlEntity = entity;
                }
                int b = 0;
                int N2 = runs.size();
                while (b < N2) {
                    TextStyleSpan.TextStyleRun run = runs.get(b);
                    if (newRun.start > run.start) {
                        if (newRun.start < run.end) {
                            if (newRun.end < run.end) {
                                TextStyleSpan.TextStyleRun r = new TextStyleSpan.TextStyleRun(newRun);
                                r.merge(run);
                                int b2 = b + 1;
                                runs.add(b2, r);
                                TextStyleSpan.TextStyleRun r2 = new TextStyleSpan.TextStyleRun(run);
                                r2.start = newRun.end;
                                b = b2 + 1;
                                N2 = N2 + 1 + 1;
                                runs.add(b, r2);
                            } else if (newRun.end >= run.end) {
                                TextStyleSpan.TextStyleRun r3 = new TextStyleSpan.TextStyleRun(newRun);
                                r3.merge(run);
                                r3.end = run.end;
                                b++;
                                N2++;
                                runs.add(b, r3);
                            }
                            int temp = newRun.start;
                            newRun.start = run.end;
                            run.end = temp;
                        }
                    } else if (run.start < newRun.end) {
                        int temp2 = run.start;
                        if (newRun.end == run.end) {
                            run.merge(newRun);
                        } else if (newRun.end < run.end) {
                            TextStyleSpan.TextStyleRun r4 = new TextStyleSpan.TextStyleRun(run);
                            r4.merge(newRun);
                            r4.end = newRun.end;
                            b++;
                            N2++;
                            runs.add(b, r4);
                            run.start = newRun.end;
                        } else {
                            TextStyleSpan.TextStyleRun r5 = new TextStyleSpan.TextStyleRun(newRun);
                            r5.start = run.end;
                            b++;
                            N2++;
                            runs.add(b, r5);
                            run.merge(newRun);
                        }
                        newRun.end = temp2;
                    }
                    b++;
                }
                int b3 = newRun.start;
                if (b3 < newRun.end) {
                    runs.add(newRun);
                }
            }
        }
        return runs;
    }

    static /* synthetic */ int lambda$getTextStyleRuns$99(TLRPC.MessageEntity o1, TLRPC.MessageEntity o2) {
        if (o1.offset > o2.offset) {
            return 1;
        }
        if (o1.offset < o2.offset) {
            return -1;
        }
        return 0;
    }

    public ArrayList<TLRPC.MessageEntity> getEntities(CharSequence[] message) {
        ArrayList<TLRPC.MessageEntity> entities;
        TLRPC.MessageEntity entity;
        TextStyleSpan[] spans;
        String mono;
        String pre;
        char c;
        int firstChar;
        char c2;
        char c3;
        if (message == null) {
            return null;
        }
        int i = 0;
        if (message[0] == null) {
            return null;
        }
        ArrayList<TLRPC.MessageEntity> entities2 = null;
        int start = -1;
        int lastIndex = 0;
        boolean isPre = false;
        String mono2 = "`";
        String pre2 = "```";
        while (true) {
            int iIndexOf = TextUtils.indexOf(message[i], !isPre ? "`" : "```", lastIndex);
            int index = iIndexOf;
            if (iIndexOf == -1) {
                break;
            }
            if (start == -1) {
                isPre = message[i].length() - index > 2 && message[i].charAt(index + 1) == '`' && message[i].charAt(index + 2) == '`';
                start = index;
                lastIndex = index + (isPre ? 3 : 1);
            } else {
                if (entities2 == null) {
                    entities2 = new ArrayList<>();
                }
                for (int a = (isPre ? 3 : 1) + index; a < message[i].length() && message[i].charAt(a) == '`'; a++) {
                    index++;
                }
                int lastIndex2 = (isPre ? 3 : 1) + index;
                if (isPre) {
                    int firstChar2 = start > 0 ? message[i].charAt(start - 1) : 0;
                    boolean replacedFirst = firstChar2 == 32 || firstChar2 == 10;
                    CharSequence startMessage = substring(message[i], i, start - (replacedFirst ? 1 : 0));
                    CharSequence content = substring(message[i], start + 3, index);
                    if (index + 3 < message[i].length()) {
                        c = 0;
                        firstChar = message[0].charAt(index + 3);
                    } else {
                        c = 0;
                        firstChar = 0;
                    }
                    mono = mono2;
                    CharSequence endMessage = substring(message[c], index + 3 + ((firstChar == 32 || firstChar == 10) ? 1 : 0), message[0].length());
                    if (startMessage.length() != 0) {
                        startMessage = AndroidUtilities.concat(startMessage, ShellAdbUtils.COMMAND_LINE_END);
                    } else {
                        replacedFirst = true;
                    }
                    if (endMessage.length() == 0) {
                        c2 = 0;
                        c3 = 1;
                    } else {
                        c2 = 0;
                        c3 = 1;
                        endMessage = AndroidUtilities.concat(ShellAdbUtils.COMMAND_LINE_END, endMessage);
                    }
                    if (TextUtils.isEmpty(content)) {
                        pre = pre2;
                    } else {
                        pre = pre2;
                        CharSequence[] charSequenceArr = new CharSequence[3];
                        charSequenceArr[c2] = startMessage;
                        charSequenceArr[c3] = content;
                        charSequenceArr[2] = endMessage;
                        message[c2] = AndroidUtilities.concat(charSequenceArr);
                        TLRPC.TL_messageEntityPre entity2 = new TLRPC.TL_messageEntityPre();
                        entity2.offset = (replacedFirst ? 0 : 1) + start;
                        entity2.length = ((index - start) - 3) + (replacedFirst ? 0 : 1);
                        entity2.language = "";
                        entities2.add(entity2);
                        lastIndex2 -= 6;
                    }
                } else {
                    mono = mono2;
                    pre = pre2;
                    if (start + 1 != index) {
                        message[0] = AndroidUtilities.concat(substring(message[0], 0, start), substring(message[0], start + 1, index), substring(message[0], index + 1, message[0].length()));
                        TLRPC.TL_messageEntityCode entity3 = new TLRPC.TL_messageEntityCode();
                        entity3.offset = start;
                        entity3.length = (index - start) - 1;
                        entities2.add(entity3);
                        lastIndex2 -= 2;
                    }
                }
                lastIndex = lastIndex2;
                start = -1;
                isPre = false;
                mono2 = mono;
                pre2 = pre;
                i = 0;
            }
        }
        if (start != -1 && isPre) {
            message[0] = AndroidUtilities.concat(substring(message[0], 0, start), substring(message[0], start + 2, message[0].length()));
            if (entities2 == null) {
                entities2 = new ArrayList<>();
            }
            TLRPC.TL_messageEntityCode entity4 = new TLRPC.TL_messageEntityCode();
            entity4.offset = start;
            entity4.length = 1;
            entities2.add(entity4);
        }
        if (message[0] instanceof Spanned) {
            Spanned spannable = (Spanned) message[0];
            TextStyleSpan[] spans2 = (TextStyleSpan[]) spannable.getSpans(0, message[0].length(), TextStyleSpan.class);
            if (spans2 != null && spans2.length > 0) {
                int a2 = 0;
                while (a2 < spans2.length) {
                    TextStyleSpan span = spans2[a2];
                    int spanStart = spannable.getSpanStart(span);
                    int spanEnd = spannable.getSpanEnd(span);
                    if (checkInclusion(spanStart, entities2) || checkInclusion(spanEnd, entities2)) {
                        spans = spans2;
                    } else if (checkIntersection(spanStart, spanEnd, entities2)) {
                        spans = spans2;
                    } else {
                        if (entities2 == null) {
                            entities2 = new ArrayList<>();
                        }
                        int flags = span.getStyleFlags();
                        if ((flags & 1) == 0) {
                            spans = spans2;
                        } else {
                            TLRPC.MessageEntity entity5 = new TLRPC.TL_messageEntityBold();
                            entity5.offset = spanStart;
                            spans = spans2;
                            entity5.length = spanEnd - spanStart;
                            entities2.add(entity5);
                        }
                        if ((flags & 2) != 0) {
                            TLRPC.MessageEntity entity6 = new TLRPC.TL_messageEntityItalic();
                            entity6.offset = spanStart;
                            entity6.length = spanEnd - spanStart;
                            entities2.add(entity6);
                        }
                        if ((flags & 4) != 0) {
                            TLRPC.MessageEntity entity7 = new TLRPC.TL_messageEntityCode();
                            entity7.offset = spanStart;
                            entity7.length = spanEnd - spanStart;
                            entities2.add(entity7);
                        }
                        if ((flags & 8) != 0) {
                            TLRPC.MessageEntity entity8 = new TLRPC.TL_messageEntityStrike();
                            entity8.offset = spanStart;
                            entity8.length = spanEnd - spanStart;
                            entities2.add(entity8);
                        }
                        if ((flags & 16) != 0) {
                            TLRPC.MessageEntity entity9 = new TLRPC.TL_messageEntityUnderline();
                            entity9.offset = spanStart;
                            entity9.length = spanEnd - spanStart;
                            entities2.add(entity9);
                        }
                        if ((flags & 32) != 0) {
                            TLRPC.MessageEntity entity10 = new TLRPC.TL_messageEntityBlockquote();
                            entity10.offset = spanStart;
                            entity10.length = spanEnd - spanStart;
                            entities2.add(entity10);
                        }
                    }
                    a2++;
                    spans2 = spans;
                }
            }
            URLSpanUserMention[] spansMentions = (URLSpanUserMention[]) spannable.getSpans(0, message[0].length(), URLSpanUserMention.class);
            if (spansMentions != null && spansMentions.length > 0) {
                if (entities2 == null) {
                    entities2 = new ArrayList<>();
                }
                for (int b = 0; b < spansMentions.length; b++) {
                    TLRPC.TL_inputMessageEntityMentionName entity11 = new TLRPC.TL_inputMessageEntityMentionName();
                    entity11.user_id = getMessagesController().getInputUser(Utilities.parseInt(spansMentions[b].getURL()).intValue());
                    if (entity11.user_id != null) {
                        entity11.offset = spannable.getSpanStart(spansMentions[b]);
                        entity11.length = Math.min(spannable.getSpanEnd(spansMentions[b]), message[0].length()) - entity11.offset;
                        if (message[0].charAt((entity11.offset + entity11.length) - 1) == ' ') {
                            entity11.length--;
                        }
                        entities2.add(entity11);
                    }
                }
            }
            URLSpanReplacement[] spansUrlReplacement = (URLSpanReplacement[]) spannable.getSpans(0, message[0].length(), URLSpanReplacement.class);
            if (spansUrlReplacement != null && spansUrlReplacement.length > 0) {
                if (entities2 == null) {
                    entities2 = new ArrayList<>();
                }
                for (int b2 = 0; b2 < spansUrlReplacement.length; b2++) {
                    TLRPC.TL_messageEntityTextUrl entity12 = new TLRPC.TL_messageEntityTextUrl();
                    entity12.offset = spannable.getSpanStart(spansUrlReplacement[b2]);
                    entity12.length = Math.min(spannable.getSpanEnd(spansUrlReplacement[b2]), message[0].length()) - entity12.offset;
                    entity12.url = spansUrlReplacement[b2].getURL();
                    entities2.add(entity12);
                }
            }
        }
        int c4 = 0;
        while (c4 < 2) {
            int lastIndex3 = 0;
            int start2 = -1;
            String checkString = c4 == 0 ? "**" : "__";
            char checkChar = c4 == 0 ? '*' : '_';
            while (true) {
                int iIndexOf2 = TextUtils.indexOf(message[0], checkString, lastIndex3);
                int index2 = iIndexOf2;
                if (iIndexOf2 != -1) {
                    if (start2 == -1) {
                        char prevChar = index2 == 0 ? ' ' : message[0].charAt(index2 - 1);
                        if (!checkInclusion(index2, entities2) && (prevChar == ' ' || prevChar == '\n')) {
                            start2 = index2;
                        }
                        lastIndex3 = index2 + 2;
                    } else {
                        for (int a3 = index2 + 2; a3 < message[0].length() && message[0].charAt(a3) == checkChar; a3++) {
                            index2++;
                        }
                        lastIndex3 = index2 + 2;
                        if (checkInclusion(index2, entities2) || checkIntersection(start2, index2, entities2)) {
                            start2 = -1;
                        } else {
                            if (start2 + 2 != index2) {
                                if (entities2 != null) {
                                    entities = entities2;
                                } else {
                                    entities = new ArrayList<>();
                                }
                                try {
                                    message[0] = AndroidUtilities.concat(substring(message[0], 0, start2), substring(message[0], start2 + 2, index2), substring(message[0], index2 + 2, message[0].length()));
                                } catch (Exception e) {
                                    message[0] = substring(message[0], 0, start2).toString() + substring(message[0], start2 + 2, index2).toString() + substring(message[0], index2 + 2, message[0].length()).toString();
                                }
                                if (c4 == 0) {
                                    entity = new TLRPC.TL_messageEntityBold();
                                } else {
                                    entity = new TLRPC.TL_messageEntityItalic();
                                }
                                entity.offset = start2;
                                entity.length = (index2 - start2) - 2;
                                removeOffsetAfter(entity.offset + entity.length, 4, entities);
                                entities.add(entity);
                                lastIndex3 -= 4;
                                entities2 = entities;
                            }
                            start2 = -1;
                        }
                    }
                }
            }
            c4++;
        }
        return entities2;
    }

    public void loadDrafts() {
        if (getUserConfig().draftsLoaded || this.loadingDrafts) {
            return;
        }
        this.loadingDrafts = true;
        TLRPC.TL_messages_getAllDrafts req = new TLRPC.TL_messages_getAllDrafts();
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$Fuk-Lgpo079vetzpE1Z_CILqVxQ
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) throws Exception {
                this.f$0.lambda$loadDrafts$101$MediaDataController(tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$loadDrafts$101$MediaDataController(TLObject response, TLRPC.TL_error error) throws Exception {
        if (error != null) {
            return;
        }
        getMessagesController().processUpdates((TLRPC.Updates) response, false);
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$S3Vm0fZAxhf1IBKunUPdIUEVAMQ
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$100$MediaDataController();
            }
        });
    }

    public /* synthetic */ void lambda$null$100$MediaDataController() {
        getUserConfig().draftsLoaded = true;
        this.loadingDrafts = false;
        getUserConfig().saveConfig(false);
    }

    public TLRPC.DraftMessage getDraft(long did) {
        return this.drafts.get(did);
    }

    public TLRPC.Message getDraftMessage(long did) {
        return this.draftMessages.get(did);
    }

    public void saveDraft(long did, CharSequence message, ArrayList<TLRPC.MessageEntity> entities, TLRPC.Message replyToMessage, boolean noWebpage) {
        saveDraft(did, message, entities, replyToMessage, noWebpage, false);
    }

    public void saveDraft(long did, CharSequence message, ArrayList<TLRPC.MessageEntity> entities, TLRPC.Message replyToMessage, boolean noWebpage, boolean clean) {
        TLRPC.DraftMessage draftMessage;
        if (!TextUtils.isEmpty(message) || replyToMessage != null) {
            draftMessage = new TLRPC.TL_draftMessage();
        } else {
            draftMessage = new TLRPC.TL_draftMessageEmpty();
        }
        draftMessage.date = (int) (System.currentTimeMillis() / 1000);
        draftMessage.message = message == null ? "" : message.toString();
        draftMessage.no_webpage = noWebpage;
        if (replyToMessage != null) {
            draftMessage.reply_to_msg_id = replyToMessage.id;
            draftMessage.flags |= 1;
        }
        if (entities != null && !entities.isEmpty()) {
            draftMessage.entities = entities;
            draftMessage.flags |= 8;
        }
        TLRPC.DraftMessage currentDraft = this.drafts.get(did);
        if (!clean) {
            if (currentDraft == null || !currentDraft.message.equals(draftMessage.message) || currentDraft.reply_to_msg_id != draftMessage.reply_to_msg_id || currentDraft.no_webpage != draftMessage.no_webpage) {
                if (currentDraft == null && TextUtils.isEmpty(draftMessage.message) && draftMessage.reply_to_msg_id == 0) {
                    return;
                }
            } else {
                return;
            }
        }
        saveDraft(did, draftMessage, replyToMessage, false);
        int lower_id = (int) did;
        if (lower_id != 0) {
            TLRPC.TL_messages_saveDraft req = new TLRPC.TL_messages_saveDraft();
            req.peer = getMessagesController().getInputPeer(lower_id);
            if (req.peer == null) {
                return;
            }
            req.message = draftMessage.message;
            req.no_webpage = draftMessage.no_webpage;
            req.reply_to_msg_id = draftMessage.reply_to_msg_id;
            req.entities = draftMessage.entities;
            req.flags = draftMessage.flags;
            getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$EtSnA5GHtwdRa1dzS5rzUvCyOMs
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    MediaDataController.lambda$saveDraft$102(tLObject, tL_error);
                }
            });
        }
        getMessagesController().sortDialogs(null);
        getNotificationCenter().postNotificationName(NotificationCenter.dialogsNeedReload, new Object[0]);
    }

    static /* synthetic */ void lambda$saveDraft$102(TLObject response, TLRPC.TL_error error) {
    }

    public void saveDraft(final long did, TLRPC.DraftMessage draft, TLRPC.Message replyToMessage, boolean fromServer) {
        TLRPC.User user;
        TLRPC.Chat chat;
        long messageId;
        int channelIdFinal;
        SharedPreferences.Editor editor = this.preferences.edit();
        if (draft == null || (draft instanceof TLRPC.TL_draftMessageEmpty)) {
            this.drafts.remove(did);
            this.draftMessages.remove(did);
            this.preferences.edit().remove("" + did).remove("r_" + did).commit();
        } else {
            this.drafts.put(did, draft);
            try {
                SerializedData serializedData = new SerializedData(draft.getObjectSize());
                draft.serializeToStream(serializedData);
                editor.putString("" + did, Utilities.bytesToHex(serializedData.toByteArray()));
                serializedData.cleanup();
            } catch (Exception e) {
                FileLog.e(e);
            }
        }
        if (replyToMessage == null) {
            this.draftMessages.remove(did);
            editor.remove("r_" + did);
        } else {
            this.draftMessages.put(did, replyToMessage);
            SerializedData serializedData2 = new SerializedData(replyToMessage.getObjectSize());
            replyToMessage.serializeToStream(serializedData2);
            editor.putString("r_" + did, Utilities.bytesToHex(serializedData2.toByteArray()));
            serializedData2.cleanup();
        }
        editor.commit();
        if (fromServer) {
            if (draft.reply_to_msg_id != 0 && replyToMessage == null) {
                int lower_id = (int) did;
                if (lower_id > 0) {
                    TLRPC.User user2 = getMessagesController().getUser(Integer.valueOf(lower_id));
                    user = user2;
                    chat = null;
                } else {
                    TLRPC.Chat chat2 = getMessagesController().getChat(Integer.valueOf(-lower_id));
                    user = null;
                    chat = chat2;
                }
                if (user != null || chat != null) {
                    long messageId2 = draft.reply_to_msg_id;
                    if (ChatObject.isChannel(chat)) {
                        messageId = messageId2 | (((long) chat.id) << 32);
                        channelIdFinal = chat.id;
                    } else {
                        messageId = messageId2;
                        channelIdFinal = 0;
                    }
                    final long messageIdFinal = messageId;
                    final int i = channelIdFinal;
                    getMessagesStorage().getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$DGNdM7xnAs1PY6G1axI6iXMXWMQ
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$saveDraft$105$MediaDataController(messageIdFinal, i, did);
                        }
                    });
                }
            }
            getNotificationCenter().postNotificationName(NotificationCenter.newDraftReceived, Long.valueOf(did));
        }
    }

    public /* synthetic */ void lambda$saveDraft$105$MediaDataController(long messageIdFinal, int channelIdFinal, final long did) {
        NativeByteBuffer data;
        TLRPC.Message message = null;
        try {
            SQLiteCursor cursor = getMessagesStorage().getDatabase().queryFinalized(String.format(Locale.US, "SELECT data FROM messages WHERE mid = %d", Long.valueOf(messageIdFinal)), new Object[0]);
            if (cursor.next() && (data = cursor.byteBufferValue(0)) != null) {
                message = TLRPC.Message.TLdeserialize(data, data.readInt32(false), false);
                message.readAttachPath(data, getUserConfig().clientUserId);
                data.reuse();
            }
            cursor.dispose();
            if (message == null) {
                if (channelIdFinal != 0) {
                    TLRPC.TL_channels_getMessages req = new TLRPC.TL_channels_getMessages();
                    req.channel = getMessagesController().getInputChannel(channelIdFinal);
                    req.id.add(Integer.valueOf((int) messageIdFinal));
                    getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$-Qao_XuNtdiGFF7MnBqE1AYuZX0
                        @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                        public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                            this.f$0.lambda$null$103$MediaDataController(did, tLObject, tL_error);
                        }
                    });
                    return;
                }
                TLRPC.TL_messages_getMessages req2 = new TLRPC.TL_messages_getMessages();
                req2.id.add(Integer.valueOf((int) messageIdFinal));
                getConnectionsManager().sendRequest(req2, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$wkfx68m-quvLBBcvKKb1k70JQsg
                    @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                    public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                        this.f$0.lambda$null$104$MediaDataController(did, tLObject, tL_error);
                    }
                });
                return;
            }
            saveDraftReplyMessage(did, message);
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public /* synthetic */ void lambda$null$103$MediaDataController(long did, TLObject response, TLRPC.TL_error error) {
        if (error == null) {
            TLRPC.messages_Messages messagesRes = (TLRPC.messages_Messages) response;
            if (!messagesRes.messages.isEmpty()) {
                saveDraftReplyMessage(did, messagesRes.messages.get(0));
            }
        }
    }

    public /* synthetic */ void lambda$null$104$MediaDataController(long did, TLObject response, TLRPC.TL_error error) {
        if (error == null) {
            TLRPC.messages_Messages messagesRes = (TLRPC.messages_Messages) response;
            if (!messagesRes.messages.isEmpty()) {
                saveDraftReplyMessage(did, messagesRes.messages.get(0));
            }
        }
    }

    private void saveDraftReplyMessage(final long did, final TLRPC.Message message) {
        if (message == null) {
            return;
        }
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$IwXJdCGEkKhPaDnuo1b6-k3O1Xw
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$saveDraftReplyMessage$106$MediaDataController(did, message);
            }
        });
    }

    public /* synthetic */ void lambda$saveDraftReplyMessage$106$MediaDataController(long did, TLRPC.Message message) {
        TLRPC.DraftMessage draftMessage = this.drafts.get(did);
        if (draftMessage != null && draftMessage.reply_to_msg_id == message.id) {
            this.draftMessages.put(did, message);
            SerializedData serializedData = new SerializedData(message.getObjectSize());
            message.serializeToStream(serializedData);
            this.preferences.edit().putString("r_" + did, Utilities.bytesToHex(serializedData.toByteArray())).commit();
            getNotificationCenter().postNotificationName(NotificationCenter.newDraftReceived, Long.valueOf(did));
            serializedData.cleanup();
        }
    }

    public void clearAllDrafts() {
        this.drafts.clear();
        this.draftMessages.clear();
        this.preferences.edit().clear().commit();
        getMessagesController().sortDialogs(null);
        getNotificationCenter().postNotificationName(NotificationCenter.dialogsNeedReload, new Object[0]);
    }

    public void cleanDraft(long did, boolean replyOnly) {
        TLRPC.DraftMessage draftMessage = this.drafts.get(did);
        if (draftMessage == null) {
            return;
        }
        if (!replyOnly) {
            this.drafts.remove(did);
            this.draftMessages.remove(did);
            this.preferences.edit().remove("" + did).remove("r_" + did).commit();
            getMessagesController().sortDialogs(null);
            getNotificationCenter().postNotificationName(NotificationCenter.dialogsNeedReload, new Object[0]);
            return;
        }
        if (draftMessage.reply_to_msg_id != 0) {
            draftMessage.reply_to_msg_id = 0;
            draftMessage.flags &= -2;
            saveDraft(did, draftMessage.message, draftMessage.entities, null, draftMessage.no_webpage, true);
        }
    }

    public void beginTransaction() {
        this.inTransaction = true;
    }

    public void endTransaction() {
        this.inTransaction = false;
    }

    public void clearBotKeyboard(final long did, final ArrayList<Integer> messages) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$XdiVLd_peDG7AHEA9m75MmqEda4
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$clearBotKeyboard$107$MediaDataController(messages, did);
            }
        });
    }

    public /* synthetic */ void lambda$clearBotKeyboard$107$MediaDataController(ArrayList messages, long did) {
        if (messages != null) {
            for (int a = 0; a < messages.size(); a++) {
                long did1 = this.botKeyboardsByMids.get(((Integer) messages.get(a)).intValue());
                if (did1 != 0) {
                    this.botKeyboards.remove(did1);
                    this.botKeyboardsByMids.delete(((Integer) messages.get(a)).intValue());
                    getNotificationCenter().postNotificationName(NotificationCenter.botKeyboardDidLoad, null, Long.valueOf(did1));
                }
            }
            return;
        }
        this.botKeyboards.remove(did);
        getNotificationCenter().postNotificationName(NotificationCenter.botKeyboardDidLoad, null, Long.valueOf(did));
    }

    public void loadBotKeyboard(final long did) {
        TLRPC.Message keyboard = this.botKeyboards.get(did);
        if (keyboard != null) {
            getNotificationCenter().postNotificationName(NotificationCenter.botKeyboardDidLoad, keyboard, Long.valueOf(did));
        } else {
            getMessagesStorage().getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$DgdPQLXU67E8UhyeTbkYbZFwKxE
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$loadBotKeyboard$109$MediaDataController(did);
                }
            });
        }
    }

    public /* synthetic */ void lambda$loadBotKeyboard$109$MediaDataController(final long did) {
        NativeByteBuffer data;
        TLRPC.Message botKeyboard = null;
        try {
            SQLiteCursor cursor = getMessagesStorage().getDatabase().queryFinalized(String.format(Locale.US, "SELECT info FROM bot_keyboard WHERE uid = %d", Long.valueOf(did)), new Object[0]);
            if (cursor.next() && !cursor.isNull(0) && (data = cursor.byteBufferValue(0)) != null) {
                botKeyboard = TLRPC.Message.TLdeserialize(data, data.readInt32(false), false);
                data.reuse();
            }
            cursor.dispose();
            if (botKeyboard != null) {
                final TLRPC.Message botKeyboardFinal = botKeyboard;
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$tIzzNy7eaEOU1TuWqV4CcqVyZm0
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$108$MediaDataController(botKeyboardFinal, did);
                    }
                });
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public /* synthetic */ void lambda$null$108$MediaDataController(TLRPC.Message botKeyboardFinal, long did) {
        getNotificationCenter().postNotificationName(NotificationCenter.botKeyboardDidLoad, botKeyboardFinal, Long.valueOf(did));
    }

    public void loadBotInfo(final int uid, boolean cache, final int classGuid) {
        TLRPC.BotInfo botInfo;
        if (cache && (botInfo = this.botInfos.get(uid)) != null) {
            getNotificationCenter().postNotificationName(NotificationCenter.botInfoDidLoad, botInfo, Integer.valueOf(classGuid));
        } else {
            getMessagesStorage().getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$czoztJGHuQ_fh_c7PkdSb_VvDMI
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$loadBotInfo$111$MediaDataController(uid, classGuid);
                }
            });
        }
    }

    public /* synthetic */ void lambda$loadBotInfo$111$MediaDataController(int uid, final int classGuid) {
        NativeByteBuffer data;
        TLRPC.BotInfo botInfo = null;
        try {
            SQLiteCursor cursor = getMessagesStorage().getDatabase().queryFinalized(String.format(Locale.US, "SELECT info FROM bot_info WHERE uid = %d", Integer.valueOf(uid)), new Object[0]);
            if (cursor.next() && !cursor.isNull(0) && (data = cursor.byteBufferValue(0)) != null) {
                botInfo = TLRPC.BotInfo.TLdeserialize(data, data.readInt32(false), false);
                data.reuse();
            }
            cursor.dispose();
            if (botInfo != null) {
                final TLRPC.BotInfo botInfoFinal = botInfo;
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$-4D47svfVob1Ent1p6tH8CZIm1s
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$110$MediaDataController(botInfoFinal, classGuid);
                    }
                });
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public /* synthetic */ void lambda$null$110$MediaDataController(TLRPC.BotInfo botInfoFinal, int classGuid) {
        getNotificationCenter().postNotificationName(NotificationCenter.botInfoDidLoad, botInfoFinal, Integer.valueOf(classGuid));
    }

    public void putBotKeyboard(final long did, final TLRPC.Message message) {
        if (message == null) {
            return;
        }
        int mid = 0;
        try {
            SQLiteCursor cursor = getMessagesStorage().getDatabase().queryFinalized(String.format(Locale.US, "SELECT mid FROM bot_keyboard WHERE uid = %d", Long.valueOf(did)), new Object[0]);
            if (cursor.next()) {
                mid = cursor.intValue(0);
            }
            cursor.dispose();
            if (mid >= message.id) {
                return;
            }
            SQLitePreparedStatement state = getMessagesStorage().getDatabase().executeFast("REPLACE INTO bot_keyboard VALUES(?, ?, ?)");
            state.requery();
            NativeByteBuffer data = new NativeByteBuffer(message.getObjectSize());
            message.serializeToStream(data);
            state.bindLong(1, did);
            state.bindInteger(2, message.id);
            state.bindByteBuffer(3, data);
            state.step();
            data.reuse();
            state.dispose();
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$AQzzYBnwy25icLmI_2ueMY8VMTY
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$putBotKeyboard$112$MediaDataController(did, message);
                }
            });
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public /* synthetic */ void lambda$putBotKeyboard$112$MediaDataController(long did, TLRPC.Message message) {
        TLRPC.Message old = this.botKeyboards.get(did);
        this.botKeyboards.put(did, message);
        if (old != null) {
            this.botKeyboardsByMids.delete(old.id);
        }
        this.botKeyboardsByMids.put(message.id, did);
        getNotificationCenter().postNotificationName(NotificationCenter.botKeyboardDidLoad, message, Long.valueOf(did));
    }

    public void putBotInfo(final TLRPC.BotInfo botInfo) {
        if (botInfo == null) {
            return;
        }
        this.botInfos.put(botInfo.user_id, botInfo);
        getMessagesStorage().getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$6VUXyLNp_doMdciCEljd0uLSVJk
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$putBotInfo$113$MediaDataController(botInfo);
            }
        });
    }

    public /* synthetic */ void lambda$putBotInfo$113$MediaDataController(TLRPC.BotInfo botInfo) {
        try {
            SQLitePreparedStatement state = getMessagesStorage().getDatabase().executeFast("REPLACE INTO bot_info(uid, info) VALUES(?, ?)");
            state.requery();
            NativeByteBuffer data = new NativeByteBuffer(botInfo.getObjectSize());
            botInfo.serializeToStream(data);
            state.bindInteger(1, botInfo.user_id);
            state.bindByteBuffer(2, data);
            state.step();
            data.reuse();
            state.dispose();
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public void fetchNewEmojiKeywords(String[] langCodes) {
        if (langCodes == null) {
            return;
        }
        for (final String langCode : langCodes) {
            if (TextUtils.isEmpty(langCode) || this.currentFetchingEmoji.get(langCode) != null) {
                return;
            }
            this.currentFetchingEmoji.put(langCode, true);
            getMessagesStorage().getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$Ik5kn5OXW_TlcDwJh7_Euzsg7yE
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$fetchNewEmojiKeywords$119$MediaDataController(langCode);
                }
            });
        }
    }

    public /* synthetic */ void lambda$fetchNewEmojiKeywords$119$MediaDataController(final String str) {
        TLObject tLObject;
        int iIntValue = -1;
        String strStringValue = null;
        long jLongValue = 0;
        try {
            SQLiteCursor sQLiteCursorQueryFinalized = getMessagesStorage().getDatabase().queryFinalized("SELECT alias, version, date FROM emoji_keywords_info_v2 WHERE lang = ?", str);
            if (sQLiteCursorQueryFinalized.next()) {
                strStringValue = sQLiteCursorQueryFinalized.stringValue(0);
                iIntValue = sQLiteCursorQueryFinalized.intValue(1);
                jLongValue = sQLiteCursorQueryFinalized.longValue(2);
            }
            sQLiteCursorQueryFinalized.dispose();
        } catch (Exception e) {
            FileLog.e(e);
        }
        if (!BuildVars.DEBUG_VERSION && Math.abs(System.currentTimeMillis() - jLongValue) < 3600000) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$2bL8iNsDajjADyTVdXAxfAQIcUs
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$114$MediaDataController(str);
                }
            });
            return;
        }
        if (iIntValue == -1) {
            TLRPC.TL_messages_getEmojiKeywords tL_messages_getEmojiKeywords = new TLRPC.TL_messages_getEmojiKeywords();
            tL_messages_getEmojiKeywords.lang_code = str;
            tLObject = tL_messages_getEmojiKeywords;
        } else {
            TLRPC.TL_messages_getEmojiKeywordsDifference tL_messages_getEmojiKeywordsDifference = new TLRPC.TL_messages_getEmojiKeywordsDifference();
            tL_messages_getEmojiKeywordsDifference.lang_code = str;
            tL_messages_getEmojiKeywordsDifference.from_version = iIntValue;
            tLObject = tL_messages_getEmojiKeywordsDifference;
        }
        final String str2 = strStringValue;
        final int i = iIntValue;
        getConnectionsManager().sendRequest(tLObject, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$ztGiDdysc9x4H91vQ4nKVOrIsLs
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject2, TLRPC.TL_error tL_error) {
                this.f$0.lambda$null$118$MediaDataController(i, str2, str, tLObject2, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$null$114$MediaDataController(String langCode) {
        this.currentFetchingEmoji.remove(langCode);
    }

    public /* synthetic */ void lambda$null$118$MediaDataController(int versionFinal, String aliasFinal, final String langCode, TLObject response, TLRPC.TL_error error) {
        if (response != null) {
            TLRPC.TL_emojiKeywordsDifference res = (TLRPC.TL_emojiKeywordsDifference) response;
            if (versionFinal != -1 && !res.lang_code.equals(aliasFinal)) {
                getMessagesStorage().getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$IS4SHzD5T4eTsXQMC7z_67DS4vE
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$116$MediaDataController(langCode);
                    }
                });
                return;
            } else {
                putEmojiKeywords(langCode, res);
                return;
            }
        }
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$FLIHDM9hMelerbuVMBT27iEnUKM
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$117$MediaDataController(langCode);
            }
        });
    }

    public /* synthetic */ void lambda$null$116$MediaDataController(final String langCode) {
        try {
            SQLitePreparedStatement deleteState = getMessagesStorage().getDatabase().executeFast("DELETE FROM emoji_keywords_info_v2 WHERE lang = ?");
            deleteState.bindString(1, langCode);
            deleteState.step();
            deleteState.dispose();
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$NY1T2nOA9Pkh4xYrnZHw-ywokcY
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$115$MediaDataController(langCode);
                }
            });
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public /* synthetic */ void lambda$null$115$MediaDataController(String langCode) {
        this.currentFetchingEmoji.remove(langCode);
        fetchNewEmojiKeywords(new String[]{langCode});
    }

    public /* synthetic */ void lambda$null$117$MediaDataController(String langCode) {
        this.currentFetchingEmoji.remove(langCode);
    }

    private void putEmojiKeywords(final String lang, final TLRPC.TL_emojiKeywordsDifference res) {
        if (res == null) {
            return;
        }
        getMessagesStorage().getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$8skfH_muAXw0AuQJe6xbLbGelU0
            @Override // java.lang.Runnable
            public final void run() throws Throwable {
                this.f$0.lambda$putEmojiKeywords$121$MediaDataController(res, lang);
            }
        });
    }

    /* JADX WARN: Removed duplicated region for block: B:52:0x0133  */
    /* JADX WARN: Removed duplicated region for block: B:54:0x0138  */
    /* JADX WARN: Removed duplicated region for block: B:56:0x013d  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public /* synthetic */ void lambda$putEmojiKeywords$121$MediaDataController(im.uwrkaxlmjj.tgnet.TLRPC.TL_emojiKeywordsDifference r17, final java.lang.String r18) throws java.lang.Throwable {
        /*
            Method dump skipped, instruction units count: 321
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MediaDataController.lambda$putEmojiKeywords$121$MediaDataController(im.uwrkaxlmjj.tgnet.TLRPC$TL_emojiKeywordsDifference, java.lang.String):void");
    }

    public /* synthetic */ void lambda$null$120$MediaDataController(String lang) {
        this.currentFetchingEmoji.remove(lang);
        getNotificationCenter().postNotificationName(NotificationCenter.newEmojiSuggestionsAvailable, lang);
    }

    public void getEmojiSuggestions(String[] langCodes, String keyword, boolean fullMatch, KeywordResultCallback callback) {
        getEmojiSuggestions(langCodes, keyword, fullMatch, callback, null);
    }

    public void getEmojiSuggestions(final String[] langCodes, final String keyword, final boolean fullMatch, final KeywordResultCallback callback, final CountDownLatch sync) {
        if (callback == null) {
            return;
        }
        if (TextUtils.isEmpty(keyword) || langCodes == null) {
            callback.run(new ArrayList<>(), null);
            return;
        }
        final ArrayList<String> recentEmoji = new ArrayList<>(Emoji.recentEmoji);
        getMessagesStorage().getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$MediaDataController$eLboOJNSKemALflGNuoGR2uXwW8
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$getEmojiSuggestions$125$MediaDataController(langCodes, callback, keyword, fullMatch, recentEmoji, sync);
            }
        });
        if (sync != null) {
            try {
                sync.await();
            } catch (Throwable th) {
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:27:0x007e A[Catch: Exception -> 0x0139, TryCatch #1 {Exception -> 0x0139, blocks: (B:15:0x004b, B:17:0x0052, B:21:0x005e, B:25:0x0072, B:27:0x007e, B:29:0x008c, B:32:0x0096, B:36:0x00eb, B:38:0x00f1, B:41:0x0108, B:43:0x0128, B:34:0x00ad, B:35:0x00c5), top: B:58:0x0045 }] */
    /* JADX WARN: Removed duplicated region for block: B:32:0x0096 A[Catch: Exception -> 0x0139, TryCatch #1 {Exception -> 0x0139, blocks: (B:15:0x004b, B:17:0x0052, B:21:0x005e, B:25:0x0072, B:27:0x007e, B:29:0x008c, B:32:0x0096, B:36:0x00eb, B:38:0x00f1, B:41:0x0108, B:43:0x0128, B:34:0x00ad, B:35:0x00c5), top: B:58:0x0045 }] */
    /* JADX WARN: Removed duplicated region for block: B:33:0x00ab  */
    /* JADX WARN: Removed duplicated region for block: B:38:0x00f1 A[Catch: Exception -> 0x0139, TryCatch #1 {Exception -> 0x0139, blocks: (B:15:0x004b, B:17:0x0052, B:21:0x005e, B:25:0x0072, B:27:0x007e, B:29:0x008c, B:32:0x0096, B:36:0x00eb, B:38:0x00f1, B:41:0x0108, B:43:0x0128, B:34:0x00ad, B:35:0x00c5), top: B:58:0x0045 }] */
    /* JADX WARN: Removed duplicated region for block: B:53:0x014e  */
    /* JADX WARN: Removed duplicated region for block: B:54:0x0155  */
    /* JADX WARN: Removed duplicated region for block: B:64:0x0094 A[EDGE_INSN: B:64:0x0094->B:31:0x0094 BREAK  A[LOOP:2: B:26:0x007c->B:30:0x0092], SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public /* synthetic */ void lambda$getEmojiSuggestions$125$MediaDataController(final java.lang.String[] r19, final im.uwrkaxlmjj.messenger.MediaDataController.KeywordResultCallback r20, java.lang.String r21, boolean r22, final java.util.ArrayList r23, java.util.concurrent.CountDownLatch r24) {
        /*
            Method dump skipped, instruction units count: 350
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.MediaDataController.lambda$getEmojiSuggestions$125$MediaDataController(java.lang.String[], im.uwrkaxlmjj.messenger.MediaDataController$KeywordResultCallback, java.lang.String, boolean, java.util.ArrayList, java.util.concurrent.CountDownLatch):void");
    }

    public /* synthetic */ void lambda$null$122$MediaDataController(String[] langCodes, KeywordResultCallback callback, ArrayList result) {
        for (String str : langCodes) {
            if (this.currentFetchingEmoji.get(str) != null) {
                return;
            }
        }
        callback.run(result, null);
    }

    static /* synthetic */ int lambda$null$123(ArrayList recentEmoji, KeywordResult o1, KeywordResult o2) {
        int idx1 = recentEmoji.indexOf(o1.emoji);
        if (idx1 < 0) {
            idx1 = Integer.MAX_VALUE;
        }
        int idx2 = recentEmoji.indexOf(o2.emoji);
        if (idx2 < 0) {
            idx2 = Integer.MAX_VALUE;
        }
        if (idx1 < idx2) {
            return -1;
        }
        if (idx1 > idx2) {
            return 1;
        }
        int len1 = o1.keyword.length();
        int len2 = o2.keyword.length();
        if (len1 < len2) {
            return -1;
        }
        if (len1 > len2) {
            return 1;
        }
        return 0;
    }
}
