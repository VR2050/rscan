package im.uwrkaxlmjj.messenger;

import android.content.Intent;
import android.os.SystemClock;
import android.text.TextUtils;
import android.util.LongSparseArray;
import android.util.SparseIntArray;
import com.google.android.exoplayer2.DefaultRenderersFactory;
import com.google.android.gms.location.LocationRequest;
import com.zhy.http.okhttp.OkHttpUtils;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.sqlite.SQLiteCursor;
import im.uwrkaxlmjj.sqlite.SQLitePreparedStatement;
import im.uwrkaxlmjj.tgnet.NativeByteBuffer;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import java.util.ArrayList;
import java.util.HashMap;

/* JADX INFO: loaded from: classes2.dex */
public class LocationController extends BaseController implements NotificationCenter.NotificationCenterDelegate {
    private static final int BACKGROUD_UPDATE_TIME = 30000;
    private static final long FASTEST_INTERVAL = 1000;
    private static final int FOREGROUND_UPDATE_TIME = 20000;
    private static final int LOCATION_ACQUIRE_TIME = 10000;
    private static final int PLAY_SERVICES_RESOLUTION_REQUEST = 9000;
    private static final long UPDATE_INTERVAL = 1000;
    private LongSparseArray<Boolean> cacheRequests;
    private ArrayList<TLRPC.TL_peerLocated> cachedNearbyChats;
    private ArrayList<TLRPC.TL_peerLocated> cachedNearbyUsers;
    private boolean lastLocationByBaiduMaps;
    private long lastLocationSendTime;
    private long lastLocationStartTime;
    private LocationRequest locationRequest;
    private boolean locationSentSinceLastBaiduMapUpdate;
    public LongSparseArray<ArrayList<TLRPC.Message>> locationsCache;
    private boolean lookingForPeopleNearby;
    private SparseIntArray requests;
    private ArrayList<SharingLocationInfo> sharingLocations;
    private LongSparseArray<SharingLocationInfo> sharingLocationsMap;
    private LongSparseArray<SharingLocationInfo> sharingLocationsMapUI;
    public ArrayList<SharingLocationInfo> sharingLocationsUI;
    private boolean started;
    private static volatile LocationController[] Instance = new LocationController[3];
    private static HashMap<LocationFetchCallback, Runnable> callbacks = new HashMap<>();

    public interface LocationFetchCallback {
    }

    public static class SharingLocationInfo {
        public long did;
        public MessageObject messageObject;
        public int mid;
        public int period;
        public int stopTime;
    }

    public static LocationController getInstance(int num) {
        LocationController localInstance = Instance[num];
        if (localInstance == null) {
            synchronized (LocationController.class) {
                localInstance = Instance[num];
                if (localInstance == null) {
                    LocationController[] locationControllerArr = Instance;
                    LocationController locationController = new LocationController(num);
                    localInstance = locationController;
                    locationControllerArr[num] = locationController;
                }
            }
        }
        return localInstance;
    }

    public LocationController(int instance) {
        super(instance);
        this.sharingLocationsMap = new LongSparseArray<>();
        this.sharingLocations = new ArrayList<>();
        this.locationsCache = new LongSparseArray<>();
        this.locationSentSinceLastBaiduMapUpdate = true;
        this.requests = new SparseIntArray();
        this.cacheRequests = new LongSparseArray<>();
        this.sharingLocationsUI = new ArrayList<>();
        this.sharingLocationsMapUI = new LongSparseArray<>();
        this.cachedNearbyUsers = new ArrayList<>();
        this.cachedNearbyChats = new ArrayList<>();
        initLocationClient();
        LocationRequest locationRequest = new LocationRequest();
        this.locationRequest = locationRequest;
        locationRequest.setPriority(100);
        this.locationRequest.setInterval(1000L);
        this.locationRequest.setFastestInterval(1000L);
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$LocationController$qbwoLK9jpBw2EoXQLwTcwUn_yKQ
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$new$0$LocationController();
            }
        });
        loadSharingLocations();
    }

    public /* synthetic */ void lambda$new$0$LocationController() {
        LocationController locationController = getAccountInstance().getLocationController();
        getNotificationCenter().addObserver(locationController, NotificationCenter.didReceiveNewMessages);
        getNotificationCenter().addObserver(locationController, NotificationCenter.messagesDeleted);
        getNotificationCenter().addObserver(locationController, NotificationCenter.replaceMessagesObjects);
    }

    private void initLocationClient() {
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        ArrayList<TLRPC.Message> messages;
        ArrayList<TLRPC.Message> messages2;
        if (id == NotificationCenter.didReceiveNewMessages) {
            boolean scheduled = ((Boolean) args[2]).booleanValue();
            if (scheduled) {
                return;
            }
            long did = ((Long) args[0]).longValue();
            if (!isSharingLocation(did) || (messages2 = this.locationsCache.get(did)) == null) {
                return;
            }
            ArrayList<MessageObject> arr = (ArrayList) args[1];
            boolean added = false;
            for (int a = 0; a < arr.size(); a++) {
                MessageObject messageObject = arr.get(a);
                if (messageObject.isLiveLocation()) {
                    added = true;
                    boolean replaced = false;
                    int b = 0;
                    while (true) {
                        if (b >= messages2.size()) {
                            break;
                        }
                        if (messages2.get(b).from_id != messageObject.messageOwner.from_id) {
                            b++;
                        } else {
                            replaced = true;
                            messages2.set(b, messageObject.messageOwner);
                            break;
                        }
                    }
                    if (!replaced) {
                        messages2.add(messageObject.messageOwner);
                    }
                }
            }
            if (added) {
                NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.liveLocationsCacheChanged, Long.valueOf(did), Integer.valueOf(this.currentAccount));
                return;
            }
            return;
        }
        if (id == NotificationCenter.messagesDeleted) {
            boolean scheduled2 = ((Boolean) args[2]).booleanValue();
            if (!scheduled2 && !this.sharingLocationsUI.isEmpty()) {
                ArrayList<Integer> markAsDeletedMessages = (ArrayList) args[0];
                int channelId = ((Integer) args[1]).intValue();
                ArrayList<Long> toRemove = null;
                for (int a2 = 0; a2 < this.sharingLocationsUI.size(); a2++) {
                    SharingLocationInfo info = this.sharingLocationsUI.get(a2);
                    int messageChannelId = info.messageObject != null ? info.messageObject.getChannelId() : 0;
                    if (channelId == messageChannelId && markAsDeletedMessages.contains(Integer.valueOf(info.mid))) {
                        if (toRemove == null) {
                            toRemove = new ArrayList<>();
                        }
                        toRemove.add(Long.valueOf(info.did));
                    }
                }
                if (toRemove != null) {
                    for (int a3 = 0; a3 < toRemove.size(); a3++) {
                        removeSharingLocation(toRemove.get(a3).longValue());
                    }
                    return;
                }
                return;
            }
            return;
        }
        if (id == NotificationCenter.replaceMessagesObjects) {
            long did2 = ((Long) args[0]).longValue();
            if (!isSharingLocation(did2) || (messages = this.locationsCache.get(did2)) == null) {
                return;
            }
            boolean updated = false;
            ArrayList<MessageObject> messageObjects = (ArrayList) args[1];
            for (int a4 = 0; a4 < messageObjects.size(); a4++) {
                MessageObject messageObject2 = messageObjects.get(a4);
                int b2 = 0;
                while (true) {
                    if (b2 >= messages.size()) {
                        break;
                    }
                    if (messages.get(b2).from_id != messageObject2.messageOwner.from_id) {
                        b2++;
                    } else {
                        if (!messageObject2.isLiveLocation()) {
                            messages.remove(b2);
                        } else {
                            messages.set(b2, messageObject2.messageOwner);
                        }
                        updated = true;
                    }
                }
            }
            if (updated) {
                NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.liveLocationsCacheChanged, Long.valueOf(did2), Integer.valueOf(this.currentAccount));
            }
        }
    }

    public void startFusedLocationRequest(final boolean permissionsGranted) {
        Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$LocationController$oSc13a_uTG5tXhykRPotor-auoA
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$startFusedLocationRequest$1$LocationController(permissionsGranted);
            }
        });
    }

    public /* synthetic */ void lambda$startFusedLocationRequest$1$LocationController(boolean permissionsGranted) {
        if ((this.lookingForPeopleNearby || !this.sharingLocations.isEmpty()) && !permissionsGranted) {
            start();
        }
    }

    private void broadcastLastKnownLocation() {
    }

    protected void update() {
        if (this.sharingLocations.isEmpty()) {
            return;
        }
        int a = 0;
        while (a < this.sharingLocations.size()) {
            final SharingLocationInfo info = this.sharingLocations.get(a);
            int currentTime = getConnectionsManager().getCurrentTime();
            if (info.stopTime <= currentTime) {
                this.sharingLocations.remove(a);
                this.sharingLocationsMap.remove(info.did);
                saveSharingLocation(info, 1);
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$LocationController$fH7argznkHydbVVLyzLt9mwoVcE
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$update$2$LocationController(info);
                    }
                });
                a--;
            }
            a++;
        }
        if (!this.started) {
            if (Math.abs(this.lastLocationSendTime - SystemClock.uptimeMillis()) > 30000) {
                this.lastLocationStartTime = SystemClock.uptimeMillis();
                start();
                return;
            }
            return;
        }
        if (Math.abs(this.lastLocationStartTime - SystemClock.uptimeMillis()) > OkHttpUtils.DEFAULT_MILLISECONDS) {
            this.lastLocationSendTime = SystemClock.uptimeMillis();
            this.locationSentSinceLastBaiduMapUpdate = true;
            broadcastLastKnownLocation();
        }
    }

    public /* synthetic */ void lambda$update$2$LocationController(SharingLocationInfo info) {
        this.sharingLocationsUI.remove(info);
        this.sharingLocationsMapUI.remove(info.did);
        if (this.sharingLocationsUI.isEmpty()) {
            stopService();
        }
        NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.liveLocationsChanged, new Object[0]);
    }

    public void cleanup() {
        this.sharingLocationsUI.clear();
        this.sharingLocationsMapUI.clear();
        this.locationsCache.clear();
        this.cacheRequests.clear();
        this.cachedNearbyUsers.clear();
        this.cachedNearbyChats.clear();
        stopService();
        Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$LocationController$vaU0pM9eBKRSu2_YK53jeIB3hao
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$cleanup$3$LocationController();
            }
        });
    }

    public /* synthetic */ void lambda$cleanup$3$LocationController() {
        this.requests.clear();
        this.sharingLocationsMap.clear();
        this.sharingLocations.clear();
        stop();
    }

    public void setCachedNearbyUsersAndChats(ArrayList<TLRPC.TL_peerLocated> u, ArrayList<TLRPC.TL_peerLocated> c) {
        this.cachedNearbyUsers = new ArrayList<>(u);
        this.cachedNearbyChats = new ArrayList<>(c);
    }

    public ArrayList<TLRPC.TL_peerLocated> getCachedNearbyUsers() {
        return this.cachedNearbyUsers;
    }

    public ArrayList<TLRPC.TL_peerLocated> getCachedNearbyChats() {
        return this.cachedNearbyChats;
    }

    protected void addSharingLocation(long did, int mid, int period, TLRPC.Message message) {
        final SharingLocationInfo info = new SharingLocationInfo();
        info.did = did;
        info.mid = mid;
        info.period = period;
        info.messageObject = new MessageObject(this.currentAccount, message, false);
        info.stopTime = getConnectionsManager().getCurrentTime() + period;
        final SharingLocationInfo old = this.sharingLocationsMap.get(did);
        this.sharingLocationsMap.put(did, info);
        if (old != null) {
            this.sharingLocations.remove(old);
        }
        this.sharingLocations.add(info);
        saveSharingLocation(info, 0);
        this.lastLocationSendTime = (SystemClock.uptimeMillis() - 30000) + DefaultRenderersFactory.DEFAULT_ALLOWED_VIDEO_JOINING_TIME_MS;
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$LocationController$-ea6trGEiunryBtF5oLUZH7wELM
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$addSharingLocation$4$LocationController(old, info);
            }
        });
    }

    public /* synthetic */ void lambda$addSharingLocation$4$LocationController(SharingLocationInfo old, SharingLocationInfo info) {
        if (old != null) {
            this.sharingLocationsUI.remove(old);
        }
        this.sharingLocationsUI.add(info);
        this.sharingLocationsMapUI.put(info.did, info);
        startService();
        NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.liveLocationsChanged, new Object[0]);
    }

    public boolean isSharingLocation(long did) {
        return this.sharingLocationsMapUI.indexOfKey(did) >= 0;
    }

    public SharingLocationInfo getSharingLocationInfo(long did) {
        return this.sharingLocationsMapUI.get(did);
    }

    private void loadSharingLocations() {
        getMessagesStorage().getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$LocationController$5pnqXv0CL8RzfGfuPGA7Qk1crfE
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$loadSharingLocations$8$LocationController();
            }
        });
    }

    public /* synthetic */ void lambda$loadSharingLocations$8$LocationController() {
        final ArrayList<SharingLocationInfo> result = new ArrayList<>();
        final ArrayList<TLRPC.User> users = new ArrayList<>();
        final ArrayList<TLRPC.Chat> chats = new ArrayList<>();
        try {
            ArrayList<Integer> usersToLoad = new ArrayList<>();
            ArrayList<Integer> chatsToLoad = new ArrayList<>();
            SQLiteCursor cursor = getMessagesStorage().getDatabase().queryFinalized("SELECT uid, mid, date, period, message FROM sharing_locations WHERE 1", new Object[0]);
            while (cursor.next()) {
                SharingLocationInfo info = new SharingLocationInfo();
                info.did = cursor.longValue(0);
                info.mid = cursor.intValue(1);
                info.stopTime = cursor.intValue(2);
                info.period = cursor.intValue(3);
                NativeByteBuffer data = cursor.byteBufferValue(4);
                if (data != null) {
                    info.messageObject = new MessageObject(this.currentAccount, TLRPC.Message.TLdeserialize(data, data.readInt32(false), false), false);
                    MessagesStorage.addUsersAndChatsFromMessage(info.messageObject.messageOwner, usersToLoad, chatsToLoad);
                    data.reuse();
                }
                result.add(info);
                int lower_id = (int) info.did;
                if (lower_id != 0) {
                    if (lower_id < 0) {
                        if (!chatsToLoad.contains(Integer.valueOf(-lower_id))) {
                            chatsToLoad.add(Integer.valueOf(-lower_id));
                        }
                    } else if (!usersToLoad.contains(Integer.valueOf(lower_id))) {
                        usersToLoad.add(Integer.valueOf(lower_id));
                    }
                }
            }
            cursor.dispose();
            if (!chatsToLoad.isEmpty()) {
                getMessagesStorage().getChatsInternal(TextUtils.join(",", chatsToLoad), chats);
            }
            if (!usersToLoad.isEmpty()) {
                getMessagesStorage().getUsersInternal(TextUtils.join(",", usersToLoad), users);
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
        if (!result.isEmpty()) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$LocationController$N_JLEiptU2Q397F8rn5jjPTmlrA
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$7$LocationController(users, chats, result);
                }
            });
        }
    }

    public /* synthetic */ void lambda$null$7$LocationController(ArrayList users, ArrayList chats, final ArrayList result) {
        getMessagesController().putUsers(users, true);
        getMessagesController().putChats(chats, true);
        Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$LocationController$MMtdP75gvt2cvNXgoTWDVRCJ9CA
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$6$LocationController(result);
            }
        });
    }

    public /* synthetic */ void lambda$null$6$LocationController(final ArrayList result) {
        this.sharingLocations.addAll(result);
        for (int a = 0; a < this.sharingLocations.size(); a++) {
            SharingLocationInfo info = this.sharingLocations.get(a);
            this.sharingLocationsMap.put(info.did, info);
        }
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$LocationController$wDicuoDX_9jyif59i_kOCLRHrsA
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$5$LocationController(result);
            }
        });
    }

    public /* synthetic */ void lambda$null$5$LocationController(ArrayList result) {
        this.sharingLocationsUI.addAll(result);
        for (int a = 0; a < result.size(); a++) {
            SharingLocationInfo info = (SharingLocationInfo) result.get(a);
            this.sharingLocationsMapUI.put(info.did, info);
        }
        startService();
        NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.liveLocationsChanged, new Object[0]);
    }

    private void saveSharingLocation(final SharingLocationInfo info, final int remove) {
        getMessagesStorage().getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$LocationController$3Ugp35-nGKsdchD2GuSOVcRaABM
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$saveSharingLocation$9$LocationController(remove, info);
            }
        });
    }

    public /* synthetic */ void lambda$saveSharingLocation$9$LocationController(int remove, SharingLocationInfo info) {
        try {
            if (remove == 2) {
                getMessagesStorage().getDatabase().executeFast("DELETE FROM sharing_locations WHERE 1").stepThis().dispose();
            } else if (remove == 1) {
                if (info == null) {
                    return;
                }
                getMessagesStorage().getDatabase().executeFast("DELETE FROM sharing_locations WHERE uid = " + info.did).stepThis().dispose();
            } else {
                if (info == null) {
                    return;
                }
                SQLitePreparedStatement state = getMessagesStorage().getDatabase().executeFast("REPLACE INTO sharing_locations VALUES(?, ?, ?, ?, ?)");
                state.requery();
                NativeByteBuffer data = new NativeByteBuffer(info.messageObject.messageOwner.getObjectSize());
                info.messageObject.messageOwner.serializeToStream(data);
                state.bindLong(1, info.did);
                state.bindInteger(2, info.mid);
                state.bindInteger(3, info.stopTime);
                state.bindInteger(4, info.period);
                state.bindByteBuffer(5, data);
                state.step();
                state.dispose();
                data.reuse();
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public void removeSharingLocation(final long did) {
        Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$LocationController$AvAlzHV8DDqxxZOcnC-8Q6Fik_s
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$removeSharingLocation$12$LocationController(did);
            }
        });
    }

    public /* synthetic */ void lambda$removeSharingLocation$12$LocationController(long did) {
        final SharingLocationInfo info = this.sharingLocationsMap.get(did);
        this.sharingLocationsMap.remove(did);
        if (info != null) {
            TLRPC.TL_messages_editMessage req = new TLRPC.TL_messages_editMessage();
            req.peer = getMessagesController().getInputPeer((int) info.did);
            req.id = info.mid;
            req.flags |= 16384;
            req.media = new TLRPC.TL_inputMediaGeoLive();
            req.media.stopped = true;
            req.media.geo_point = new TLRPC.TL_inputGeoPointEmpty();
            getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$LocationController$WSvci--AWqi285ltYxom2NWca6w
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$null$10$LocationController(tLObject, tL_error);
                }
            });
            this.sharingLocations.remove(info);
            saveSharingLocation(info, 1);
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$LocationController$fBwnwhMp01f1lSHE0B10YsT6jKU
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$11$LocationController(info);
                }
            });
            if (this.sharingLocations.isEmpty()) {
                stop();
            }
        }
    }

    public /* synthetic */ void lambda$null$10$LocationController(TLObject response, TLRPC.TL_error error) {
        if (error != null) {
            return;
        }
        getMessagesController().processUpdates((TLRPC.Updates) response, false);
    }

    public /* synthetic */ void lambda$null$11$LocationController(SharingLocationInfo info) {
        this.sharingLocationsUI.remove(info);
        this.sharingLocationsMapUI.remove(info.did);
        if (this.sharingLocationsUI.isEmpty()) {
            stopService();
        }
        NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.liveLocationsChanged, new Object[0]);
    }

    private void startService() {
        try {
            ApplicationLoader.applicationContext.startService(new Intent(ApplicationLoader.applicationContext, (Class<?>) LocationSharingService.class));
        } catch (Throwable e) {
            FileLog.e(e);
        }
    }

    private void stopService() {
        ApplicationLoader.applicationContext.stopService(new Intent(ApplicationLoader.applicationContext, (Class<?>) LocationSharingService.class));
    }

    public void removeAllLocationSharings() {
        Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$LocationController$NgdURHvYw2z8WbVhFIbRL77eY2Y
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$removeAllLocationSharings$15$LocationController();
            }
        });
    }

    public /* synthetic */ void lambda$removeAllLocationSharings$15$LocationController() {
        for (int a = 0; a < this.sharingLocations.size(); a++) {
            SharingLocationInfo info = this.sharingLocations.get(a);
            TLRPC.TL_messages_editMessage req = new TLRPC.TL_messages_editMessage();
            req.peer = getMessagesController().getInputPeer((int) info.did);
            req.id = info.mid;
            req.flags |= 16384;
            req.media = new TLRPC.TL_inputMediaGeoLive();
            req.media.stopped = true;
            req.media.geo_point = new TLRPC.TL_inputGeoPointEmpty();
            getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$LocationController$UdqAhFAN8b3QvxkDys25YO4pGQk
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$null$13$LocationController(tLObject, tL_error);
                }
            });
        }
        this.sharingLocations.clear();
        this.sharingLocationsMap.clear();
        saveSharingLocation(null, 2);
        stop();
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$LocationController$qumL88ZN8fMQCnQ1oIugbbNXsnA
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$14$LocationController();
            }
        });
    }

    public /* synthetic */ void lambda$null$13$LocationController(TLObject response, TLRPC.TL_error error) {
        if (error != null) {
            return;
        }
        getMessagesController().processUpdates((TLRPC.Updates) response, false);
    }

    public /* synthetic */ void lambda$null$14$LocationController() {
        this.sharingLocationsUI.clear();
        this.sharingLocationsMapUI.clear();
        stopService();
        NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.liveLocationsChanged, new Object[0]);
    }

    private void start() {
        if (this.started) {
            return;
        }
        this.lastLocationStartTime = SystemClock.uptimeMillis();
        this.started = true;
    }

    private void stop() {
        if (this.lookingForPeopleNearby) {
            return;
        }
        this.started = false;
    }

    public void startLocationLookupForPeopleNearby(final boolean stop) {
        Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$LocationController$eWTiEGfePgJaD8Zr-doc6uaLsHg
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$startLocationLookupForPeopleNearby$16$LocationController(stop);
            }
        });
    }

    public /* synthetic */ void lambda$startLocationLookupForPeopleNearby$16$LocationController(boolean stop) {
        boolean z = !stop;
        this.lookingForPeopleNearby = z;
        if (z) {
            start();
        } else if (this.sharingLocations.isEmpty()) {
            stop();
        }
    }

    public static int getLocationsCount() {
        int count = 0;
        for (int a = 0; a < 3; a++) {
            count += getInstance(a).sharingLocationsUI.size();
        }
        return count;
    }
}
