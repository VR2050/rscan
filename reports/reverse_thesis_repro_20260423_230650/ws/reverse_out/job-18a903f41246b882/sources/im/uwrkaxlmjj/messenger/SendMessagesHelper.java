package im.uwrkaxlmjj.messenger;

import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.drawable.BitmapDrawable;
import android.location.Location;
import android.location.LocationListener;
import android.location.LocationManager;
import android.media.MediaMetadataRetriever;
import android.media.MediaPlayer;
import android.media.ThumbnailUtils;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.SystemClock;
import android.text.TextUtils;
import android.util.LongSparseArray;
import android.util.SparseArray;
import androidx.core.view.inputmethod.InputContentInfoCompat;
import com.google.android.exoplayer2.DefaultRenderersFactory;
import com.snail.antifake.deviceid.ShellAdbUtils;
import im.uwrkaxlmjj.messenger.MediaController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.support.SparseLongArray;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.NativeByteBuffer;
import im.uwrkaxlmjj.tgnet.QuickAckDelegate;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.SerializedData;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.tgnet.TLRPCContacts;
import im.uwrkaxlmjj.ui.ChatActivity;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.components.AlertsCreator;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/* JADX INFO: loaded from: classes2.dex */
public class SendMessagesHelper extends BaseController implements NotificationCenter.NotificationCenterDelegate {
    private static volatile SendMessagesHelper[] Instance;
    private static DispatchQueue mediaSendQueue = new DispatchQueue("mediaSendQueue");
    private static ThreadPoolExecutor mediaSendThreadPool;
    private HashMap<String, ArrayList<DelayedMessage>> delayedMessages;
    private SparseArray<TLRPC.Message> editingMessages;
    private LocationProvider locationProvider;
    private SparseArray<TLRPC.Message> sendingMessages;
    private LongSparseArray<Integer> sendingMessagesIdDialogs;
    private SparseArray<MessageObject> unsentMessages;
    private SparseArray<TLRPC.Message> uploadMessages;
    private LongSparseArray<Integer> uploadingMessagesIdDialogs;
    private LongSparseArray<Long> voteSendTime;
    private HashMap<String, Boolean> waitingForCallback;
    private HashMap<String, MessageObject> waitingForLocation;
    private HashMap<String, byte[]> waitingForVote;

    public static class SendingMediaInfo {
        public boolean canDeleteAfter;
        public String caption;
        public ArrayList<TLRPC.MessageEntity> entities;
        public TLRPC.BotInlineResult inlineResult;
        public boolean isVideo;
        public ArrayList<TLRPC.InputDocument> masks;
        public HashMap<String, String> params;
        public String path;
        public MediaController.SearchImage searchImage;
        public int ttl;
        public Uri uri;
        public VideoEditedInfo videoEditedInfo;
    }

    static {
        int cores;
        if (Build.VERSION.SDK_INT >= 17) {
            cores = Runtime.getRuntime().availableProcessors();
        } else {
            cores = 2;
        }
        mediaSendThreadPool = new ThreadPoolExecutor(cores, cores, 60L, TimeUnit.SECONDS, new LinkedBlockingQueue());
        Instance = new SendMessagesHelper[3];
    }

    /* JADX INFO: Access modifiers changed from: private */
    static class MediaSendPrepareWorker {
        public volatile String parentObject;
        public volatile TLRPC.TL_photo photo;
        public CountDownLatch sync;

        private MediaSendPrepareWorker() {
        }
    }

    public static class LocationProvider {
        private LocationProviderDelegate delegate;
        private GpsLocationListener gpsLocationListener;
        private Location lastKnownLocation;
        private LocationManager locationManager;
        private Runnable locationQueryCancelRunnable;
        private GpsLocationListener networkLocationListener;

        public interface LocationProviderDelegate {
            void onLocationAcquired(Location location);

            void onUnableLocationAcquire();
        }

        private class GpsLocationListener implements LocationListener {
            private GpsLocationListener() {
            }

            @Override // android.location.LocationListener
            public void onLocationChanged(Location location) {
                if (location == null || LocationProvider.this.locationQueryCancelRunnable == null) {
                    return;
                }
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.d("found location " + location);
                }
                LocationProvider.this.lastKnownLocation = location;
                if (location.getAccuracy() < 100.0f) {
                    if (LocationProvider.this.delegate != null) {
                        LocationProvider.this.delegate.onLocationAcquired(location);
                    }
                    if (LocationProvider.this.locationQueryCancelRunnable != null) {
                        AndroidUtilities.cancelRunOnUIThread(LocationProvider.this.locationQueryCancelRunnable);
                    }
                    LocationProvider.this.cleanup();
                }
            }

            @Override // android.location.LocationListener
            public void onStatusChanged(String provider, int status, Bundle extras) {
            }

            @Override // android.location.LocationListener
            public void onProviderEnabled(String provider) {
            }

            @Override // android.location.LocationListener
            public void onProviderDisabled(String provider) {
            }
        }

        public LocationProvider() {
            this.gpsLocationListener = new GpsLocationListener();
            this.networkLocationListener = new GpsLocationListener();
        }

        public LocationProvider(LocationProviderDelegate locationProviderDelegate) {
            this.gpsLocationListener = new GpsLocationListener();
            this.networkLocationListener = new GpsLocationListener();
            this.delegate = locationProviderDelegate;
        }

        public void setDelegate(LocationProviderDelegate locationProviderDelegate) {
            this.delegate = locationProviderDelegate;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void cleanup() {
            this.locationManager.removeUpdates(this.gpsLocationListener);
            this.locationManager.removeUpdates(this.networkLocationListener);
            this.lastKnownLocation = null;
            this.locationQueryCancelRunnable = null;
        }

        public void start() {
            if (this.locationManager == null) {
                this.locationManager = (LocationManager) ApplicationLoader.applicationContext.getSystemService("location");
            }
            try {
                this.locationManager.requestLocationUpdates("gps", 1L, 0.0f, this.gpsLocationListener);
            } catch (Exception e) {
                FileLog.e(e);
            }
            try {
                this.locationManager.requestLocationUpdates("network", 1L, 0.0f, this.networkLocationListener);
            } catch (Exception e2) {
                FileLog.e(e2);
            }
            try {
                Location lastKnownLocation = this.locationManager.getLastKnownLocation("gps");
                this.lastKnownLocation = lastKnownLocation;
                if (lastKnownLocation == null) {
                    this.lastKnownLocation = this.locationManager.getLastKnownLocation("network");
                }
            } catch (Exception e3) {
                FileLog.e(e3);
            }
            Runnable runnable = this.locationQueryCancelRunnable;
            if (runnable != null) {
                AndroidUtilities.cancelRunOnUIThread(runnable);
            }
            Runnable runnable2 = new Runnable() { // from class: im.uwrkaxlmjj.messenger.SendMessagesHelper.LocationProvider.1
                @Override // java.lang.Runnable
                public void run() {
                    if (LocationProvider.this.locationQueryCancelRunnable == this) {
                        if (LocationProvider.this.delegate != null) {
                            if (LocationProvider.this.lastKnownLocation != null) {
                                LocationProvider.this.delegate.onLocationAcquired(LocationProvider.this.lastKnownLocation);
                            } else {
                                LocationProvider.this.delegate.onUnableLocationAcquire();
                            }
                        }
                        LocationProvider.this.cleanup();
                    }
                }
            };
            this.locationQueryCancelRunnable = runnable2;
            AndroidUtilities.runOnUIThread(runnable2, DefaultRenderersFactory.DEFAULT_ALLOWED_VIDEO_JOINING_TIME_MS);
        }

        public void stop() {
            if (this.locationManager == null) {
                return;
            }
            Runnable runnable = this.locationQueryCancelRunnable;
            if (runnable != null) {
                AndroidUtilities.cancelRunOnUIThread(runnable);
            }
            cleanup();
        }
    }

    protected class DelayedMessageSendAfterRequest {
        public DelayedMessage delayedMessage;
        public MessageObject msgObj;
        public ArrayList<MessageObject> msgObjs;
        public String originalPath;
        public ArrayList<String> originalPaths;
        public Object parentObject;
        public ArrayList<Object> parentObjects;
        public TLObject request;
        public boolean scheduled;

        protected DelayedMessageSendAfterRequest() {
        }
    }

    protected class DelayedMessage {
        public TLRPC.EncryptedChat encryptedChat;
        public HashMap<Object, Object> extraHashMap;
        public int finalGroupMessage;
        public long groupId;
        public String httpLocation;
        public ArrayList<String> httpLocations;
        public ArrayList<TLRPC.InputMedia> inputMedias;
        public TLRPC.InputMedia inputUploadMedia;
        public TLObject locationParent;
        public ArrayList<TLRPC.PhotoSize> locations;
        public ArrayList<MessageObject> messageObjects;
        public ArrayList<TLRPC.Message> messages;
        public MessageObject obj;
        public String originalPath;
        public ArrayList<String> originalPaths;
        public Object parentObject;
        public ArrayList<Object> parentObjects;
        public long peer;
        public boolean performMediaUpload;
        public TLRPC.PhotoSize photoSize;
        ArrayList<DelayedMessageSendAfterRequest> requests;
        public boolean scheduled;
        public TLObject sendEncryptedRequest;
        public TLObject sendRequest;
        public int type;
        public VideoEditedInfo videoEditedInfo;
        public ArrayList<VideoEditedInfo> videoEditedInfos;

        public DelayedMessage(long peer) {
            this.peer = peer;
        }

        public void initForGroup(long id) {
            this.type = 4;
            this.groupId = id;
            this.messageObjects = new ArrayList<>();
            this.messages = new ArrayList<>();
            this.inputMedias = new ArrayList<>();
            this.originalPaths = new ArrayList<>();
            this.parentObjects = new ArrayList<>();
            this.extraHashMap = new HashMap<>();
            this.locations = new ArrayList<>();
            this.httpLocations = new ArrayList<>();
            this.videoEditedInfos = new ArrayList<>();
        }

        public void addDelayedRequest(TLObject req, MessageObject msgObj, String originalPath, Object parentObject, DelayedMessage delayedMessage, boolean scheduled) {
            DelayedMessageSendAfterRequest request = SendMessagesHelper.this.new DelayedMessageSendAfterRequest();
            request.request = req;
            request.msgObj = msgObj;
            request.originalPath = originalPath;
            request.delayedMessage = delayedMessage;
            request.parentObject = parentObject;
            request.scheduled = scheduled;
            if (this.requests == null) {
                this.requests = new ArrayList<>();
            }
            this.requests.add(request);
        }

        public void addDelayedRequest(TLObject req, ArrayList<MessageObject> msgObjs, ArrayList<String> originalPaths, ArrayList<Object> parentObjects, DelayedMessage delayedMessage, boolean scheduled) {
            DelayedMessageSendAfterRequest request = SendMessagesHelper.this.new DelayedMessageSendAfterRequest();
            request.request = req;
            request.msgObjs = msgObjs;
            request.originalPaths = originalPaths;
            request.delayedMessage = delayedMessage;
            request.parentObjects = parentObjects;
            request.scheduled = scheduled;
            if (this.requests == null) {
                this.requests = new ArrayList<>();
            }
            this.requests.add(request);
        }

        public void sendDelayedRequests() {
            if (this.requests != null) {
                int i = this.type;
                if (i != 4 && i != 0) {
                    return;
                }
                int size = this.requests.size();
                for (int a = 0; a < size; a++) {
                    DelayedMessageSendAfterRequest request = this.requests.get(a);
                    if (request.request instanceof TLRPC.TL_messages_sendEncryptedMultiMedia) {
                        SendMessagesHelper.this.getSecretChatHelper().performSendEncryptedRequest((TLRPC.TL_messages_sendEncryptedMultiMedia) request.request, this);
                    } else if (!(request.request instanceof TLRPC.TL_messages_sendMultiMedia)) {
                        SendMessagesHelper.this.performSendMessageRequest(request.request, request.msgObj, request.originalPath, request.delayedMessage, request.parentObject, request.scheduled);
                    } else {
                        SendMessagesHelper.this.performSendMessageRequestMulti((TLRPC.TL_messages_sendMultiMedia) request.request, request.msgObjs, request.originalPaths, request.parentObjects, request.delayedMessage, request.scheduled);
                    }
                }
                this.requests = null;
            }
        }

        public void markAsError() {
            if (this.type == 4) {
                for (int a = 0; a < this.messageObjects.size(); a++) {
                    MessageObject obj = this.messageObjects.get(a);
                    SendMessagesHelper.this.getMessagesStorage().markMessageAsSendError(obj.messageOwner, obj.scheduled);
                    obj.messageOwner.send_state = 2;
                    SendMessagesHelper.this.getNotificationCenter().postNotificationName(NotificationCenter.messageSendError, Integer.valueOf(obj.getId()));
                    SendMessagesHelper.this.processSentMessage(obj.getId());
                    SendMessagesHelper.this.removeFromUploadingMessages(obj.getId(), this.scheduled);
                }
                SendMessagesHelper.this.delayedMessages.remove("group_" + this.groupId);
            } else {
                SendMessagesHelper.this.getMessagesStorage().markMessageAsSendError(this.obj.messageOwner, this.obj.scheduled);
                this.obj.messageOwner.send_state = 2;
                SendMessagesHelper.this.getNotificationCenter().postNotificationName(NotificationCenter.messageSendError, Integer.valueOf(this.obj.getId()));
                SendMessagesHelper.this.processSentMessage(this.obj.getId());
                SendMessagesHelper.this.removeFromUploadingMessages(this.obj.getId(), this.scheduled);
            }
            sendDelayedRequests();
        }
    }

    public static SendMessagesHelper getInstance(int num) {
        SendMessagesHelper localInstance = Instance[num];
        if (localInstance == null) {
            synchronized (SendMessagesHelper.class) {
                localInstance = Instance[num];
                if (localInstance == null) {
                    SendMessagesHelper[] sendMessagesHelperArr = Instance;
                    SendMessagesHelper sendMessagesHelper = new SendMessagesHelper(num);
                    localInstance = sendMessagesHelper;
                    sendMessagesHelperArr[num] = sendMessagesHelper;
                }
            }
        }
        return localInstance;
    }

    public SendMessagesHelper(int instance) {
        super(instance);
        this.delayedMessages = new HashMap<>();
        this.unsentMessages = new SparseArray<>();
        this.sendingMessages = new SparseArray<>();
        this.editingMessages = new SparseArray<>();
        this.uploadMessages = new SparseArray<>();
        this.sendingMessagesIdDialogs = new LongSparseArray<>();
        this.uploadingMessagesIdDialogs = new LongSparseArray<>();
        this.waitingForLocation = new HashMap<>();
        this.waitingForCallback = new HashMap<>();
        this.waitingForVote = new HashMap<>();
        this.voteSendTime = new LongSparseArray<>();
        this.locationProvider = new LocationProvider(new LocationProvider.LocationProviderDelegate() { // from class: im.uwrkaxlmjj.messenger.SendMessagesHelper.1
            @Override // im.uwrkaxlmjj.messenger.SendMessagesHelper.LocationProvider.LocationProviderDelegate
            public void onLocationAcquired(Location location) {
                SendMessagesHelper.this.sendLocation(location);
                SendMessagesHelper.this.waitingForLocation.clear();
            }

            @Override // im.uwrkaxlmjj.messenger.SendMessagesHelper.LocationProvider.LocationProviderDelegate
            public void onUnableLocationAcquire() {
                HashMap<String, MessageObject> waitingForLocationCopy = new HashMap<>(SendMessagesHelper.this.waitingForLocation);
                SendMessagesHelper.this.getNotificationCenter().postNotificationName(NotificationCenter.wasUnableToFindCurrentLocation, waitingForLocationCopy);
                SendMessagesHelper.this.waitingForLocation.clear();
            }
        });
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SendMessagesHelper$yekR1VsT2eEUSr754uH7XvYB4u8
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$new$0$SendMessagesHelper();
            }
        });
    }

    public /* synthetic */ void lambda$new$0$SendMessagesHelper() {
        getNotificationCenter().addObserver(this, NotificationCenter.FileDidUpload);
        getNotificationCenter().addObserver(this, NotificationCenter.FileDidFailUpload);
        getNotificationCenter().addObserver(this, NotificationCenter.filePreparingStarted);
        getNotificationCenter().addObserver(this, NotificationCenter.fileNewChunkAvailable);
        getNotificationCenter().addObserver(this, NotificationCenter.filePreparingFailed);
        getNotificationCenter().addObserver(this, NotificationCenter.httpFileDidFailedLoad);
        getNotificationCenter().addObserver(this, NotificationCenter.httpFileDidLoad);
        getNotificationCenter().addObserver(this, NotificationCenter.fileDidLoad);
        getNotificationCenter().addObserver(this, NotificationCenter.fileDidFailToLoad);
    }

    public void cleanup() {
        this.delayedMessages.clear();
        this.unsentMessages.clear();
        this.sendingMessages.clear();
        this.editingMessages.clear();
        this.sendingMessagesIdDialogs.clear();
        this.uploadMessages.clear();
        this.uploadingMessagesIdDialogs.clear();
        this.waitingForLocation.clear();
        this.waitingForCallback.clear();
        this.waitingForVote.clear();
        this.locationProvider.stop();
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        String path;
        ArrayList<DelayedMessage> arr;
        int fileType;
        final MessageObject messageObject;
        ArrayList<DelayedMessage> arr2;
        ArrayList<DelayedMessage> arr3;
        TLRPC.InputMedia media;
        ArrayList<DelayedMessage> arr4;
        String location;
        TLRPC.InputFile file;
        String str;
        TLRPC.InputEncryptedFile encryptedFile;
        int a;
        int a2;
        TLRPC.InputEncryptedFile encryptedFile2;
        String str2 = "_t";
        if (id == NotificationCenter.FileDidUpload) {
            String location2 = (String) args[0];
            TLRPC.InputFile file2 = (TLRPC.InputFile) args[1];
            TLRPC.InputEncryptedFile encryptedFile3 = (TLRPC.InputEncryptedFile) args[2];
            ArrayList<DelayedMessage> arr5 = this.delayedMessages.get(location2);
            if (arr5 != null) {
                int a3 = 0;
                while (true) {
                    int a4 = a3;
                    if (a4 >= arr5.size()) {
                        break;
                    }
                    DelayedMessage message = arr5.get(a4);
                    if (message.sendRequest instanceof TLRPC.TL_messages_sendMedia) {
                        TLRPC.InputMedia media2 = ((TLRPC.TL_messages_sendMedia) message.sendRequest).media;
                        media = media2;
                    } else if (message.sendRequest instanceof TLRPC.TL_messages_editMessage) {
                        TLRPC.InputMedia media3 = ((TLRPC.TL_messages_editMessage) message.sendRequest).media;
                        media = media3;
                    } else if (!(message.sendRequest instanceof TLRPC.TL_messages_sendMultiMedia)) {
                        media = null;
                    } else {
                        TLRPC.InputMedia media4 = (TLRPC.InputMedia) message.extraHashMap.get(location2);
                        media = media4;
                    }
                    if (file2 != null && media != null) {
                        if (message.type == 0) {
                            media.file = file2;
                            a2 = a4;
                            arr4 = arr5;
                            String location3 = location2;
                            encryptedFile2 = encryptedFile3;
                            performSendMessageRequest(message.sendRequest, message.obj, message.originalPath, message, true, null, message.parentObject, message.scheduled);
                            file = file2;
                            location = location3;
                        } else {
                            TLRPC.InputMedia media5 = media;
                            a2 = a4;
                            arr4 = arr5;
                            encryptedFile2 = encryptedFile3;
                            TLRPC.InputFile file3 = file2;
                            String location4 = location2;
                            if (message.type == 1) {
                                if (media5.file == null) {
                                    file = file3;
                                    media5.file = file;
                                    if (media5.thumb == null && message.photoSize != null && message.photoSize.location != null) {
                                        performSendDelayedMessage(message);
                                        location = location4;
                                    } else {
                                        performSendMessageRequest(message.sendRequest, message.obj, message.originalPath, null, message.parentObject, message.scheduled);
                                        location = location4;
                                    }
                                } else {
                                    file = file3;
                                    media5.thumb = file;
                                    media5.flags |= 4;
                                    performSendMessageRequest(message.sendRequest, message.obj, message.originalPath, null, message.parentObject, message.scheduled);
                                    location = location4;
                                }
                            } else {
                                file = file3;
                                if (message.type == 2) {
                                    if (media5.file == null) {
                                        media5.file = file;
                                        if (media5.thumb == null && message.photoSize != null && message.photoSize.location != null) {
                                            performSendDelayedMessage(message);
                                            location = location4;
                                        } else {
                                            performSendMessageRequest(message.sendRequest, message.obj, message.originalPath, null, message.parentObject, message.scheduled);
                                            location = location4;
                                        }
                                    } else {
                                        media5.thumb = file;
                                        media5.flags |= 4;
                                        performSendMessageRequest(message.sendRequest, message.obj, message.originalPath, null, message.parentObject, message.scheduled);
                                        location = location4;
                                    }
                                } else if (message.type == 3) {
                                    media5.file = file;
                                    performSendMessageRequest(message.sendRequest, message.obj, message.originalPath, null, message.parentObject, message.scheduled);
                                    location = location4;
                                } else if (message.type != 4) {
                                    location = location4;
                                } else if (media5 instanceof TLRPC.TL_inputMediaUploadedDocument) {
                                    if (media5.file == null) {
                                        media5.file = file;
                                        HashMap<Object, Object> map = message.extraHashMap;
                                        StringBuilder sb = new StringBuilder();
                                        location = location4;
                                        sb.append(location);
                                        sb.append("_i");
                                        MessageObject messageObject2 = (MessageObject) map.get(sb.toString());
                                        int index = message.messageObjects.indexOf(messageObject2);
                                        message.photoSize = (TLRPC.PhotoSize) message.extraHashMap.get(location + str2);
                                        stopVideoService(message.messageObjects.get(index).messageOwner.attachPath);
                                        if (media5.thumb != null || message.photoSize == null) {
                                            uploadMultiMedia(message, media5, null, location);
                                        } else {
                                            message.performMediaUpload = true;
                                            performSendDelayedMessage(message, index);
                                        }
                                    } else {
                                        location = location4;
                                        media5.thumb = file;
                                        media5.flags |= 4;
                                        uploadMultiMedia(message, media5, null, (String) message.extraHashMap.get(location + "_o"));
                                    }
                                } else {
                                    location = location4;
                                    media5.file = file;
                                    uploadMultiMedia(message, media5, null, location);
                                }
                            }
                        }
                        int a5 = a2;
                        arr4.remove(a5);
                        a = a5 - 1;
                        str = str2;
                        encryptedFile = encryptedFile2;
                    } else {
                        arr4 = arr5;
                        TLRPC.InputEncryptedFile encryptedFile4 = encryptedFile3;
                        location = location2;
                        file = file2;
                        if (encryptedFile4 == null || message.sendEncryptedRequest == null) {
                            str = str2;
                            encryptedFile = encryptedFile4;
                            a = a4;
                        } else {
                            TLRPC.TL_decryptedMessage decryptedMessage = null;
                            if (message.type == 4) {
                                TLRPC.TL_messages_sendEncryptedMultiMedia req = (TLRPC.TL_messages_sendEncryptedMultiMedia) message.sendEncryptedRequest;
                                TLRPC.InputEncryptedFile inputEncryptedFile = (TLRPC.InputEncryptedFile) message.extraHashMap.get(location);
                                int index2 = req.files.indexOf(inputEncryptedFile);
                                if (index2 < 0) {
                                    str = str2;
                                    encryptedFile = encryptedFile4;
                                } else {
                                    encryptedFile = encryptedFile4;
                                    req.files.set(index2, encryptedFile);
                                    str = str2;
                                    if (inputEncryptedFile.id == 1) {
                                        message.photoSize = (TLRPC.PhotoSize) message.extraHashMap.get(location + str);
                                        stopVideoService(message.messageObjects.get(index2).messageOwner.attachPath);
                                    }
                                    TLRPC.TL_decryptedMessage decryptedMessage2 = req.messages.get(index2);
                                    decryptedMessage = decryptedMessage2;
                                }
                            } else {
                                str = str2;
                                encryptedFile = encryptedFile4;
                                decryptedMessage = (TLRPC.TL_decryptedMessage) message.sendEncryptedRequest;
                            }
                            if (decryptedMessage != null) {
                                if ((decryptedMessage.media instanceof TLRPC.TL_decryptedMessageMediaVideo) || (decryptedMessage.media instanceof TLRPC.TL_decryptedMessageMediaPhoto) || (decryptedMessage.media instanceof TLRPC.TL_decryptedMessageMediaDocument)) {
                                    long size = ((Long) args[5]).longValue();
                                    decryptedMessage.media.size = (int) size;
                                }
                                decryptedMessage.media.key = (byte[]) args[3];
                                decryptedMessage.media.iv = (byte[]) args[4];
                                if (message.type == 4) {
                                    uploadMultiMedia(message, null, encryptedFile, location);
                                } else {
                                    getSecretChatHelper().performSendEncryptedRequest(decryptedMessage, message.obj.messageOwner, message.encryptedChat, encryptedFile, message.originalPath, message.obj);
                                }
                            }
                            arr4.remove(a4);
                            a = a4 - 1;
                        }
                    }
                    a3 = a + 1;
                    file2 = file;
                    str2 = str;
                    encryptedFile3 = encryptedFile;
                    arr5 = arr4;
                    location2 = location;
                }
                String location5 = location2;
                if (arr5.isEmpty()) {
                    this.delayedMessages.remove(location5);
                }
            }
            return;
        }
        if (id == NotificationCenter.FileDidFailUpload) {
            String location6 = (String) args[0];
            boolean enc = ((Boolean) args[1]).booleanValue();
            ArrayList<DelayedMessage> arr6 = this.delayedMessages.get(location6);
            if (arr6 != null) {
                int a6 = 0;
                while (a6 < arr6.size()) {
                    DelayedMessage obj = arr6.get(a6);
                    if ((enc && obj.sendEncryptedRequest != null) || (!enc && obj.sendRequest != null)) {
                        obj.markAsError();
                        arr6.remove(a6);
                        a6--;
                    }
                    a6++;
                }
                if (arr6.isEmpty()) {
                    this.delayedMessages.remove(location6);
                    return;
                }
                return;
            }
            return;
        }
        if (id == NotificationCenter.filePreparingStarted) {
            MessageObject messageObject3 = (MessageObject) args[0];
            if (messageObject3.getId() == 0) {
                return;
            }
            ArrayList<DelayedMessage> arr7 = this.delayedMessages.get(messageObject3.messageOwner.attachPath);
            if (arr7 != null) {
                int a7 = 0;
                while (true) {
                    if (a7 >= arr7.size()) {
                        break;
                    }
                    DelayedMessage message2 = arr7.get(a7);
                    if (message2.type == 4) {
                        int index3 = message2.messageObjects.indexOf(messageObject3);
                        message2.photoSize = (TLRPC.PhotoSize) message2.extraHashMap.get(messageObject3.messageOwner.attachPath + "_t");
                        message2.performMediaUpload = true;
                        performSendDelayedMessage(message2, index3);
                        arr7.remove(a7);
                        break;
                    }
                    if (message2.obj != messageObject3) {
                        a7++;
                    } else {
                        message2.videoEditedInfo = null;
                        performSendDelayedMessage(message2);
                        arr7.remove(a7);
                        break;
                    }
                }
                if (arr7.isEmpty()) {
                    this.delayedMessages.remove(messageObject3.messageOwner.attachPath);
                    return;
                }
                return;
            }
            return;
        }
        if (id == NotificationCenter.fileNewChunkAvailable) {
            MessageObject messageObject4 = (MessageObject) args[0];
            if (messageObject4.getId() == 0) {
                return;
            }
            String finalPath = (String) args[1];
            long availableSize = ((Long) args[2]).longValue();
            long finalSize = ((Long) args[3]).longValue();
            boolean isEncrypted = ((int) messageObject4.getDialogId()) == 0;
            getFileLoader().checkUploadNewDataAvailable(finalPath, isEncrypted, availableSize, finalSize);
            if (finalSize != 0) {
                stopVideoService(messageObject4.messageOwner.attachPath);
                ArrayList<DelayedMessage> arr8 = this.delayedMessages.get(messageObject4.messageOwner.attachPath);
                if (arr8 != null) {
                    int a8 = 0;
                    while (a8 < arr8.size()) {
                        DelayedMessage message3 = arr8.get(a8);
                        if (message3.type == 4) {
                            int b = 0;
                            while (true) {
                                if (b >= message3.messageObjects.size()) {
                                    arr3 = arr8;
                                    break;
                                }
                                MessageObject obj2 = message3.messageObjects.get(b);
                                if (obj2 != messageObject4) {
                                    b++;
                                } else {
                                    obj2.videoEditedInfo = null;
                                    obj2.messageOwner.params.remove("ve");
                                    obj2.messageOwner.media.document.size = (int) finalSize;
                                    ArrayList<TLRPC.Message> messages = new ArrayList<>();
                                    messages.add(obj2.messageOwner);
                                    arr3 = arr8;
                                    getMessagesStorage().putMessages(messages, false, true, false, 0, obj2.scheduled);
                                    break;
                                }
                            }
                        } else {
                            arr3 = arr8;
                            if (message3.obj == messageObject4) {
                                message3.obj.videoEditedInfo = null;
                                message3.obj.messageOwner.params.remove("ve");
                                message3.obj.messageOwner.media.document.size = (int) finalSize;
                                ArrayList<TLRPC.Message> messages2 = new ArrayList<>();
                                messages2.add(message3.obj.messageOwner);
                                getMessagesStorage().putMessages(messages2, false, true, false, 0, message3.obj.scheduled);
                                return;
                            }
                        }
                        a8++;
                        arr8 = arr3;
                    }
                    return;
                }
                return;
            }
            return;
        }
        if (id == NotificationCenter.filePreparingFailed) {
            MessageObject messageObject5 = (MessageObject) args[0];
            if (messageObject5.getId() == 0) {
                return;
            }
            String finalPath2 = (String) args[1];
            stopVideoService(messageObject5.messageOwner.attachPath);
            ArrayList<DelayedMessage> arr9 = this.delayedMessages.get(finalPath2);
            if (arr9 != null) {
                int a9 = 0;
                while (a9 < arr9.size()) {
                    DelayedMessage message4 = arr9.get(a9);
                    if (message4.type == 4) {
                        int b2 = 0;
                        while (true) {
                            if (b2 >= message4.messages.size()) {
                                break;
                            }
                            if (message4.messageObjects.get(b2) != messageObject5) {
                                b2++;
                            } else {
                                message4.markAsError();
                                arr9.remove(a9);
                                a9--;
                                break;
                            }
                        }
                    } else if (message4.obj == messageObject5) {
                        message4.markAsError();
                        arr9.remove(a9);
                        a9--;
                    }
                    a9++;
                }
                if (arr9.isEmpty()) {
                    this.delayedMessages.remove(finalPath2);
                    return;
                }
                return;
            }
            return;
        }
        if (id != NotificationCenter.httpFileDidLoad) {
            if (id == NotificationCenter.fileDidLoad) {
                String path2 = (String) args[0];
                ArrayList<DelayedMessage> arr10 = this.delayedMessages.get(path2);
                if (arr10 != null) {
                    for (int a10 = 0; a10 < arr10.size(); a10++) {
                        performSendDelayedMessage(arr10.get(a10));
                    }
                    this.delayedMessages.remove(path2);
                    return;
                }
                return;
            }
            if ((id == NotificationCenter.httpFileDidFailedLoad || id == NotificationCenter.fileDidFailToLoad) && (arr = this.delayedMessages.get((path = (String) args[0]))) != null) {
                for (int a11 = 0; a11 < arr.size(); a11++) {
                    arr.get(a11).markAsError();
                }
                this.delayedMessages.remove(path);
                return;
            }
            return;
        }
        final String path3 = (String) args[0];
        ArrayList<DelayedMessage> arr11 = this.delayedMessages.get(path3);
        if (arr11 != null) {
            int a12 = 0;
            while (a12 < arr11.size()) {
                final DelayedMessage message5 = arr11.get(a12);
                if (message5.type == 0) {
                    fileType = 0;
                    messageObject = message5.obj;
                } else if (message5.type == 2) {
                    fileType = 1;
                    messageObject = message5.obj;
                } else if (message5.type != 4) {
                    fileType = -1;
                    messageObject = null;
                } else {
                    MessageObject messageObject6 = (MessageObject) message5.extraHashMap.get(path3);
                    if (messageObject6.getDocument() != null) {
                        fileType = 1;
                        messageObject = messageObject6;
                    } else {
                        fileType = 0;
                        messageObject = messageObject6;
                    }
                }
                if (fileType == 0) {
                    String md5 = Utilities.MD5(path3) + "." + ImageLoader.getHttpUrlExtension(path3, "file");
                    final File cacheFile = new File(FileLoader.getDirectory(4), md5);
                    final MessageObject messageObject7 = messageObject;
                    arr2 = arr11;
                    Utilities.globalQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SendMessagesHelper$-iR2vIn7Pk6uR6N0SBYdxLuuUD8
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$didReceivedNotification$2$SendMessagesHelper(cacheFile, messageObject7, message5, path3);
                        }
                    });
                } else {
                    arr2 = arr11;
                    if (fileType == 1) {
                        String md52 = Utilities.MD5(path3) + ".gif";
                        final File cacheFile2 = new File(FileLoader.getDirectory(4), md52);
                        Utilities.globalQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SendMessagesHelper$KZAmPrEYogjW30OKIXU9JFED66k
                            @Override // java.lang.Runnable
                            public final void run() {
                                this.f$0.lambda$didReceivedNotification$4$SendMessagesHelper(message5, cacheFile2, messageObject);
                            }
                        });
                    }
                }
                a12++;
                arr11 = arr2;
            }
            this.delayedMessages.remove(path3);
        }
    }

    public /* synthetic */ void lambda$didReceivedNotification$2$SendMessagesHelper(final File cacheFile, final MessageObject messageObject, final DelayedMessage message, final String path) {
        final TLRPC.TL_photo photo = generatePhotoSizes(cacheFile.toString(), null, false);
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SendMessagesHelper$ooIxQDlADXVLaXPjgo8sQdAOs_c
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$1$SendMessagesHelper(photo, messageObject, cacheFile, message, path);
            }
        });
    }

    public /* synthetic */ void lambda$null$1$SendMessagesHelper(TLRPC.TL_photo photo, MessageObject messageObject, File cacheFile, DelayedMessage message, String path) {
        if (photo != null) {
            messageObject.messageOwner.media.photo = photo;
            messageObject.messageOwner.attachPath = cacheFile.toString();
            ArrayList<TLRPC.Message> messages = new ArrayList<>();
            messages.add(messageObject.messageOwner);
            getMessagesStorage().putMessages(messages, false, true, false, 0, messageObject.scheduled);
            getNotificationCenter().postNotificationName(NotificationCenter.updateMessageMedia, messageObject.messageOwner);
            message.photoSize = photo.sizes.get(photo.sizes.size() - 1);
            message.locationParent = photo;
            message.httpLocation = null;
            if (message.type == 4) {
                message.performMediaUpload = true;
                performSendDelayedMessage(message, message.messageObjects.indexOf(messageObject));
                return;
            } else {
                performSendDelayedMessage(message);
                return;
            }
        }
        if (BuildVars.LOGS_ENABLED) {
            FileLog.e("can't load image " + path + " to file " + cacheFile.toString());
        }
        message.markAsError();
    }

    public /* synthetic */ void lambda$didReceivedNotification$4$SendMessagesHelper(final DelayedMessage message, final File cacheFile, final MessageObject messageObject) {
        final TLRPC.Document document = message.obj.getDocument();
        if (document.thumbs.isEmpty() || (document.thumbs.get(0).location instanceof TLRPC.TL_fileLocationUnavailable)) {
            try {
                Bitmap bitmap = ImageLoader.loadBitmap(cacheFile.getAbsolutePath(), null, 90.0f, 90.0f, true);
                if (bitmap != null) {
                    document.thumbs.clear();
                    document.thumbs.add(ImageLoader.scaleAndSaveImage(bitmap, 90.0f, 90.0f, 55, message.sendEncryptedRequest != null));
                    bitmap.recycle();
                }
            } catch (Exception e) {
                document.thumbs.clear();
                FileLog.e(e);
            }
        }
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SendMessagesHelper$R1UdqKOxmEpTigVUDSACWdLmuzk
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$3$SendMessagesHelper(message, cacheFile, document, messageObject);
            }
        });
    }

    public /* synthetic */ void lambda$null$3$SendMessagesHelper(DelayedMessage message, File cacheFile, TLRPC.Document document, MessageObject messageObject) {
        message.httpLocation = null;
        message.obj.messageOwner.attachPath = cacheFile.toString();
        if (!document.thumbs.isEmpty()) {
            message.photoSize = document.thumbs.get(0);
            message.locationParent = document;
        }
        ArrayList<TLRPC.Message> messages = new ArrayList<>();
        messages.add(messageObject.messageOwner);
        getMessagesStorage().putMessages(messages, false, true, false, 0, messageObject.scheduled);
        message.performMediaUpload = true;
        performSendDelayedMessage(message);
        getNotificationCenter().postNotificationName(NotificationCenter.updateMessageMedia, message.obj.messageOwner);
    }

    private void revertEditingMessageObject(MessageObject object) {
        object.cancelEditing = true;
        object.messageOwner.media = object.previousMedia;
        object.messageOwner.message = object.previousCaption;
        object.messageOwner.entities = object.previousCaptionEntities;
        object.messageOwner.attachPath = object.previousAttachPath;
        object.messageOwner.send_state = 0;
        object.previousMedia = null;
        object.previousCaption = null;
        object.previousCaptionEntities = null;
        object.previousAttachPath = null;
        object.videoEditedInfo = null;
        object.type = -1;
        object.setType();
        object.caption = null;
        object.generateCaption();
        ArrayList<TLRPC.Message> arr = new ArrayList<>();
        arr.add(object.messageOwner);
        getMessagesStorage().putMessages(arr, false, true, false, 0, object.scheduled);
        ArrayList<MessageObject> arrayList = new ArrayList<>();
        arrayList.add(object);
        getNotificationCenter().postNotificationName(NotificationCenter.replaceMessagesObjects, Long.valueOf(object.getDialogId()), arrayList);
    }

    public void cancelSendingMessage(MessageObject object) {
        ArrayList<MessageObject> arrayList = new ArrayList<>();
        arrayList.add(object);
        cancelSendingMessage(arrayList);
    }

    public void cancelSendingMessage(ArrayList<MessageObject> objects) {
        boolean scheduled;
        long scheduledDialogId;
        TLRPC.Message sendingMessage;
        Iterator<Map.Entry<String, ArrayList<DelayedMessage>>> it;
        boolean enc;
        int channelId;
        int b;
        MessageObject messageObject;
        ArrayList<String> keysToRemove = new ArrayList<>();
        ArrayList<DelayedMessage> checkReadyToSendGroups = new ArrayList<>();
        ArrayList<Integer> messageIds = new ArrayList<>();
        int c = 0;
        boolean enc2 = false;
        int channelId2 = 0;
        boolean scheduled2 = false;
        long scheduledDialogId2 = 0;
        while (c < objects.size()) {
            MessageObject object = objects.get(c);
            if (!object.scheduled) {
                scheduled = scheduled2;
                scheduledDialogId = scheduledDialogId2;
            } else {
                scheduled = true;
                scheduledDialogId = object.getDialogId();
            }
            messageIds.add(Integer.valueOf(object.getId()));
            channelId2 = object.messageOwner.to_id.channel_id;
            TLRPC.Message sendingMessage2 = removeFromSendingMessages(object.getId(), object.scheduled);
            if (sendingMessage2 != null) {
                getConnectionsManager().cancelRequest(sendingMessage2.reqId, true);
            }
            Iterator<Map.Entry<String, ArrayList<DelayedMessage>>> it2 = this.delayedMessages.entrySet().iterator();
            while (it2.hasNext()) {
                Map.Entry<String, ArrayList<DelayedMessage>> entry = it2.next();
                ArrayList<DelayedMessage> messages = entry.getValue();
                long scheduledDialogId3 = scheduledDialogId;
                int a = 0;
                while (true) {
                    if (a >= messages.size()) {
                        sendingMessage = sendingMessage2;
                        it = it2;
                        enc = enc2;
                        channelId = channelId2;
                        break;
                    }
                    DelayedMessage message = messages.get(a);
                    sendingMessage = sendingMessage2;
                    it = it2;
                    if (message.type == 4) {
                        MessageObject messageObject2 = null;
                        int index = 0;
                        while (true) {
                            MessageObject messageObject3 = messageObject2;
                            if (index >= message.messageObjects.size()) {
                                enc = enc2;
                                b = -1;
                                messageObject = messageObject3;
                                break;
                            }
                            MessageObject messageObject4 = message.messageObjects.get(index);
                            enc = enc2;
                            if (messageObject4.getId() == object.getId()) {
                                removeFromUploadingMessages(object.getId(), object.scheduled);
                                b = index;
                                messageObject = messageObject4;
                                break;
                            } else {
                                index++;
                                messageObject2 = messageObject4;
                                enc2 = enc;
                            }
                        }
                        if (b >= 0) {
                            message.messageObjects.remove(b);
                            message.messages.remove(b);
                            message.originalPaths.remove(b);
                            if (message.sendRequest != null) {
                                channelId = channelId2;
                                ((TLRPC.TL_messages_sendMultiMedia) message.sendRequest).multi_media.remove(b);
                            } else {
                                channelId = channelId2;
                                TLRPC.TL_messages_sendEncryptedMultiMedia request = (TLRPC.TL_messages_sendEncryptedMultiMedia) message.sendEncryptedRequest;
                                request.messages.remove(b);
                                request.files.remove(b);
                            }
                            MediaController.getInstance().cancelVideoConvert(object);
                            String keyToRemove = (String) message.extraHashMap.get(messageObject);
                            if (keyToRemove != null) {
                                keysToRemove.add(keyToRemove);
                            }
                            if (message.messageObjects.isEmpty()) {
                                message.sendDelayedRequests();
                            } else {
                                int i = message.finalGroupMessage;
                                int index2 = object.getId();
                                if (i == index2) {
                                    MessageObject prevMessage = message.messageObjects.get(message.messageObjects.size() - 1);
                                    message.finalGroupMessage = prevMessage.getId();
                                    prevMessage.messageOwner.params.put("final", "1");
                                    TLRPC.TL_messages_messages messagesRes = new TLRPC.TL_messages_messages();
                                    messagesRes.messages.add(prevMessage.messageOwner);
                                    getMessagesStorage().putMessages((TLRPC.messages_Messages) messagesRes, message.peer, -2, 0, false, scheduled);
                                }
                                if (!checkReadyToSendGroups.contains(message)) {
                                    checkReadyToSendGroups.add(message);
                                }
                            }
                        } else {
                            channelId = channelId2;
                        }
                    } else {
                        enc = enc2;
                        channelId = channelId2;
                        if (message.obj.getId() == object.getId()) {
                            removeFromUploadingMessages(object.getId(), object.scheduled);
                            messages.remove(a);
                            message.sendDelayedRequests();
                            MediaController.getInstance().cancelVideoConvert(message.obj);
                            if (messages.size() == 0) {
                                keysToRemove.add(entry.getKey());
                                if (message.sendEncryptedRequest != null) {
                                    enc2 = true;
                                }
                            }
                        } else {
                            a++;
                            sendingMessage2 = sendingMessage;
                            it2 = it;
                            enc2 = enc;
                            channelId2 = channelId;
                        }
                    }
                }
                enc2 = enc;
                scheduledDialogId = scheduledDialogId3;
                sendingMessage2 = sendingMessage;
                it2 = it;
                channelId2 = channelId;
            }
            c++;
            scheduled2 = scheduled;
            scheduledDialogId2 = scheduledDialogId;
        }
        for (int a2 = 0; a2 < keysToRemove.size(); a2++) {
            String key = keysToRemove.get(a2);
            if (key.startsWith("http")) {
                ImageLoader.getInstance().cancelLoadHttpFile(key);
            } else {
                getFileLoader().cancelUploadFile(key, enc2);
            }
            stopVideoService(key);
            this.delayedMessages.remove(key);
        }
        int N = checkReadyToSendGroups.size();
        for (int a3 = 0; a3 < N; a3++) {
            sendReadyToSendGroup(checkReadyToSendGroups.get(a3), false, true);
        }
        int a4 = objects.size();
        if (a4 == 1 && objects.get(0).isEditing() && objects.get(0).previousMedia != null) {
            revertEditingMessageObject(objects.get(0));
        } else {
            getMessagesController().deleteMessages(messageIds, null, null, scheduledDialogId2, channelId2, false, scheduled2);
        }
    }

    public boolean retrySendMessage(MessageObject messageObject, boolean unsent) {
        if (messageObject.getId() >= 0) {
            if (messageObject.isEditing()) {
                editMessageMedia(messageObject, null, null, null, null, null, true, messageObject);
            }
            return false;
        }
        if (messageObject.messageOwner.action instanceof TLRPC.TL_messageEncryptedAction) {
            int enc_id = (int) (messageObject.getDialogId() >> 32);
            TLRPC.EncryptedChat encryptedChat = getMessagesController().getEncryptedChat(Integer.valueOf(enc_id));
            if (encryptedChat == null) {
                getMessagesStorage().markMessageAsSendError(messageObject.messageOwner, messageObject.scheduled);
                messageObject.messageOwner.send_state = 2;
                getNotificationCenter().postNotificationName(NotificationCenter.messageSendError, Integer.valueOf(messageObject.getId()));
                processSentMessage(messageObject.getId());
                return false;
            }
            if (messageObject.messageOwner.random_id == 0) {
                messageObject.messageOwner.random_id = getNextRandomId();
            }
            if (messageObject.messageOwner.action.encryptedAction instanceof TLRPC.TL_decryptedMessageActionSetMessageTTL) {
                getSecretChatHelper().sendTTLMessage(encryptedChat, messageObject.messageOwner);
            } else if (messageObject.messageOwner.action.encryptedAction instanceof TLRPC.TL_decryptedMessageActionDeleteMessages) {
                getSecretChatHelper().sendMessagesDeleteMessage(encryptedChat, null, messageObject.messageOwner);
            } else if (messageObject.messageOwner.action.encryptedAction instanceof TLRPC.TL_decryptedMessageActionFlushHistory) {
                getSecretChatHelper().sendClearHistoryMessage(encryptedChat, messageObject.messageOwner);
            } else if (messageObject.messageOwner.action.encryptedAction instanceof TLRPC.TL_decryptedMessageActionNotifyLayer) {
                getSecretChatHelper().sendNotifyLayerMessage(encryptedChat, messageObject.messageOwner);
            } else if (messageObject.messageOwner.action.encryptedAction instanceof TLRPC.TL_decryptedMessageActionReadMessages) {
                getSecretChatHelper().sendMessagesReadMessage(encryptedChat, null, messageObject.messageOwner);
            } else if (messageObject.messageOwner.action.encryptedAction instanceof TLRPC.TL_decryptedMessageActionScreenshotMessages) {
                getSecretChatHelper().sendScreenshotMessage(encryptedChat, null, messageObject.messageOwner);
            } else if (!(messageObject.messageOwner.action.encryptedAction instanceof TLRPC.TL_decryptedMessageActionTyping) && !(messageObject.messageOwner.action.encryptedAction instanceof TLRPC.TL_decryptedMessageActionResend)) {
                if (messageObject.messageOwner.action.encryptedAction instanceof TLRPC.TL_decryptedMessageActionCommitKey) {
                    getSecretChatHelper().sendCommitKeyMessage(encryptedChat, messageObject.messageOwner);
                } else if (messageObject.messageOwner.action.encryptedAction instanceof TLRPC.TL_decryptedMessageActionAbortKey) {
                    getSecretChatHelper().sendAbortKeyMessage(encryptedChat, messageObject.messageOwner, 0L);
                } else if (messageObject.messageOwner.action.encryptedAction instanceof TLRPC.TL_decryptedMessageActionRequestKey) {
                    getSecretChatHelper().sendRequestKeyMessage(encryptedChat, messageObject.messageOwner);
                } else if (messageObject.messageOwner.action.encryptedAction instanceof TLRPC.TL_decryptedMessageActionAcceptKey) {
                    getSecretChatHelper().sendAcceptKeyMessage(encryptedChat, messageObject.messageOwner);
                } else if (messageObject.messageOwner.action.encryptedAction instanceof TLRPC.TL_decryptedMessageActionNoop) {
                    getSecretChatHelper().sendNoopMessage(encryptedChat, messageObject.messageOwner);
                }
            }
            return true;
        }
        if (messageObject.messageOwner.action instanceof TLRPC.TL_messageActionScreenshotTaken) {
            TLRPC.User user = getMessagesController().getUser(Integer.valueOf((int) messageObject.getDialogId()));
            sendScreenshotMessage(user, messageObject.messageOwner.reply_to_msg_id, messageObject.messageOwner);
        }
        if (unsent) {
            this.unsentMessages.put(messageObject.getId(), messageObject);
        }
        sendMessage(messageObject);
        return true;
    }

    protected void processSentMessage(int id) {
        int prevSize = this.unsentMessages.size();
        this.unsentMessages.remove(id);
        if (prevSize != 0 && this.unsentMessages.size() == 0) {
            checkUnsentMessages();
        }
    }

    public void processForwardFromMyName(MessageObject messageObject, long did) {
        TLRPC.WebPage webPage;
        ArrayList<TLRPC.MessageEntity> entities;
        HashMap<String, String> params;
        if (messageObject == null) {
            return;
        }
        if (messageObject.messageOwner.media != null && !(messageObject.messageOwner.media instanceof TLRPC.TL_messageMediaEmpty) && !(messageObject.messageOwner.media instanceof TLRPC.TL_messageMediaWebPage) && !(messageObject.messageOwner.media instanceof TLRPC.TL_messageMediaGame) && !(messageObject.messageOwner.media instanceof TLRPC.TL_messageMediaInvoice)) {
            if (((int) did) == 0 && messageObject.messageOwner.to_id != null && ((messageObject.messageOwner.media.photo instanceof TLRPC.TL_photo) || (messageObject.messageOwner.media.document instanceof TLRPC.TL_document))) {
                HashMap<String, String> params2 = new HashMap<>();
                params2.put("parentObject", "sent_" + messageObject.messageOwner.to_id.channel_id + "_" + messageObject.getId());
                params = params2;
            } else {
                params = null;
            }
            if (messageObject.messageOwner.media.photo instanceof TLRPC.TL_photo) {
                sendMessage((TLRPC.TL_photo) messageObject.messageOwner.media.photo, null, did, messageObject.replyMessageObject, messageObject.messageOwner.message, messageObject.messageOwner.entities, null, params, true, 0, messageObject.messageOwner.media.ttl_seconds, messageObject);
                return;
            }
            if (messageObject.messageOwner.media.document instanceof TLRPC.TL_document) {
                sendMessage((TLRPC.TL_document) messageObject.messageOwner.media.document, null, messageObject.messageOwner.attachPath, did, messageObject.replyMessageObject, messageObject.messageOwner.message, messageObject.messageOwner.entities, null, params, true, 0, messageObject.messageOwner.media.ttl_seconds, messageObject);
                return;
            }
            if ((messageObject.messageOwner.media instanceof TLRPC.TL_messageMediaVenue) || (messageObject.messageOwner.media instanceof TLRPC.TL_messageMediaGeo)) {
                sendMessage(messageObject.messageOwner.media, did, messageObject.replyMessageObject, (TLRPC.ReplyMarkup) null, (HashMap<String, String>) null, true, 0);
                return;
            }
            if (messageObject.messageOwner.media.phone_number == null) {
                if (((int) did) != 0) {
                    ArrayList<MessageObject> arrayList = new ArrayList<>();
                    arrayList.add(messageObject);
                    sendMessage(arrayList, did, true, 0);
                    return;
                }
                return;
            }
            TLRPC.User user = new TLRPC.TL_userContact_old2();
            user.phone = messageObject.messageOwner.media.phone_number;
            user.first_name = messageObject.messageOwner.media.first_name;
            user.last_name = messageObject.messageOwner.media.last_name;
            user.id = messageObject.messageOwner.media.user_id;
            sendMessage(user, did, messageObject.replyMessageObject, (TLRPC.ReplyMarkup) null, (HashMap<String, String>) null, true, 0);
            return;
        }
        if (messageObject.messageOwner.message != null) {
            if (!(messageObject.messageOwner.media instanceof TLRPC.TL_messageMediaWebPage)) {
                webPage = null;
            } else {
                TLRPC.WebPage webPage2 = messageObject.messageOwner.media.webpage;
                webPage = webPage2;
            }
            if (messageObject.messageOwner.entities != null && !messageObject.messageOwner.entities.isEmpty()) {
                ArrayList<TLRPC.MessageEntity> entities2 = new ArrayList<>();
                for (int a = 0; a < messageObject.messageOwner.entities.size(); a++) {
                    TLRPC.MessageEntity entity = messageObject.messageOwner.entities.get(a);
                    if ((entity instanceof TLRPC.TL_messageEntityBold) || (entity instanceof TLRPC.TL_messageEntityItalic) || (entity instanceof TLRPC.TL_messageEntityPre) || (entity instanceof TLRPC.TL_messageEntityCode) || (entity instanceof TLRPC.TL_messageEntityTextUrl)) {
                        entities2.add(entity);
                    }
                }
                entities = entities2;
            } else {
                entities = null;
            }
            sendMessage(messageObject.messageOwner.message, did, messageObject.replyMessageObject, webPage, true, entities, null, null, true, 0);
            return;
        }
        if (((int) did) != 0) {
            ArrayList<MessageObject> arrayList2 = new ArrayList<>();
            arrayList2.add(messageObject);
            sendMessage(arrayList2, did, true, 0);
        }
    }

    public void sendScreenshotMessage(TLRPC.User user, int messageId, TLRPC.Message resendMessage) {
        TLRPC.Message message;
        if (user != null && messageId != 0) {
            if (user.id == getUserConfig().getClientUserId()) {
                return;
            }
            TLRPC.TL_messages_sendScreenshotNotification req = new TLRPC.TL_messages_sendScreenshotNotification();
            req.peer = new TLRPC.TL_inputPeerUser();
            req.peer.access_hash = user.access_hash;
            req.peer.user_id = user.id;
            if (resendMessage != null) {
                req.reply_to_msg_id = messageId;
                req.random_id = resendMessage.random_id;
                message = resendMessage;
            } else {
                TLRPC.Message message2 = new TLRPC.TL_messageService();
                message2.random_id = getNextRandomId();
                message2.dialog_id = user.id;
                message2.unread = true;
                message2.out = true;
                int newMessageId = getUserConfig().getNewMessageId();
                message2.id = newMessageId;
                message2.local_id = newMessageId;
                message2.from_id = getUserConfig().getClientUserId();
                message2.flags |= 256;
                message2.flags |= 8;
                message2.reply_to_msg_id = messageId;
                message2.to_id = new TLRPC.TL_peerUser();
                message2.to_id.user_id = user.id;
                message2.date = getConnectionsManager().getCurrentTime();
                message2.action = new TLRPC.TL_messageActionScreenshotTaken();
                getUserConfig().saveConfig(false);
                message = message2;
            }
            req.random_id = message.random_id;
            MessageObject newMsgObj = new MessageObject(this.currentAccount, message, false);
            newMsgObj.messageOwner.send_state = 1;
            ArrayList<MessageObject> objArr = new ArrayList<>();
            objArr.add(newMsgObj);
            getMessagesController().updateInterfaceWithMessages(message.dialog_id, objArr, false);
            getNotificationCenter().postNotificationName(NotificationCenter.dialogsNeedReload, new Object[0]);
            ArrayList<TLRPC.Message> arr = new ArrayList<>();
            arr.add(message);
            getMessagesStorage().putMessages(arr, false, true, false, 0, false);
            performSendMessageRequest(req, newMsgObj, null, null, null, false);
        }
    }

    public void sendSticker(TLRPC.Document document, long peer, MessageObject replyingMessageObject, Object parentObject, boolean notify, int scheduleDate) {
        TLRPC.Document document2;
        if (document == null) {
            return;
        }
        if (((int) peer) != 0) {
            document2 = document;
        } else {
            int high_id = (int) (peer >> 32);
            TLRPC.EncryptedChat encryptedChat = getMessagesController().getEncryptedChat(Integer.valueOf(high_id));
            if (encryptedChat == null) {
                return;
            }
            TLRPC.TL_document_layer82 newDocument = new TLRPC.TL_document_layer82();
            newDocument.id = document.id;
            newDocument.access_hash = document.access_hash;
            newDocument.date = document.date;
            newDocument.mime_type = document.mime_type;
            newDocument.file_reference = document.file_reference;
            if (newDocument.file_reference == null) {
                newDocument.file_reference = new byte[0];
            }
            newDocument.size = document.size;
            newDocument.dc_id = document.dc_id;
            newDocument.attributes = new ArrayList<>(document.attributes);
            if (newDocument.mime_type == null) {
                newDocument.mime_type = "";
            }
            TLRPC.PhotoSize thumb = FileLoader.getClosestPhotoSizeWithSize(document.thumbs, 90);
            if (thumb instanceof TLRPC.TL_photoSize) {
                File file = FileLoader.getPathToAttach(thumb, true);
                if (file.exists()) {
                    try {
                        byte[] arr = new byte[(int) file.length()];
                        RandomAccessFile reader = new RandomAccessFile(file, "r");
                        reader.readFully(arr);
                        TLRPC.PhotoSize newThumb = new TLRPC.TL_photoCachedSize();
                        TLRPC.TL_fileLocation_layer82 fileLocation = new TLRPC.TL_fileLocation_layer82();
                        fileLocation.dc_id = thumb.location.dc_id;
                        fileLocation.volume_id = thumb.location.volume_id;
                        fileLocation.local_id = thumb.location.local_id;
                        fileLocation.secret = thumb.location.secret;
                        newThumb.location = fileLocation;
                        newThumb.size = thumb.size;
                        newThumb.w = thumb.w;
                        newThumb.h = thumb.h;
                        newThumb.type = thumb.type;
                        newThumb.bytes = arr;
                        newDocument.thumbs.add(newThumb);
                        newDocument.flags = 1 | newDocument.flags;
                    } catch (Exception e) {
                        FileLog.e(e);
                    }
                }
            }
            if (newDocument.thumbs.isEmpty()) {
                TLRPC.PhotoSize thumb2 = new TLRPC.TL_photoSizeEmpty();
                thumb2.type = "s";
                newDocument.thumbs.add(thumb2);
            }
            document2 = newDocument;
        }
        if (document2 instanceof TLRPC.TL_document) {
            sendMessage((TLRPC.TL_document) document2, null, null, peer, replyingMessageObject, null, null, null, null, notify, scheduleDate, 0, parentObject);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:249:0x0726  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public int sendMessage(java.util.ArrayList<im.uwrkaxlmjj.messenger.MessageObject> r50, final long r51, boolean r53, final int r54) {
        /*
            Method dump skipped, instruction units count: 2271
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.SendMessagesHelper.sendMessage(java.util.ArrayList, long, boolean, int):int");
    }

    public /* synthetic */ void lambda$sendMessage$9$SendMessagesHelper(final long peer, final int scheduleDate, boolean isMegagroupFinal, boolean toMyself, LongSparseArray messagesByRandomIdsFinal, ArrayList newMsgObjArr, ArrayList newMsgArr, final TLRPC.Peer to_id, final TLRPC.TL_messages_forwardMessages req, TLObject response, final TLRPC.TL_error error) throws Exception {
        final SendMessagesHelper sendMessagesHelper;
        Integer value;
        TLRPC.Message message;
        SparseLongArray newMessagesByIds;
        TLRPC.Updates updates;
        int i;
        final TLRPC.Message newMsgObj1;
        int index;
        int i2 = scheduleDate;
        ArrayList arrayList = newMsgObjArr;
        ArrayList arrayList2 = newMsgArr;
        if (error == null) {
            SparseLongArray newMessagesByIds2 = new SparseLongArray();
            TLRPC.Updates updates2 = (TLRPC.Updates) response;
            int a1 = 0;
            while (a1 < updates2.updates.size()) {
                TLRPC.Update update = updates2.updates.get(a1);
                if (update instanceof TLRPC.TL_updateMessageID) {
                    TLRPC.TL_updateMessageID updateMessageID = (TLRPC.TL_updateMessageID) update;
                    newMessagesByIds2.put(updateMessageID.id, updateMessageID.random_id);
                    updates2.updates.remove(a1);
                    a1--;
                }
                a1++;
            }
            Integer value2 = getMessagesController().dialogs_read_outbox_max.get(Long.valueOf(peer));
            if (i2 != 0) {
                value = 0;
            } else if (value2 == null) {
                Integer value3 = Integer.valueOf(getMessagesStorage().getDialogReadMax(true, peer));
                getMessagesController().dialogs_read_outbox_max.put(Long.valueOf(peer), value3);
                value = value3;
            } else {
                value = value2;
            }
            int a12 = 0;
            int sentCount = 0;
            while (a12 < updates2.updates.size()) {
                TLRPC.Update update2 = updates2.updates.get(a12);
                if ((update2 instanceof TLRPC.TL_updateNewMessage) || (update2 instanceof TLRPC.TL_updateNewChannelMessage) || (update2 instanceof TLRPC.TL_updateNewScheduledMessage)) {
                    updates2.updates.remove(a12);
                    int a13 = a12 - 1;
                    if (update2 instanceof TLRPC.TL_updateNewMessage) {
                        TLRPC.TL_updateNewMessage updateNewMessage = (TLRPC.TL_updateNewMessage) update2;
                        TLRPC.Message message2 = updateNewMessage.message;
                        getMessagesController().processNewDifferenceParams(-1, updateNewMessage.pts, -1, updateNewMessage.pts_count);
                        message = message2;
                    } else if (update2 instanceof TLRPC.TL_updateNewScheduledMessage) {
                        message = ((TLRPC.TL_updateNewScheduledMessage) update2).message;
                    } else {
                        TLRPC.TL_updateNewChannelMessage updateNewChannelMessage = (TLRPC.TL_updateNewChannelMessage) update2;
                        TLRPC.Message message3 = updateNewChannelMessage.message;
                        getMessagesController().processNewChannelDifferenceParams(updateNewChannelMessage.pts, updateNewChannelMessage.pts_count, message3.to_id.channel_id);
                        if (isMegagroupFinal) {
                            message3.flags |= Integer.MIN_VALUE;
                        }
                        message = message3;
                    }
                    ImageLoader.saveMessageThumbs(message);
                    if (i2 == 0) {
                        message.unread = value.intValue() < message.id;
                    }
                    if (toMyself) {
                        message.out = true;
                        message.unread = false;
                        message.media_unread = false;
                    }
                    long random_id = newMessagesByIds2.get(message.id);
                    if (random_id == 0 || (newMsgObj1 = (TLRPC.Message) messagesByRandomIdsFinal.get(random_id)) == null || (index = arrayList.indexOf(newMsgObj1)) == -1) {
                        int sentCount2 = sentCount;
                        newMessagesByIds = newMessagesByIds2;
                        updates = updates2;
                        i = 1;
                        sentCount = sentCount2;
                        a12 = a13;
                    } else {
                        MessageObject msgObj1 = (MessageObject) arrayList2.get(index);
                        arrayList.remove(index);
                        arrayList2.remove(index);
                        final int oldId = newMsgObj1.id;
                        final ArrayList<TLRPC.Message> sentMessages = new ArrayList<>();
                        sentMessages.add(message);
                        int sentCount3 = message.id;
                        updateMediaPaths(msgObj1, message, sentCount3, null, true);
                        final int existFlags = msgObj1.getMediaExistanceFlags();
                        newMsgObj1.id = message.id;
                        newMessagesByIds = newMessagesByIds2;
                        updates = updates2;
                        i = 1;
                        final TLRPC.Message message4 = message;
                        getMessagesStorage().getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SendMessagesHelper$TRVa9b5V1Gy5r8e3IrZ9seN6jac
                            @Override // java.lang.Runnable
                            public final void run() {
                                this.f$0.lambda$null$6$SendMessagesHelper(newMsgObj1, oldId, to_id, scheduleDate, sentMessages, peer, message4, existFlags);
                            }
                        });
                        a12 = a13;
                        sentCount++;
                    }
                } else {
                    newMessagesByIds = newMessagesByIds2;
                    updates = updates2;
                    i = 1;
                }
                a12 += i;
                arrayList = newMsgObjArr;
                arrayList2 = newMsgArr;
                updates2 = updates;
                newMessagesByIds2 = newMessagesByIds;
                i2 = scheduleDate;
            }
            int sentCount4 = sentCount;
            TLRPC.Updates updates3 = updates2;
            if (!updates3.updates.isEmpty()) {
                getMessagesController().processUpdates(updates3, false);
            }
            getStatsController().incrementSentItemsCount(ApplicationLoader.getCurrentNetworkType(), 1, sentCount4);
            sendMessagesHelper = this;
        } else {
            sendMessagesHelper = this;
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SendMessagesHelper$B8o-e5aV7LOY_R1z8JIgQ4Vg28c
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$7$SendMessagesHelper(error, req);
                }
            });
        }
        for (int a14 = 0; a14 < newMsgObjArr.size(); a14++) {
            final TLRPC.Message newMsgObj12 = (TLRPC.Message) newMsgObjArr.get(a14);
            getMessagesStorage().markMessageAsSendError(newMsgObj12, scheduleDate != 0);
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SendMessagesHelper$gowd_ovBv7KfYlnFAjBhEIJSWFs
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$8$SendMessagesHelper(newMsgObj12, scheduleDate);
                }
            });
        }
    }

    public /* synthetic */ void lambda$null$6$SendMessagesHelper(final TLRPC.Message newMsgObj1, final int oldId, TLRPC.Peer to_id, final int scheduleDate, ArrayList sentMessages, final long peer, final TLRPC.Message message, final int existFlags) {
        getMessagesStorage().updateMessageStateAndId(newMsgObj1.random_id, Integer.valueOf(oldId), newMsgObj1.id, 0, false, to_id.channel_id, scheduleDate != 0 ? 1 : 0);
        getMessagesStorage().putMessages((ArrayList<TLRPC.Message>) sentMessages, true, true, false, 0, scheduleDate != 0);
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SendMessagesHelper$y9bHFwSGeOuXv8CBBLls6nTramU
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$5$SendMessagesHelper(newMsgObj1, peer, oldId, message, existFlags, scheduleDate);
            }
        });
    }

    public /* synthetic */ void lambda$null$5$SendMessagesHelper(TLRPC.Message newMsgObj1, long peer, int oldId, TLRPC.Message message, int existFlags, int scheduleDate) {
        newMsgObj1.send_state = 0;
        getMediaDataController().increasePeerRaiting(peer);
        NotificationCenter notificationCenter = getNotificationCenter();
        int i = NotificationCenter.messageReceivedByServer;
        Object[] objArr = new Object[7];
        objArr[0] = Integer.valueOf(oldId);
        objArr[1] = Integer.valueOf(message.id);
        objArr[2] = message;
        objArr[3] = Long.valueOf(peer);
        objArr[4] = 0L;
        objArr[5] = Integer.valueOf(existFlags);
        objArr[6] = Boolean.valueOf(scheduleDate != 0);
        notificationCenter.postNotificationName(i, objArr);
        processSentMessage(oldId);
        removeFromSendingMessages(oldId, scheduleDate != 0);
    }

    public /* synthetic */ void lambda$null$7$SendMessagesHelper(TLRPC.TL_error error, TLRPC.TL_messages_forwardMessages req) {
        AlertsCreator.processError(this.currentAccount, error, null, req, new Object[0]);
    }

    public /* synthetic */ void lambda$null$8$SendMessagesHelper(TLRPC.Message newMsgObj1, int scheduleDate) {
        newMsgObj1.send_state = 2;
        getNotificationCenter().postNotificationName(NotificationCenter.messageSendError, Integer.valueOf(newMsgObj1.id));
        processSentMessage(newMsgObj1.id);
        removeFromSendingMessages(newMsgObj1.id, scheduleDate != 0);
    }

    private void writePreviousMessageData(TLRPC.Message message, SerializedData data) {
        message.media.serializeToStream(data);
        data.writeString(message.message != null ? message.message : "");
        data.writeString(message.attachPath != null ? message.attachPath : "");
        int count = message.entities.size();
        data.writeInt32(count);
        for (int a = 0; a < count; a++) {
            message.entities.get(a).serializeToStream(data);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:108:0x0248  */
    /* JADX WARN: Removed duplicated region for block: B:111:0x0251 A[Catch: Exception -> 0x025f, TryCatch #7 {Exception -> 0x025f, blocks: (B:103:0x021b, B:111:0x0251, B:113:0x0257), top: B:311:0x021b }] */
    /* JADX WARN: Removed duplicated region for block: B:117:0x0268  */
    /* JADX WARN: Removed duplicated region for block: B:229:0x0505 A[Catch: Exception -> 0x04c7, TRY_ENTER, TRY_LEAVE, TryCatch #24 {Exception -> 0x04c7, blocks: (B:229:0x0505, B:232:0x0517, B:234:0x0529, B:240:0x0557, B:235:0x0535, B:237:0x0548, B:239:0x054e, B:242:0x055e, B:216:0x049b, B:218:0x04af, B:219:0x04bc, B:211:0x0479, B:213:0x048f), top: B:342:0x0479 }] */
    /* JADX WARN: Removed duplicated region for block: B:232:0x0517 A[Catch: Exception -> 0x04c7, TRY_ENTER, TryCatch #24 {Exception -> 0x04c7, blocks: (B:229:0x0505, B:232:0x0517, B:234:0x0529, B:240:0x0557, B:235:0x0535, B:237:0x0548, B:239:0x054e, B:242:0x055e, B:216:0x049b, B:218:0x04af, B:219:0x04bc, B:211:0x0479, B:213:0x048f), top: B:342:0x0479 }] */
    /* JADX WARN: Removed duplicated region for block: B:242:0x055e A[Catch: Exception -> 0x04c7, TRY_LEAVE, TryCatch #24 {Exception -> 0x04c7, blocks: (B:229:0x0505, B:232:0x0517, B:234:0x0529, B:240:0x0557, B:235:0x0535, B:237:0x0548, B:239:0x054e, B:242:0x055e, B:216:0x049b, B:218:0x04af, B:219:0x04bc, B:211:0x0479, B:213:0x048f), top: B:342:0x0479 }] */
    /* JADX WARN: Removed duplicated region for block: B:245:0x0565  */
    /* JADX WARN: Removed duplicated region for block: B:253:0x0599  */
    /* JADX WARN: Removed duplicated region for block: B:338:0x01a8 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:340:0x0174 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:84:0x01a1 A[ADDED_TO_REGION] */
    /* JADX WARN: Type inference failed for: r18v1 */
    /* JADX WARN: Type inference failed for: r18v11 */
    /* JADX WARN: Type inference failed for: r18v12 */
    /* JADX WARN: Type inference failed for: r18v4 */
    /* JADX WARN: Type inference failed for: r18v5 */
    /* JADX WARN: Type inference failed for: r18v7 */
    /* JADX WARN: Type inference failed for: r18v8 */
    /* JADX WARN: Type inference failed for: r18v9 */
    /* JADX WARN: Type inference failed for: r1v16 */
    /* JADX WARN: Type inference failed for: r1v17 */
    /* JADX WARN: Type inference failed for: r1v35 */
    /* JADX WARN: Type inference failed for: r1v36 */
    /* JADX WARN: Type inference failed for: r1v37 */
    /* JADX WARN: Type inference failed for: r1v38 */
    /* JADX WARN: Type inference failed for: r1v41 */
    /* JADX WARN: Type inference failed for: r1v42 */
    /* JADX WARN: Type inference failed for: r1v43 */
    /* JADX WARN: Type inference failed for: r1v45 */
    /* JADX WARN: Type inference failed for: r1v71 */
    /* JADX WARN: Type inference failed for: r1v72 */
    /* JADX WARN: Type inference failed for: r1v73 */
    /* JADX WARN: Type inference failed for: r1v74 */
    /* JADX WARN: Type inference failed for: r1v75 */
    /* JADX WARN: Type inference failed for: r1v76 */
    /* JADX WARN: Type inference failed for: r1v77 */
    /* JADX WARN: Type inference failed for: r20v0 */
    /* JADX WARN: Type inference failed for: r20v1 */
    /* JADX WARN: Type inference failed for: r20v10 */
    /* JADX WARN: Type inference failed for: r20v12 */
    /* JADX WARN: Type inference failed for: r20v15 */
    /* JADX WARN: Type inference failed for: r20v19 */
    /* JADX WARN: Type inference failed for: r20v2 */
    /* JADX WARN: Type inference failed for: r20v21 */
    /* JADX WARN: Type inference failed for: r20v24 */
    /* JADX WARN: Type inference failed for: r20v25 */
    /* JADX WARN: Type inference failed for: r20v26 */
    /* JADX WARN: Type inference failed for: r20v27 */
    /* JADX WARN: Type inference failed for: r20v29 */
    /* JADX WARN: Type inference failed for: r20v3 */
    /* JADX WARN: Type inference failed for: r20v31 */
    /* JADX WARN: Type inference failed for: r20v36 */
    /* JADX WARN: Type inference failed for: r20v37 */
    /* JADX WARN: Type inference failed for: r20v38 */
    /* JADX WARN: Type inference failed for: r20v42 */
    /* JADX WARN: Type inference failed for: r20v43 */
    /* JADX WARN: Type inference failed for: r20v44 */
    /* JADX WARN: Type inference failed for: r20v45 */
    /* JADX WARN: Type inference failed for: r20v46 */
    /* JADX WARN: Type inference failed for: r20v47 */
    /* JADX WARN: Type inference failed for: r20v5 */
    /* JADX WARN: Type inference failed for: r20v7 */
    /* JADX WARN: Type inference failed for: r20v8 */
    /* JADX WARN: Type inference failed for: r22v10 */
    /* JADX WARN: Type inference failed for: r22v11 */
    /* JADX WARN: Type inference failed for: r22v2 */
    /* JADX WARN: Type inference failed for: r22v3 */
    /* JADX WARN: Type inference failed for: r22v4 */
    /* JADX WARN: Type inference failed for: r22v6 */
    /* JADX WARN: Type inference failed for: r22v7 */
    /* JADX WARN: Type inference failed for: r22v8 */
    /* JADX WARN: Type inference failed for: r30v0, types: [im.uwrkaxlmjj.messenger.SendMessagesHelper] */
    /* JADX WARN: Type inference failed for: r5v19 */
    /* JADX WARN: Type inference failed for: r5v23 */
    /* JADX WARN: Type inference failed for: r6v1 */
    /* JADX WARN: Type inference failed for: r6v15 */
    /* JADX WARN: Type inference failed for: r7v0 */
    /* JADX WARN: Type inference failed for: r7v1 */
    /* JADX WARN: Type inference failed for: r7v10 */
    /* JADX WARN: Type inference failed for: r7v11 */
    /* JADX WARN: Type inference failed for: r7v12 */
    /* JADX WARN: Type inference failed for: r7v17 */
    /* JADX WARN: Type inference failed for: r7v20 */
    /* JADX WARN: Type inference failed for: r7v21 */
    /* JADX WARN: Type inference failed for: r7v27 */
    /* JADX WARN: Type inference failed for: r7v30 */
    /* JADX WARN: Type inference failed for: r7v33 */
    /* JADX WARN: Type inference failed for: r7v34 */
    /* JADX WARN: Type inference failed for: r7v35 */
    /* JADX WARN: Type inference failed for: r7v4 */
    /* JADX WARN: Type inference failed for: r7v40 */
    /* JADX WARN: Type inference failed for: r7v41 */
    /* JADX WARN: Type inference failed for: r7v42 */
    /* JADX WARN: Type inference failed for: r7v43 */
    /* JADX WARN: Type inference failed for: r7v44 */
    /* JADX WARN: Type inference failed for: r7v45 */
    /* JADX WARN: Type inference failed for: r7v46 */
    /* JADX WARN: Type inference failed for: r7v47 */
    /* JADX WARN: Type inference failed for: r7v5 */
    /* JADX WARN: Type inference failed for: r7v6 */
    /* JADX WARN: Type inference failed for: r7v7 */
    /* JADX WARN: Type inference failed for: r7v8 */
    /* JADX WARN: Type inference failed for: r7v9 */
    /* JADX WARN: Type inference failed for: r8v0 */
    /* JADX WARN: Type inference failed for: r8v10 */
    /* JADX WARN: Type inference failed for: r8v65 */
    /* JADX WARN: Type inference failed for: r8v9 */
    /* JADX WARN: Type inference failed for: r9v10 */
    /* JADX WARN: Type inference failed for: r9v16 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private void editMessageMedia(im.uwrkaxlmjj.messenger.MessageObject r31, im.uwrkaxlmjj.tgnet.TLRPC.TL_photo r32, im.uwrkaxlmjj.messenger.VideoEditedInfo r33, im.uwrkaxlmjj.tgnet.TLRPC.TL_document r34, java.lang.String r35, java.util.HashMap<java.lang.String, java.lang.String> r36, boolean r37, java.lang.Object r38) {
        /*
            Method dump skipped, instruction units count: 1697
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.SendMessagesHelper.editMessageMedia(im.uwrkaxlmjj.messenger.MessageObject, im.uwrkaxlmjj.tgnet.TLRPC$TL_photo, im.uwrkaxlmjj.messenger.VideoEditedInfo, im.uwrkaxlmjj.tgnet.TLRPC$TL_document, java.lang.String, java.util.HashMap, boolean, java.lang.Object):void");
    }

    public int editMessage(MessageObject messageObject, String message, boolean searchLinks, final BaseFragment fragment, ArrayList<TLRPC.MessageEntity> entities, int scheduleDate, final Runnable callback) {
        if (fragment == null || fragment.getParentActivity() == null) {
            return 0;
        }
        final TLRPC.TL_messages_editMessage req = new TLRPC.TL_messages_editMessage();
        req.peer = getMessagesController().getInputPeer((int) messageObject.getDialogId());
        if (message != null) {
            req.message = message;
            req.flags |= 2048;
            req.no_webpage = !searchLinks;
        }
        req.id = messageObject.getId();
        if (entities != null) {
            req.entities = entities;
            req.flags |= 8;
        }
        if (scheduleDate != 0) {
            req.schedule_date = scheduleDate;
            req.flags |= 32768;
        }
        return getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SendMessagesHelper$bEsf3NZNdFTqS6iMEPrDybnNOHU
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) throws Exception {
                this.f$0.lambda$editMessage$11$SendMessagesHelper(fragment, req, callback, tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$editMessage$11$SendMessagesHelper(final BaseFragment fragment, final TLRPC.TL_messages_editMessage req, Runnable callback, TLObject response, final TLRPC.TL_error error) throws Exception {
        if (error == null) {
            getMessagesController().processUpdates((TLRPC.Updates) response, false);
        } else {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SendMessagesHelper$ylLrvll1KNLmaR70Bovp7tPzgXk
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$10$SendMessagesHelper(error, fragment, req);
                }
            });
        }
        if (callback != null) {
            AndroidUtilities.runOnUIThread(callback);
        }
    }

    public /* synthetic */ void lambda$null$10$SendMessagesHelper(TLRPC.TL_error error, BaseFragment fragment, TLRPC.TL_messages_editMessage req) {
        AlertsCreator.processError(this.currentAccount, error, fragment, req, new Object[0]);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void sendLocation(Location location) {
        TLRPC.TL_messageMediaGeo mediaGeo = new TLRPC.TL_messageMediaGeo();
        mediaGeo.geo = new TLRPC.TL_geoPoint();
        mediaGeo.geo.lat = AndroidUtilities.fixLocationCoord(location.getLatitude());
        mediaGeo.geo._long = AndroidUtilities.fixLocationCoord(location.getLongitude());
        for (Map.Entry<String, MessageObject> entry : this.waitingForLocation.entrySet()) {
            MessageObject messageObject = entry.getValue();
            sendMessage((TLRPC.MessageMedia) mediaGeo, messageObject.getDialogId(), messageObject, (TLRPC.ReplyMarkup) null, (HashMap<String, String>) null, true, 0);
        }
    }

    public void sendCurrentLocation(MessageObject messageObject, TLRPC.KeyboardButton button) {
        if (messageObject == null || button == null) {
            return;
        }
        StringBuilder sb = new StringBuilder();
        sb.append(messageObject.getDialogId());
        sb.append("_");
        sb.append(messageObject.getId());
        sb.append("_");
        sb.append(Utilities.bytesToHex(button.data));
        sb.append("_");
        sb.append(button instanceof TLRPC.TL_keyboardButtonGame ? "1" : "0");
        String key = sb.toString();
        this.waitingForLocation.put(key, messageObject);
        this.locationProvider.start();
    }

    public boolean isSendingCurrentLocation(MessageObject messageObject, TLRPC.KeyboardButton button) {
        if (messageObject == null || button == null) {
            return false;
        }
        StringBuilder sb = new StringBuilder();
        sb.append(messageObject.getDialogId());
        sb.append("_");
        sb.append(messageObject.getId());
        sb.append("_");
        sb.append(Utilities.bytesToHex(button.data));
        sb.append("_");
        sb.append(button instanceof TLRPC.TL_keyboardButtonGame ? "1" : "0");
        String key = sb.toString();
        return this.waitingForLocation.containsKey(key);
    }

    public void sendNotificationCallback(final long dialogId, final int msgId, final byte[] data) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SendMessagesHelper$_TWDa2uQyH3GXtAx7eCoF0_9jts
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$sendNotificationCallback$14$SendMessagesHelper(dialogId, msgId, data);
            }
        });
    }

    public /* synthetic */ void lambda$sendNotificationCallback$14$SendMessagesHelper(long dialogId, int msgId, byte[] data) {
        TLRPC.Chat chat;
        TLRPC.User user;
        int lowerId = (int) dialogId;
        final String key = dialogId + "_" + msgId + "_" + Utilities.bytesToHex(data) + "_0";
        this.waitingForCallback.put(key, true);
        if (lowerId > 0) {
            if (getMessagesController().getUser(Integer.valueOf(lowerId)) == null && (user = getMessagesStorage().getUserSync(lowerId)) != null) {
                getMessagesController().putUser(user, true);
            }
        } else if (getMessagesController().getChat(Integer.valueOf(-lowerId)) == null && (chat = getMessagesStorage().getChatSync(-lowerId)) != null) {
            getMessagesController().putChat(chat, true);
        }
        TLRPC.TL_messages_getBotCallbackAnswer req = new TLRPC.TL_messages_getBotCallbackAnswer();
        req.peer = getMessagesController().getInputPeer(lowerId);
        req.msg_id = msgId;
        req.game = false;
        if (data != null) {
            req.flags |= 1;
            req.data = data;
        }
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SendMessagesHelper$j1t_tGiVAUynD3wtDgOHLwEqej8
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$null$13$SendMessagesHelper(key, tLObject, tL_error);
            }
        }, 2);
        getMessagesController().markDialogAsRead(dialogId, msgId, msgId, 0, false, 0, true, 0);
    }

    public /* synthetic */ void lambda$null$12$SendMessagesHelper(String key) {
        this.waitingForCallback.remove(key);
    }

    public /* synthetic */ void lambda$null$13$SendMessagesHelper(final String key, TLObject response, TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SendMessagesHelper$8NgvwutJuWCSHz8HkXAEXi5kOFA
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$12$SendMessagesHelper(key);
            }
        });
    }

    public byte[] isSendingVote(MessageObject messageObject) {
        if (messageObject == null) {
            return null;
        }
        String key = "poll_" + messageObject.getPollId();
        return this.waitingForVote.get(key);
    }

    public int sendVote(final MessageObject messageObject, TLRPC.TL_pollAnswer answer, final Runnable finishRunnable) {
        if (messageObject == null) {
            return 0;
        }
        final String key = "poll_" + messageObject.getPollId();
        if (this.waitingForCallback.containsKey(key)) {
            return 0;
        }
        this.waitingForVote.put(key, answer != null ? answer.option : new byte[0]);
        TLRPC.TL_messages_sendVote req = new TLRPC.TL_messages_sendVote();
        req.msg_id = messageObject.getId();
        req.peer = getMessagesController().getInputPeer((int) messageObject.getDialogId());
        if (answer != null) {
            req.options.add(answer.option);
        }
        return getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SendMessagesHelper$dTJncgPYeZpdf67mrYeLIq65AAo
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) throws Exception {
                this.f$0.lambda$sendVote$15$SendMessagesHelper(messageObject, key, finishRunnable, tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$sendVote$15$SendMessagesHelper(MessageObject messageObject, final String key, final Runnable finishRunnable, TLObject response, TLRPC.TL_error error) throws Exception {
        if (error == null) {
            this.voteSendTime.put(messageObject.getPollId(), 0L);
            getMessagesController().processUpdates((TLRPC.Updates) response, false);
            this.voteSendTime.put(messageObject.getPollId(), Long.valueOf(SystemClock.uptimeMillis()));
        }
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.SendMessagesHelper.2
            @Override // java.lang.Runnable
            public void run() {
                SendMessagesHelper.this.waitingForVote.remove(key);
                Runnable runnable = finishRunnable;
                if (runnable != null) {
                    runnable.run();
                }
            }
        });
    }

    protected long getVoteSendTime(long pollId) {
        return this.voteSendTime.get(pollId, 0L).longValue();
    }

    public void sendReaction(MessageObject messageObject, CharSequence reaction, ChatActivity parentFragment) {
        if (messageObject == null || parentFragment == null) {
            return;
        }
        TLRPC.TL_messages_sendReaction req = new TLRPC.TL_messages_sendReaction();
        req.peer = getMessagesController().getInputPeer((int) messageObject.getDialogId());
        req.msg_id = messageObject.getId();
        if (reaction != null) {
            req.reaction = reaction.toString();
            req.flags |= 1;
        }
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SendMessagesHelper$A68p7B7_PmA58u5ot2JmPbk6HSU
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) throws Exception {
                this.f$0.lambda$sendReaction$16$SendMessagesHelper(tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$sendReaction$16$SendMessagesHelper(TLObject response, TLRPC.TL_error error) throws Exception {
        if (response != null) {
            getMessagesController().processUpdates((TLRPC.Updates) response, false);
        }
    }

    public void sendCallback(boolean cache, final MessageObject messageObject, final TLRPC.KeyboardButton button, final ChatActivity parentFragment) {
        boolean cacheFinal;
        int type;
        if (messageObject == null || button == null) {
            return;
        }
        if (parentFragment == null) {
            return;
        }
        if (button instanceof TLRPC.TL_keyboardButtonUrlAuth) {
            cacheFinal = false;
            type = 3;
        } else {
            boolean cacheFinal2 = button instanceof TLRPC.TL_keyboardButtonGame;
            if (cacheFinal2) {
                cacheFinal = false;
                type = 1;
            } else if (button instanceof TLRPC.TL_keyboardButtonBuy) {
                cacheFinal = cache;
                type = 2;
            } else {
                cacheFinal = cache;
                type = 0;
            }
        }
        final String key = messageObject.getDialogId() + "_" + messageObject.getId() + "_" + Utilities.bytesToHex(button.data) + "_" + type;
        this.waitingForCallback.put(key, true);
        final TLObject[] request = new TLObject[1];
        final boolean z = cacheFinal;
        RequestDelegate requestDelegate = new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SendMessagesHelper$Jx8qQIJlX1fr743AmWhuTRAuG3I
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$sendCallback$18$SendMessagesHelper(key, z, messageObject, button, parentFragment, request, tLObject, tL_error);
            }
        };
        if (cacheFinal) {
            getMessagesStorage().getBotCache(key, requestDelegate);
            return;
        }
        if (button instanceof TLRPC.TL_keyboardButtonUrlAuth) {
            TLRPC.TL_messages_requestUrlAuth req = new TLRPC.TL_messages_requestUrlAuth();
            req.peer = getMessagesController().getInputPeer((int) messageObject.getDialogId());
            req.msg_id = messageObject.getId();
            req.button_id = button.button_id;
            request[0] = req;
            getConnectionsManager().sendRequest(req, requestDelegate, 2);
            return;
        }
        if (button instanceof TLRPC.TL_keyboardButtonBuy) {
            if ((messageObject.messageOwner.media.flags & 4) == 0) {
                TLRPC.TL_payments_getPaymentForm req2 = new TLRPC.TL_payments_getPaymentForm();
                req2.msg_id = messageObject.getId();
                getConnectionsManager().sendRequest(req2, requestDelegate, 2);
                return;
            } else {
                TLRPC.TL_payments_getPaymentReceipt req3 = new TLRPC.TL_payments_getPaymentReceipt();
                req3.msg_id = messageObject.messageOwner.media.receipt_msg_id;
                getConnectionsManager().sendRequest(req3, requestDelegate, 2);
                return;
            }
        }
        TLRPC.TL_messages_getBotCallbackAnswer req4 = new TLRPC.TL_messages_getBotCallbackAnswer();
        req4.peer = getMessagesController().getInputPeer((int) messageObject.getDialogId());
        req4.msg_id = messageObject.getId();
        req4.game = button instanceof TLRPC.TL_keyboardButtonGame;
        if (button.data != null) {
            req4.flags |= 1;
            req4.data = button.data;
        }
        getConnectionsManager().sendRequest(req4, requestDelegate, 2);
    }

    public /* synthetic */ void lambda$sendCallback$18$SendMessagesHelper(final String key, final boolean cacheFinal, final MessageObject messageObject, final TLRPC.KeyboardButton button, final ChatActivity parentFragment, final TLObject[] request, final TLObject response, TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SendMessagesHelper$UXQPU6Se0WyWwo76hT4MpRwfU14
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$17$SendMessagesHelper(key, cacheFinal, response, messageObject, button, parentFragment, request);
            }
        });
    }

    /* JADX WARN: Removed duplicated region for block: B:82:0x0160  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public /* synthetic */ void lambda$null$17$SendMessagesHelper(java.lang.String r18, boolean r19, im.uwrkaxlmjj.tgnet.TLObject r20, im.uwrkaxlmjj.messenger.MessageObject r21, im.uwrkaxlmjj.tgnet.TLRPC.KeyboardButton r22, im.uwrkaxlmjj.ui.ChatActivity r23, im.uwrkaxlmjj.tgnet.TLObject[] r24) {
        /*
            Method dump skipped, instruction units count: 371
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.SendMessagesHelper.lambda$null$17$SendMessagesHelper(java.lang.String, boolean, im.uwrkaxlmjj.tgnet.TLObject, im.uwrkaxlmjj.messenger.MessageObject, im.uwrkaxlmjj.tgnet.TLRPC$KeyboardButton, im.uwrkaxlmjj.ui.ChatActivity, im.uwrkaxlmjj.tgnet.TLObject[]):void");
    }

    public boolean isSendingCallback(MessageObject messageObject, TLRPC.KeyboardButton button) {
        int type;
        if (messageObject == null || button == null) {
            return false;
        }
        if (button instanceof TLRPC.TL_keyboardButtonUrlAuth) {
            type = 3;
        } else if (button instanceof TLRPC.TL_keyboardButtonGame) {
            type = 1;
        } else if (button instanceof TLRPC.TL_keyboardButtonBuy) {
            type = 2;
        } else {
            type = 0;
        }
        String key = messageObject.getDialogId() + "_" + messageObject.getId() + "_" + Utilities.bytesToHex(button.data) + "_" + type;
        return this.waitingForCallback.containsKey(key);
    }

    public void sendEditMessageMedia(TLRPC.InputPeer peer, int id, TLRPC.InputMedia media) {
        if (peer == null) {
            return;
        }
        TLRPCContacts.TL_EditMessageMedia request = new TLRPCContacts.TL_EditMessageMedia();
        request.peer = peer;
        request.id = id;
        request.media = media;
        getConnectionsManager().sendRequest(request, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SendMessagesHelper$ESdFFsqfpc20-JWuFOWWhsc-UDM
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) throws Exception {
                this.f$0.lambda$sendEditMessageMedia$19$SendMessagesHelper(tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$sendEditMessageMedia$19$SendMessagesHelper(TLObject response, TLRPC.TL_error error) throws Exception {
        if (error == null) {
            getMessagesController().processUpdates((TLRPC.Updates) response, false);
        }
    }

    public void sendGame(TLRPC.InputPeer peer, TLRPC.TL_inputMediaGame game, long random_id, long taskId) {
        final long newTaskId;
        if (peer == null || game == null) {
            return;
        }
        TLRPC.TL_messages_sendMedia request = new TLRPC.TL_messages_sendMedia();
        request.peer = peer;
        if (request.peer instanceof TLRPC.TL_inputPeerChannel) {
            request.silent = MessagesController.getNotificationsSettings(this.currentAccount).getBoolean("silent_" + (-peer.channel_id), false);
        } else if (request.peer instanceof TLRPC.TL_inputPeerChat) {
            request.silent = MessagesController.getNotificationsSettings(this.currentAccount).getBoolean("silent_" + (-peer.chat_id), false);
        } else {
            request.silent = MessagesController.getNotificationsSettings(this.currentAccount).getBoolean("silent_" + peer.user_id, false);
        }
        request.random_id = random_id != 0 ? random_id : getNextRandomId();
        request.message = "";
        request.media = game;
        if (taskId == 0) {
            NativeByteBuffer data = null;
            try {
                data = new NativeByteBuffer(peer.getObjectSize() + game.getObjectSize() + 4 + 8);
                data.writeInt32(3);
                data.writeInt64(random_id);
                peer.serializeToStream(data);
                game.serializeToStream(data);
            } catch (Exception e) {
                FileLog.e(e);
            }
            newTaskId = getMessagesStorage().createPendingTask(data);
        } else {
            newTaskId = taskId;
        }
        getConnectionsManager().sendRequest(request, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SendMessagesHelper$m3Q2JUjs57wCPxNWKsSTR4xvXB0
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) throws Exception {
                this.f$0.lambda$sendGame$20$SendMessagesHelper(newTaskId, tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$sendGame$20$SendMessagesHelper(long newTaskId, TLObject response, TLRPC.TL_error error) throws Exception {
        if (error == null) {
            getMessagesController().processUpdates((TLRPC.Updates) response, false);
        }
        if (newTaskId != 0) {
            getMessagesStorage().removePendingTask(newTaskId);
        }
    }

    public void sendMessage(MessageObject retryMessageObject) {
        sendMessage(null, null, null, null, null, null, null, null, null, retryMessageObject.getDialogId(), retryMessageObject.messageOwner.attachPath, null, null, true, retryMessageObject, null, retryMessageObject.messageOwner.reply_markup, retryMessageObject.messageOwner.params, !retryMessageObject.messageOwner.silent, retryMessageObject.scheduled ? retryMessageObject.messageOwner.date : 0, 0, null);
    }

    public void sendMessage(TLRPC.User user, long peer, MessageObject reply_to_msg, TLRPC.ReplyMarkup replyMarkup, HashMap<String, String> params, boolean notify, int scheduleDate) {
        sendMessage(null, null, null, null, null, user, null, null, null, peer, null, reply_to_msg, null, true, null, null, replyMarkup, params, notify, scheduleDate, 0, null);
    }

    public void sendMessage(TLRPC.TL_document document, VideoEditedInfo videoEditedInfo, String path, long peer, MessageObject reply_to_msg, String caption, ArrayList<TLRPC.MessageEntity> entities, TLRPC.ReplyMarkup replyMarkup, HashMap<String, String> params, boolean notify, int scheduleDate, int ttl, Object parentObject) {
        sendMessage(null, caption, null, null, videoEditedInfo, null, document, null, null, peer, path, reply_to_msg, null, true, null, entities, replyMarkup, params, notify, scheduleDate, ttl, parentObject);
    }

    public void sendMessage(String message, long peer, MessageObject reply_to_msg, TLRPC.WebPage webPage, boolean searchLinks, ArrayList<TLRPC.MessageEntity> entities, TLRPC.ReplyMarkup replyMarkup, HashMap<String, String> params, boolean notify, int scheduleDate) {
        sendMessage(message, null, null, null, null, null, null, null, null, peer, null, reply_to_msg, webPage, searchLinks, null, entities, replyMarkup, params, notify, scheduleDate, 0, null);
    }

    public void sendMessage(TLRPC.MessageMedia location, long peer, MessageObject reply_to_msg, TLRPC.ReplyMarkup replyMarkup, HashMap<String, String> params, boolean notify, int scheduleDate) {
        sendMessage(null, null, location, null, null, null, null, null, null, peer, null, reply_to_msg, null, true, null, null, replyMarkup, params, notify, scheduleDate, 0, null);
    }

    public void sendMessage(TLRPC.TL_messageMediaPoll poll, long peer, MessageObject reply_to_msg, TLRPC.ReplyMarkup replyMarkup, HashMap<String, String> params, boolean notify, int scheduleDate) {
        sendMessage(null, null, null, null, null, null, null, null, poll, peer, null, reply_to_msg, null, true, null, null, replyMarkup, params, notify, scheduleDate, 0, null);
    }

    public void sendMessage(TLRPC.TL_game game, long peer, TLRPC.ReplyMarkup replyMarkup, HashMap<String, String> params, boolean notify, int scheduleDate) {
        sendMessage(null, null, null, null, null, null, null, game, null, peer, null, null, null, true, null, null, replyMarkup, params, notify, scheduleDate, 0, null);
    }

    public void sendMessage(TLRPC.TL_photo photo, String path, long peer, MessageObject reply_to_msg, String caption, ArrayList<TLRPC.MessageEntity> entities, TLRPC.ReplyMarkup replyMarkup, HashMap<String, String> params, boolean notify, int scheduleDate, int ttl, Object parentObject) {
        sendMessage(null, caption, null, photo, null, null, null, null, null, peer, path, reply_to_msg, null, true, null, entities, replyMarkup, params, notify, scheduleDate, ttl, parentObject);
    }

    public void sendRedpaketTransfer(TLRPC.User user, long peer, String message, String caption) {
        TLRPC.EncryptedChat encryptedChat;
        if ((user != null && user.phone == null) || peer == 0) {
            return;
        }
        int lower_id = (int) peer;
        int high_id = (int) (peer >> 32);
        TLRPC.InputPeer sendToPeer = lower_id != 0 ? getMessagesController().getInputPeer(lower_id) : null;
        if (lower_id == 0) {
            TLRPC.EncryptedChat encryptedChat2 = getMessagesController().getEncryptedChat(Integer.valueOf(high_id));
            if (encryptedChat2 != null) {
                encryptedChat = encryptedChat2;
            } else {
                return;
            }
        } else if (!(sendToPeer instanceof TLRPC.TL_inputPeerChannel)) {
            encryptedChat = null;
        } else {
            TLRPC.Chat chat = getMessagesController().getChat(Integer.valueOf(sendToPeer.channel_id));
            boolean z = (chat == null || chat.megagroup) ? false : true;
            encryptedChat = null;
        }
        if (message != null) {
            try {
                if (encryptedChat != null) {
                    new TLRPC.TL_message_secret();
                } else {
                    new TLRPC.TL_message();
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    /* JADX WARN: Not initialized variable reg: 31, insn: 0x0321: MOVE (r3 I:??[OBJECT, ARRAY]) = (r31 I:??[OBJECT, ARRAY] A[D('sendToPeer' im.uwrkaxlmjj.tgnet.TLRPC$InputPeer)]), block:B:111:0x0305 */
    /* JADX WARN: Unreachable blocks removed: 2, instructions: 15 */
    /* JADX WARN: Unreachable blocks removed: 2, instructions: 19 */
    /*  JADX ERROR: Type inference failed with stack overflow
        jadx.core.utils.exceptions.JadxOverflowException
        	at jadx.core.utils.ErrorsCounter.addError(ErrorsCounter.java:59)
        	at jadx.core.utils.ErrorsCounter.error(ErrorsCounter.java:31)
        	at jadx.core.dex.attributes.nodes.NotificationAttrNode.addError(NotificationAttrNode.java:19)
        	at jadx.core.dex.visitors.typeinference.TypeInferenceVisitor.visit(TypeInferenceVisitor.java:77)
        */
    private void sendMessage(java.lang.String r56, java.lang.String r57, im.uwrkaxlmjj.tgnet.TLRPC.MessageMedia r58, im.uwrkaxlmjj.tgnet.TLRPC.TL_photo r59, im.uwrkaxlmjj.messenger.VideoEditedInfo r60, im.uwrkaxlmjj.tgnet.TLRPC.User r61, im.uwrkaxlmjj.tgnet.TLRPC.TL_document r62, im.uwrkaxlmjj.tgnet.TLRPC.TL_game r63, im.uwrkaxlmjj.tgnet.TLRPC.TL_messageMediaPoll r64, long r65, java.lang.String r67, im.uwrkaxlmjj.messenger.MessageObject r68, im.uwrkaxlmjj.tgnet.TLRPC.WebPage r69, boolean r70, im.uwrkaxlmjj.messenger.MessageObject r71, java.util.ArrayList<im.uwrkaxlmjj.tgnet.TLRPC.MessageEntity> r72, im.uwrkaxlmjj.tgnet.TLRPC.ReplyMarkup r73, java.util.HashMap<java.lang.String, java.lang.String> r74, boolean r75, int r76, int r77, java.lang.Object r78) {
        /*
            Method dump skipped, instruction units count: 12988
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.SendMessagesHelper.sendMessage(java.lang.String, java.lang.String, im.uwrkaxlmjj.tgnet.TLRPC$MessageMedia, im.uwrkaxlmjj.tgnet.TLRPC$TL_photo, im.uwrkaxlmjj.messenger.VideoEditedInfo, im.uwrkaxlmjj.tgnet.TLRPC$User, im.uwrkaxlmjj.tgnet.TLRPC$TL_document, im.uwrkaxlmjj.tgnet.TLRPC$TL_game, im.uwrkaxlmjj.tgnet.TLRPC$TL_messageMediaPoll, long, java.lang.String, im.uwrkaxlmjj.messenger.MessageObject, im.uwrkaxlmjj.tgnet.TLRPC$WebPage, boolean, im.uwrkaxlmjj.messenger.MessageObject, java.util.ArrayList, im.uwrkaxlmjj.tgnet.TLRPC$ReplyMarkup, java.util.HashMap, boolean, int, int, java.lang.Object):void");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void performSendDelayedMessage(DelayedMessage message) {
        performSendDelayedMessage(message, -1);
    }

    private TLRPC.PhotoSize getThumbForSecretChat(ArrayList<TLRPC.PhotoSize> arrayList) {
        if (arrayList == null || arrayList.isEmpty()) {
            return null;
        }
        int N = arrayList.size();
        for (int a = 0; a < N; a++) {
            TLRPC.PhotoSize size = arrayList.get(a);
            if (size != null && !(size instanceof TLRPC.TL_photoStrippedSize) && !(size instanceof TLRPC.TL_photoSizeEmpty) && size.location != null) {
                TLRPC.TL_photoSize photoSize = new TLRPC.TL_photoSize();
                photoSize.type = size.type;
                photoSize.w = size.w;
                photoSize.h = size.h;
                photoSize.size = size.size;
                photoSize.bytes = size.bytes;
                if (photoSize.bytes == null) {
                    photoSize.bytes = new byte[0];
                }
                photoSize.location = new TLRPC.TL_fileLocation_layer82();
                photoSize.location.dc_id = size.location.dc_id;
                photoSize.location.volume_id = size.location.volume_id;
                photoSize.location.local_id = size.location.local_id;
                photoSize.location.secret = size.location.secret;
                return photoSize;
            }
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void performSendDelayedMessage(DelayedMessage message, int index) {
        int index2;
        TLObject inputMedia;
        MessageObject messageObject;
        TLRPC.InputMedia media;
        TLRPC.InputMedia media2;
        TLRPC.InputMedia media3;
        if (message.type == 0) {
            if (message.httpLocation != null) {
                putToDelayedMessages(message.httpLocation, message);
                ImageLoader.getInstance().loadHttpFile(message.httpLocation, "file", this.currentAccount);
            } else if (message.sendRequest != null) {
                String location = FileLoader.getPathToAttach(message.photoSize).toString();
                putToDelayedMessages(location, message);
                getFileLoader().uploadFile(location, false, true, 16777216);
                putToUploadingMessages(message.obj);
            } else {
                String location2 = FileLoader.getPathToAttach(message.photoSize).toString();
                if (message.sendEncryptedRequest != null && message.photoSize.location.dc_id != 0) {
                    File file = new File(location2);
                    if (!file.exists()) {
                        location2 = FileLoader.getPathToAttach(message.photoSize, true).toString();
                        file = new File(location2);
                    }
                    if (!file.exists()) {
                        putToDelayedMessages(FileLoader.getAttachFileName(message.photoSize), message);
                        getFileLoader().loadFile(ImageLocation.getForObject(message.photoSize, message.locationParent), message.parentObject, "jpg", 2, 0);
                        return;
                    }
                }
                putToDelayedMessages(location2, message);
                getFileLoader().uploadFile(location2, true, true, 16777216);
                putToUploadingMessages(message.obj);
            }
        } else if (message.type == 1) {
            if (message.videoEditedInfo != null && message.videoEditedInfo.needConvert()) {
                String location3 = message.obj.messageOwner.attachPath;
                TLRPC.Document document = message.obj.getDocument();
                if (location3 == null) {
                    location3 = FileLoader.getDirectory(4) + "/" + document.id + ".mp4";
                }
                putToDelayedMessages(location3, message);
                MediaController.getInstance().scheduleVideoConvert(message.obj);
                putToUploadingMessages(message.obj);
            } else {
                if (message.videoEditedInfo != null) {
                    if (message.videoEditedInfo.file != null) {
                        if (message.sendRequest instanceof TLRPC.TL_messages_sendMedia) {
                            media3 = ((TLRPC.TL_messages_sendMedia) message.sendRequest).media;
                        } else {
                            media3 = ((TLRPC.TL_messages_editMessage) message.sendRequest).media;
                        }
                        media3.file = message.videoEditedInfo.file;
                        message.videoEditedInfo.file = null;
                    } else if (message.videoEditedInfo.encryptedFile != null) {
                        TLRPC.TL_decryptedMessage decryptedMessage = (TLRPC.TL_decryptedMessage) message.sendEncryptedRequest;
                        decryptedMessage.media.size = (int) message.videoEditedInfo.estimatedSize;
                        decryptedMessage.media.key = message.videoEditedInfo.key;
                        decryptedMessage.media.iv = message.videoEditedInfo.iv;
                        getSecretChatHelper().performSendEncryptedRequest(decryptedMessage, message.obj.messageOwner, message.encryptedChat, message.videoEditedInfo.encryptedFile, message.originalPath, message.obj);
                        message.videoEditedInfo.encryptedFile = null;
                        return;
                    }
                }
                if (message.sendRequest != null) {
                    if (message.sendRequest instanceof TLRPC.TL_messages_sendMedia) {
                        media2 = ((TLRPC.TL_messages_sendMedia) message.sendRequest).media;
                    } else {
                        media2 = ((TLRPC.TL_messages_editMessage) message.sendRequest).media;
                    }
                    if (media2.file == null) {
                        String location4 = message.obj.messageOwner.attachPath;
                        TLRPC.Document document2 = message.obj.getDocument();
                        if (location4 == null) {
                            location4 = FileLoader.getDirectory(4) + "/" + document2.id + ".mp4";
                        }
                        putToDelayedMessages(location4, message);
                        if (message.obj.videoEditedInfo != null && message.obj.videoEditedInfo.needConvert()) {
                            getFileLoader().uploadFile(location4, false, false, document2.size, ConnectionsManager.FileTypeVideo, true);
                        } else {
                            getFileLoader().uploadFile(location4, false, false, ConnectionsManager.FileTypeVideo);
                        }
                        putToUploadingMessages(message.obj);
                    } else {
                        String location5 = FileLoader.getDirectory(4) + "/" + message.photoSize.location.volume_id + "_" + message.photoSize.location.local_id + ".jpg";
                        putToDelayedMessages(location5, message);
                        getFileLoader().uploadFile(location5, false, true, 16777216);
                        putToUploadingMessages(message.obj);
                    }
                } else {
                    String location6 = message.obj.messageOwner.attachPath;
                    TLRPC.Document document3 = message.obj.getDocument();
                    if (location6 == null) {
                        location6 = FileLoader.getDirectory(4) + "/" + document3.id + ".mp4";
                    }
                    if (message.sendEncryptedRequest != null && document3.dc_id != 0) {
                        File file2 = new File(location6);
                        if (!file2.exists()) {
                            putToDelayedMessages(FileLoader.getAttachFileName(document3), message);
                            getFileLoader().loadFile(document3, message.parentObject, 2, 0);
                            return;
                        }
                    }
                    putToDelayedMessages(location6, message);
                    if (message.obj.videoEditedInfo != null && message.obj.videoEditedInfo.needConvert()) {
                        getFileLoader().uploadFile(location6, true, false, document3.size, ConnectionsManager.FileTypeVideo, true);
                    } else {
                        getFileLoader().uploadFile(location6, true, false, ConnectionsManager.FileTypeVideo);
                    }
                    putToUploadingMessages(message.obj);
                }
            }
        } else if (message.type == 2) {
            if (message.httpLocation != null) {
                putToDelayedMessages(message.httpLocation, message);
                ImageLoader.getInstance().loadHttpFile(message.httpLocation, "gif", this.currentAccount);
            } else if (message.sendRequest != null) {
                if (message.sendRequest instanceof TLRPC.TL_messages_sendMedia) {
                    media = ((TLRPC.TL_messages_sendMedia) message.sendRequest).media;
                } else {
                    media = ((TLRPC.TL_messages_editMessage) message.sendRequest).media;
                }
                if (media.file == null) {
                    String location7 = message.obj.messageOwner.attachPath;
                    putToDelayedMessages(location7, message);
                    getFileLoader().uploadFile(location7, message.sendRequest == null, false, ConnectionsManager.FileTypeFile);
                    putToUploadingMessages(message.obj);
                } else if (media.thumb == null && message.photoSize != null) {
                    String location8 = FileLoader.getDirectory(4) + "/" + message.photoSize.location.volume_id + "_" + message.photoSize.location.local_id + ".jpg";
                    putToDelayedMessages(location8, message);
                    getFileLoader().uploadFile(location8, false, true, 16777216);
                    putToUploadingMessages(message.obj);
                }
            } else {
                String location9 = message.obj.messageOwner.attachPath;
                TLRPC.Document document4 = message.obj.getDocument();
                if (message.sendEncryptedRequest != null && document4.dc_id != 0) {
                    File file3 = new File(location9);
                    if (!file3.exists()) {
                        putToDelayedMessages(FileLoader.getAttachFileName(document4), message);
                        getFileLoader().loadFile(document4, message.parentObject, 2, 0);
                        return;
                    }
                }
                putToDelayedMessages(location9, message);
                getFileLoader().uploadFile(location9, true, false, ConnectionsManager.FileTypeFile);
                putToUploadingMessages(message.obj);
            }
        } else if (message.type == 3) {
            String location10 = message.obj.messageOwner.attachPath;
            putToDelayedMessages(location10, message);
            getFileLoader().uploadFile(location10, message.sendRequest == null, true, ConnectionsManager.FileTypeAudio);
            putToUploadingMessages(message.obj);
        } else if (message.type == 4) {
            boolean add = index < 0;
            if (message.performMediaUpload) {
                if (index >= 0) {
                    index2 = index;
                } else {
                    index2 = message.messageObjects.size() - 1;
                }
                MessageObject messageObject2 = message.messageObjects.get(index2);
                if (messageObject2.getDocument() != null) {
                    if (message.videoEditedInfo != null) {
                        String location11 = messageObject2.messageOwner.attachPath;
                        TLRPC.Document document5 = messageObject2.getDocument();
                        if (location11 == null) {
                            location11 = FileLoader.getDirectory(4) + "/" + document5.id + ".mp4";
                        }
                        putToDelayedMessages(location11, message);
                        message.extraHashMap.put(messageObject2, location11);
                        message.extraHashMap.put(location11 + "_i", messageObject2);
                        if (message.photoSize != null) {
                            message.extraHashMap.put(location11 + "_t", message.photoSize);
                        }
                        MediaController.getInstance().scheduleVideoConvert(messageObject2);
                        message.obj = messageObject2;
                        putToUploadingMessages(messageObject2);
                    } else {
                        TLRPC.Document document6 = messageObject2.getDocument();
                        String documentLocation = messageObject2.messageOwner.attachPath;
                        if (documentLocation != null) {
                            messageObject = messageObject2;
                        } else {
                            StringBuilder sb = new StringBuilder();
                            sb.append(FileLoader.getDirectory(4));
                            sb.append("/");
                            messageObject = messageObject2;
                            sb.append(document6.id);
                            sb.append(".mp4");
                            documentLocation = sb.toString();
                        }
                        if (message.sendRequest != null) {
                            TLRPC.TL_messages_sendMultiMedia request = (TLRPC.TL_messages_sendMultiMedia) message.sendRequest;
                            TLRPC.InputMedia media4 = request.multi_media.get(index2).media;
                            if (media4.file == null) {
                                putToDelayedMessages(documentLocation, message);
                                MessageObject messageObject3 = messageObject;
                                message.extraHashMap.put(messageObject3, documentLocation);
                                message.extraHashMap.put(documentLocation, media4);
                                message.extraHashMap.put(documentLocation + "_i", messageObject3);
                                if (message.photoSize != null) {
                                    message.extraHashMap.put(documentLocation + "_t", message.photoSize);
                                }
                                if (messageObject3.videoEditedInfo != null && messageObject3.videoEditedInfo.needConvert()) {
                                    getFileLoader().uploadFile(documentLocation, false, false, document6.size, ConnectionsManager.FileTypeVideo, true);
                                } else {
                                    getFileLoader().uploadFile(documentLocation, false, false, ConnectionsManager.FileTypeVideo);
                                }
                                putToUploadingMessages(messageObject3);
                            } else {
                                MessageObject messageObject4 = messageObject;
                                String location12 = FileLoader.getDirectory(4) + "/" + message.photoSize.location.volume_id + "_" + message.photoSize.location.local_id + ".jpg";
                                putToDelayedMessages(location12, message);
                                message.extraHashMap.put(location12 + "_o", documentLocation);
                                message.extraHashMap.put(messageObject4, location12);
                                message.extraHashMap.put(location12, media4);
                                getFileLoader().uploadFile(location12, false, true, 16777216);
                                putToUploadingMessages(messageObject4);
                            }
                        } else {
                            MessageObject messageObject5 = messageObject;
                            TLRPC.TL_messages_sendEncryptedMultiMedia request2 = (TLRPC.TL_messages_sendEncryptedMultiMedia) message.sendEncryptedRequest;
                            putToDelayedMessages(documentLocation, message);
                            message.extraHashMap.put(messageObject5, documentLocation);
                            message.extraHashMap.put(documentLocation, request2.files.get(index2));
                            message.extraHashMap.put(documentLocation + "_i", messageObject5);
                            if (message.photoSize != null) {
                                message.extraHashMap.put(documentLocation + "_t", message.photoSize);
                            }
                            if (messageObject5.videoEditedInfo != null && messageObject5.videoEditedInfo.needConvert()) {
                                getFileLoader().uploadFile(documentLocation, true, false, document6.size, ConnectionsManager.FileTypeVideo, true);
                            } else {
                                getFileLoader().uploadFile(documentLocation, true, false, ConnectionsManager.FileTypeVideo);
                            }
                            putToUploadingMessages(messageObject5);
                        }
                    }
                    message.videoEditedInfo = null;
                    message.photoSize = null;
                } else if (message.httpLocation != null) {
                    putToDelayedMessages(message.httpLocation, message);
                    message.extraHashMap.put(messageObject2, message.httpLocation);
                    message.extraHashMap.put(message.httpLocation, messageObject2);
                    ImageLoader.getInstance().loadHttpFile(message.httpLocation, "file", this.currentAccount);
                    message.httpLocation = null;
                } else {
                    if (message.sendRequest != null) {
                        TLRPC.TL_messages_sendMultiMedia request3 = (TLRPC.TL_messages_sendMultiMedia) message.sendRequest;
                        inputMedia = request3.multi_media.get(index2).media;
                    } else {
                        TLObject inputMedia2 = message.sendEncryptedRequest;
                        TLRPC.TL_messages_sendEncryptedMultiMedia request4 = (TLRPC.TL_messages_sendEncryptedMultiMedia) inputMedia2;
                        inputMedia = request4.files.get(index2);
                    }
                    String location13 = FileLoader.getPathToAttach(message.photoSize).toString();
                    putToDelayedMessages(location13, message);
                    message.extraHashMap.put(location13, inputMedia);
                    message.extraHashMap.put(messageObject2, location13);
                    getFileLoader().uploadFile(location13, message.sendEncryptedRequest != null, true, 16777216);
                    putToUploadingMessages(messageObject2);
                    message.photoSize = null;
                }
                message.performMediaUpload = false;
            } else if (!message.messageObjects.isEmpty()) {
                putToSendingMessages(message.messageObjects.get(message.messageObjects.size() - 1).messageOwner, message.finalGroupMessage != 0);
            }
            sendReadyToSendGroup(message, add, true);
        }
    }

    private void uploadMultiMedia(final DelayedMessage message, final TLRPC.InputMedia inputMedia, TLRPC.InputEncryptedFile inputEncryptedFile, String key) {
        Float fValueOf = Float.valueOf(1.0f);
        if (inputMedia != null) {
            TLRPC.TL_messages_sendMultiMedia multiMedia = (TLRPC.TL_messages_sendMultiMedia) message.sendRequest;
            int a = 0;
            while (true) {
                if (a >= multiMedia.multi_media.size()) {
                    break;
                }
                if (multiMedia.multi_media.get(a).media != inputMedia) {
                    a++;
                } else {
                    putToSendingMessages(message.messages.get(a), message.scheduled);
                    getNotificationCenter().postNotificationName(NotificationCenter.FileUploadProgressChanged, key, fValueOf, false);
                    break;
                }
            }
            TLRPC.TL_messages_uploadMedia req = new TLRPC.TL_messages_uploadMedia();
            req.media = inputMedia;
            req.peer = ((TLRPC.TL_messages_sendMultiMedia) message.sendRequest).peer;
            getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SendMessagesHelper$uUVonsTFhQEofxQPMbmTFyxl5C4
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$uploadMultiMedia$22$SendMessagesHelper(inputMedia, message, tLObject, tL_error);
                }
            });
            return;
        }
        if (inputEncryptedFile != null) {
            TLRPC.TL_messages_sendEncryptedMultiMedia multiMedia2 = (TLRPC.TL_messages_sendEncryptedMultiMedia) message.sendEncryptedRequest;
            int a2 = 0;
            while (true) {
                if (a2 >= multiMedia2.files.size()) {
                    break;
                }
                if (multiMedia2.files.get(a2) != inputEncryptedFile) {
                    a2++;
                } else {
                    putToSendingMessages(message.messages.get(a2), message.scheduled);
                    getNotificationCenter().postNotificationName(NotificationCenter.FileUploadProgressChanged, key, fValueOf, false);
                    break;
                }
            }
            sendReadyToSendGroup(message, false, true);
        }
    }

    public /* synthetic */ void lambda$uploadMultiMedia$22$SendMessagesHelper(final TLRPC.InputMedia inputMedia, final DelayedMessage message, final TLObject response, TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SendMessagesHelper$fgkPHBjnGvDTj7Z0I4vEu9vefbI
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$21$SendMessagesHelper(response, inputMedia, message);
            }
        });
    }

    public /* synthetic */ void lambda$null$21$SendMessagesHelper(TLObject response, TLRPC.InputMedia inputMedia, DelayedMessage message) {
        TLRPC.InputMedia newInputMedia = null;
        if (response != null) {
            TLRPC.MessageMedia messageMedia = (TLRPC.MessageMedia) response;
            if ((inputMedia instanceof TLRPC.TL_inputMediaUploadedPhoto) && (messageMedia instanceof TLRPC.TL_messageMediaPhoto)) {
                TLRPC.TL_inputMediaPhoto inputMediaPhoto = new TLRPC.TL_inputMediaPhoto();
                inputMediaPhoto.id = new TLRPC.TL_inputPhoto();
                inputMediaPhoto.id.id = messageMedia.photo.id;
                inputMediaPhoto.id.access_hash = messageMedia.photo.access_hash;
                inputMediaPhoto.id.file_reference = messageMedia.photo.file_reference;
                newInputMedia = inputMediaPhoto;
            } else if ((inputMedia instanceof TLRPC.TL_inputMediaUploadedDocument) && (messageMedia instanceof TLRPC.TL_messageMediaDocument)) {
                TLRPC.TL_inputMediaDocument inputMediaDocument = new TLRPC.TL_inputMediaDocument();
                inputMediaDocument.id = new TLRPC.TL_inputDocument();
                inputMediaDocument.id.id = messageMedia.document.id;
                inputMediaDocument.id.access_hash = messageMedia.document.access_hash;
                inputMediaDocument.id.file_reference = messageMedia.document.file_reference;
                newInputMedia = inputMediaDocument;
            }
        }
        if (newInputMedia != null) {
            if (inputMedia.ttl_seconds != 0) {
                newInputMedia.ttl_seconds = inputMedia.ttl_seconds;
                newInputMedia.flags |= 1;
            }
            TLRPC.TL_messages_sendMultiMedia req1 = (TLRPC.TL_messages_sendMultiMedia) message.sendRequest;
            int a = 0;
            while (true) {
                if (a >= req1.multi_media.size()) {
                    break;
                }
                if (req1.multi_media.get(a).media != inputMedia) {
                    a++;
                } else {
                    req1.multi_media.get(a).media = newInputMedia;
                    break;
                }
            }
            sendReadyToSendGroup(message, false, true);
            return;
        }
        message.markAsError();
    }

    private void sendReadyToSendGroup(DelayedMessage message, boolean add, boolean check) {
        DelayedMessage maxDelayedMessage;
        if (message.messageObjects.isEmpty()) {
            message.markAsError();
            return;
        }
        String key = "group_" + message.groupId;
        if (message.finalGroupMessage != message.messageObjects.get(message.messageObjects.size() - 1).getId()) {
            if (add) {
                putToDelayedMessages(key, message);
                return;
            }
            return;
        }
        if (add) {
            this.delayedMessages.remove(key);
            getMessagesStorage().putMessages(message.messages, false, true, false, 0, message.scheduled);
            getMessagesController().updateInterfaceWithMessages(message.peer, message.messageObjects, message.scheduled);
            if (!message.scheduled) {
                getNotificationCenter().postNotificationName(NotificationCenter.dialogsNeedReload, new Object[0]);
            }
        }
        if (message.sendRequest instanceof TLRPC.TL_messages_sendMultiMedia) {
            TLRPC.TL_messages_sendMultiMedia request = (TLRPC.TL_messages_sendMultiMedia) message.sendRequest;
            for (int a = 0; a < request.multi_media.size(); a++) {
                TLRPC.InputMedia inputMedia = request.multi_media.get(a).media;
                if ((inputMedia instanceof TLRPC.TL_inputMediaUploadedPhoto) || (inputMedia instanceof TLRPC.TL_inputMediaUploadedDocument)) {
                    return;
                }
            }
            if (check && (maxDelayedMessage = findMaxDelayedMessageForMessageId(message.finalGroupMessage, message.peer)) != null) {
                maxDelayedMessage.addDelayedRequest(message.sendRequest, message.messageObjects, message.originalPaths, message.parentObjects, message, message.scheduled);
                if (message.requests != null) {
                    maxDelayedMessage.requests.addAll(message.requests);
                    return;
                }
                return;
            }
        } else {
            TLRPC.TL_messages_sendEncryptedMultiMedia request2 = (TLRPC.TL_messages_sendEncryptedMultiMedia) message.sendEncryptedRequest;
            for (int a2 = 0; a2 < request2.files.size(); a2++) {
                if (request2.files.get(a2) instanceof TLRPC.TL_inputEncryptedFile) {
                    return;
                }
            }
        }
        if (message.sendRequest instanceof TLRPC.TL_messages_sendMultiMedia) {
            performSendMessageRequestMulti((TLRPC.TL_messages_sendMultiMedia) message.sendRequest, message.messageObjects, message.originalPaths, message.parentObjects, message, message.scheduled);
        } else {
            getSecretChatHelper().performSendEncryptedRequest((TLRPC.TL_messages_sendEncryptedMultiMedia) message.sendEncryptedRequest, message);
        }
        message.sendDelayedRequests();
    }

    public /* synthetic */ void lambda$null$23$SendMessagesHelper(String path) {
        NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.stopEncodingService, path, Integer.valueOf(this.currentAccount));
    }

    public /* synthetic */ void lambda$stopVideoService$24$SendMessagesHelper(final String path) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SendMessagesHelper$-7o1ssK9DQykvo_PI0_cOSUTwmg
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$23$SendMessagesHelper(path);
            }
        });
    }

    protected void stopVideoService(final String path) {
        getMessagesStorage().getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SendMessagesHelper$NV3oU8TSLFB6kwLW4ZQSKRzJnx0
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$stopVideoService$24$SendMessagesHelper(path);
            }
        });
    }

    protected void putToSendingMessages(final TLRPC.Message message, final boolean scheduled) {
        if (Thread.currentThread() != ApplicationLoader.applicationHandler.getLooper().getThread()) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SendMessagesHelper$u-YF2zWqv8Uo14wOdNT3_V2Tl58
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$putToSendingMessages$25$SendMessagesHelper(message, scheduled);
                }
            });
        } else {
            putToSendingMessages(message, scheduled, true);
        }
    }

    public /* synthetic */ void lambda$putToSendingMessages$25$SendMessagesHelper(TLRPC.Message message, boolean scheduled) {
        putToSendingMessages(message, scheduled, true);
    }

    protected void putToSendingMessages(TLRPC.Message message, boolean scheduled, boolean notify) {
        if (message == null) {
            return;
        }
        if (message.id > 0) {
            this.editingMessages.put(message.id, message);
            return;
        }
        boolean contains = this.sendingMessages.indexOfKey(message.id) >= 0;
        removeFromUploadingMessages(message.id, scheduled);
        this.sendingMessages.put(message.id, message);
        if (!scheduled && !contains) {
            long did = MessageObject.getDialogId(message);
            LongSparseArray<Integer> longSparseArray = this.sendingMessagesIdDialogs;
            longSparseArray.put(did, Integer.valueOf(longSparseArray.get(did, 0).intValue() + 1));
            if (notify) {
                getNotificationCenter().postNotificationName(NotificationCenter.sendingMessagesChanged, new Object[0]);
            }
        }
    }

    protected TLRPC.Message removeFromSendingMessages(int mid, boolean scheduled) {
        TLRPC.Message message;
        long did;
        Integer currentCount;
        if (mid > 0) {
            message = this.editingMessages.get(mid);
            if (message != null) {
                this.editingMessages.remove(mid);
            }
        } else {
            message = this.sendingMessages.get(mid);
            if (message != null) {
                this.sendingMessages.remove(mid);
                if (!scheduled && (currentCount = this.sendingMessagesIdDialogs.get((did = MessageObject.getDialogId(message)))) != null) {
                    int count = currentCount.intValue() - 1;
                    if (count <= 0) {
                        this.sendingMessagesIdDialogs.remove(did);
                    } else {
                        this.sendingMessagesIdDialogs.put(did, Integer.valueOf(count));
                    }
                    getNotificationCenter().postNotificationName(NotificationCenter.sendingMessagesChanged, new Object[0]);
                }
            }
        }
        return message;
    }

    public int getSendingMessageId(long did) {
        for (int a = 0; a < this.sendingMessages.size(); a++) {
            TLRPC.Message message = this.sendingMessages.valueAt(a);
            if (message.dialog_id == did) {
                return message.id;
            }
        }
        for (int a2 = 0; a2 < this.uploadMessages.size(); a2++) {
            TLRPC.Message message2 = this.uploadMessages.valueAt(a2);
            if (message2.dialog_id == did) {
                return message2.id;
            }
        }
        return 0;
    }

    protected void putToUploadingMessages(MessageObject obj) {
        if (obj == null || obj.getId() > 0 || obj.scheduled) {
            return;
        }
        TLRPC.Message message = obj.messageOwner;
        boolean contains = this.uploadMessages.indexOfKey(message.id) >= 0;
        this.uploadMessages.put(message.id, message);
        if (!contains) {
            long did = MessageObject.getDialogId(message);
            LongSparseArray<Integer> longSparseArray = this.uploadingMessagesIdDialogs;
            longSparseArray.put(did, Integer.valueOf(longSparseArray.get(did, 0).intValue() + 1));
            getNotificationCenter().postNotificationName(NotificationCenter.sendingMessagesChanged, new Object[0]);
        }
    }

    protected void removeFromUploadingMessages(int mid, boolean scheduled) {
        TLRPC.Message message;
        if (mid <= 0 && !scheduled && (message = this.uploadMessages.get(mid)) != null) {
            this.uploadMessages.remove(mid);
            long did = MessageObject.getDialogId(message);
            Integer currentCount = this.uploadingMessagesIdDialogs.get(did);
            if (currentCount != null) {
                int count = currentCount.intValue() - 1;
                if (count <= 0) {
                    this.uploadingMessagesIdDialogs.remove(did);
                } else {
                    this.uploadingMessagesIdDialogs.put(did, Integer.valueOf(count));
                }
                getNotificationCenter().postNotificationName(NotificationCenter.sendingMessagesChanged, new Object[0]);
            }
        }
    }

    public boolean isSendingMessage(int mid) {
        return this.sendingMessages.indexOfKey(mid) >= 0 || this.editingMessages.indexOfKey(mid) >= 0;
    }

    public boolean isSendingMessageIdDialog(long did) {
        return this.sendingMessagesIdDialogs.get(did, 0).intValue() > 0;
    }

    public boolean isUploadingMessageIdDialog(long did) {
        return this.uploadingMessagesIdDialogs.get(did, 0).intValue() > 0;
    }

    protected void performSendMessageRequestMulti(final TLRPC.TL_messages_sendMultiMedia req, final ArrayList<MessageObject> msgObjs, final ArrayList<String> originalPaths, final ArrayList<Object> parentObjects, final DelayedMessage delayedMessage, final boolean scheduled) {
        int size = msgObjs.size();
        for (int a = 0; a < size; a++) {
            putToSendingMessages(msgObjs.get(a).messageOwner, scheduled);
        }
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SendMessagesHelper$msjIfwy04OmwmLnwC5R-liiHNac
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$performSendMessageRequestMulti$32$SendMessagesHelper(parentObjects, req, msgObjs, originalPaths, delayedMessage, scheduled, tLObject, tL_error);
            }
        }, (QuickAckDelegate) null, 68);
    }

    public /* synthetic */ void lambda$performSendMessageRequestMulti$32$SendMessagesHelper(final ArrayList parentObjects, final TLRPC.TL_messages_sendMultiMedia req, final ArrayList msgObjs, final ArrayList originalPaths, final DelayedMessage delayedMessage, final boolean scheduled, final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SendMessagesHelper$ruWT-zI2xYIhgyK_B1TJ2lOGtOM
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$31$SendMessagesHelper(error, parentObjects, req, msgObjs, originalPaths, delayedMessage, scheduled, response);
            }
        });
    }

    public /* synthetic */ void lambda$null$31$SendMessagesHelper(TLRPC.TL_error error, ArrayList parentObjects, final TLRPC.TL_messages_sendMultiMedia req, final ArrayList msgObjs, ArrayList originalPaths, final DelayedMessage delayedMessage, final boolean scheduled, TLObject response) {
        char c;
        TLRPC.Updates updates;
        int i;
        ArrayList arrayList = originalPaths;
        if (error != null && FileRefController.isFileRefError(error.text)) {
            if (parentObjects != null) {
                ArrayList<Object> arrayList2 = new ArrayList<>(parentObjects);
                getFileRefController().requestReference(arrayList2, req, msgObjs, arrayList, arrayList2, delayedMessage, Boolean.valueOf(scheduled));
                return;
            } else if (delayedMessage != null) {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.SendMessagesHelper.3
                    @Override // java.lang.Runnable
                    public void run() {
                        int a = 0;
                        int size = req.multi_media.size();
                        while (a < size) {
                            if (delayedMessage.parentObjects.get(a) != null) {
                                SendMessagesHelper.this.removeFromSendingMessages(((MessageObject) msgObjs.get(a)).getId(), scheduled);
                                TLRPC.TL_inputSingleMedia request = req.multi_media.get(a);
                                if ((request.media instanceof TLRPC.TL_inputMediaPhoto) || (request.media instanceof TLRPC.TL_inputMediaDocument)) {
                                    request.media = delayedMessage.inputMedias.get(a);
                                }
                                DelayedMessage delayedMessage2 = delayedMessage;
                                delayedMessage2.videoEditedInfo = delayedMessage2.videoEditedInfos.get(a);
                                DelayedMessage delayedMessage3 = delayedMessage;
                                delayedMessage3.httpLocation = delayedMessage3.httpLocations.get(a);
                                DelayedMessage delayedMessage4 = delayedMessage;
                                delayedMessage4.photoSize = delayedMessage4.locations.get(a);
                                delayedMessage.performMediaUpload = true;
                                SendMessagesHelper.this.performSendDelayedMessage(delayedMessage, a);
                            }
                            a++;
                        }
                    }
                });
                return;
            }
        }
        boolean isSentError = false;
        if (error == null) {
            SparseArray<TLRPC.Message> newMessages = new SparseArray<>();
            LongSparseArray<Integer> newIds = new LongSparseArray<>();
            TLRPC.Updates updates2 = (TLRPC.Updates) response;
            ArrayList<TLRPC.Update> updatesArr = ((TLRPC.Updates) response).updates;
            int a = 0;
            while (a < updatesArr.size()) {
                TLRPC.Update update = updatesArr.get(a);
                if (update instanceof TLRPC.TL_updateMessageID) {
                    TLRPC.TL_updateMessageID updateMessageID = (TLRPC.TL_updateMessageID) update;
                    newIds.put(updateMessageID.random_id, Integer.valueOf(updateMessageID.id));
                    updatesArr.remove(a);
                    a--;
                } else if (update instanceof TLRPC.TL_updateNewMessage) {
                    final TLRPC.TL_updateNewMessage newMessage = (TLRPC.TL_updateNewMessage) update;
                    newMessages.put(newMessage.message.id, newMessage.message);
                    Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SendMessagesHelper$6W7AEgYV0Jx5J9cQFTZ-n5KQ8H8
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$null$26$SendMessagesHelper(newMessage);
                        }
                    });
                    updatesArr.remove(a);
                    a--;
                } else if (update instanceof TLRPC.TL_updateNewChannelMessage) {
                    final TLRPC.TL_updateNewChannelMessage newMessage2 = (TLRPC.TL_updateNewChannelMessage) update;
                    newMessages.put(newMessage2.message.id, newMessage2.message);
                    Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SendMessagesHelper$KWwfNuzD7hZ3Bv2YxqykMj8K1lc
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$null$27$SendMessagesHelper(newMessage2);
                        }
                    });
                    updatesArr.remove(a);
                    a--;
                } else if (update instanceof TLRPC.TL_updateNewScheduledMessage) {
                    TLRPC.TL_updateNewScheduledMessage newMessage3 = (TLRPC.TL_updateNewScheduledMessage) update;
                    newMessages.put(newMessage3.message.id, newMessage3.message);
                    updatesArr.remove(a);
                    a--;
                }
                a++;
            }
            int i2 = 0;
            while (true) {
                if (i2 >= msgObjs.size()) {
                    updates = updates2;
                    c = 0;
                    break;
                }
                MessageObject msgObj = (MessageObject) msgObjs.get(i2);
                String originalPath = (String) arrayList.get(i2);
                final TLRPC.Message newMsgObj = msgObj.messageOwner;
                final int oldId = newMsgObj.id;
                final ArrayList<TLRPC.Message> sentMessages = new ArrayList<>();
                String str = newMsgObj.attachPath;
                ArrayList<TLRPC.Update> updatesArr2 = updatesArr;
                Integer id = newIds.get(newMsgObj.random_id);
                if (id != null) {
                    TLRPC.Message message = newMessages.get(id.intValue());
                    if (message == null) {
                        updates = updates2;
                        c = 0;
                        isSentError = true;
                        break;
                    }
                    sentMessages.add(message);
                    LongSparseArray<Integer> newIds2 = newIds;
                    TLRPC.Updates updates3 = updates2;
                    SparseArray<TLRPC.Message> newMessages2 = newMessages;
                    updateMediaPaths(msgObj, message, message.id, originalPath, false);
                    final int existFlags = msgObj.getMediaExistanceFlags();
                    newMsgObj.id = message.id;
                    if ((newMsgObj.flags & Integer.MIN_VALUE) != 0) {
                        message.flags |= Integer.MIN_VALUE;
                    }
                    final long grouped_id = message.grouped_id;
                    if (!scheduled) {
                        Integer value = getMessagesController().dialogs_read_outbox_max.get(Long.valueOf(message.dialog_id));
                        if (value == null) {
                            value = Integer.valueOf(getMessagesStorage().getDialogReadMax(message.out, message.dialog_id));
                            getMessagesController().dialogs_read_outbox_max.put(Long.valueOf(message.dialog_id), value);
                        }
                        message.unread = value.intValue() < message.id;
                    }
                    if (0 == 0) {
                        getStatsController().incrementSentItemsCount(ApplicationLoader.getCurrentNetworkType(), 1, 1);
                        newMsgObj.send_state = 0;
                        getNotificationCenter().postNotificationName(NotificationCenter.messageReceivedByServer, Integer.valueOf(oldId), Integer.valueOf(newMsgObj.id), newMsgObj, Long.valueOf(newMsgObj.dialog_id), Long.valueOf(grouped_id), Integer.valueOf(existFlags), Boolean.valueOf(scheduled));
                        i = i2;
                        getMessagesStorage().getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SendMessagesHelper$W5w9aWjX3Y5B_9zoutMxKjRBf38
                            @Override // java.lang.Runnable
                            public final void run() {
                                this.f$0.lambda$null$29$SendMessagesHelper(newMsgObj, oldId, scheduled, sentMessages, grouped_id, existFlags);
                            }
                        });
                    } else {
                        i = i2;
                    }
                    i2 = i + 1;
                    arrayList = originalPaths;
                    newIds = newIds2;
                    updatesArr = updatesArr2;
                    updates2 = updates3;
                    newMessages = newMessages2;
                } else {
                    updates = updates2;
                    c = 0;
                    isSentError = true;
                    break;
                }
            }
            final TLRPC.Updates updates4 = updates;
            Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SendMessagesHelper$NFMrqI0LzX030pKNLTFwoolpalM
                @Override // java.lang.Runnable
                public final void run() throws Exception {
                    this.f$0.lambda$null$30$SendMessagesHelper(updates4);
                }
            });
        } else {
            c = 0;
            AlertsCreator.processError(this.currentAccount, error, null, req, new Object[0]);
            isSentError = true;
        }
        if (isSentError) {
            for (int i3 = 0; i3 < msgObjs.size(); i3++) {
                TLRPC.Message newMsgObj2 = ((MessageObject) msgObjs.get(i3)).messageOwner;
                getMessagesStorage().markMessageAsSendError(newMsgObj2, scheduled);
                newMsgObj2.send_state = 2;
                NotificationCenter notificationCenter = getNotificationCenter();
                int i4 = NotificationCenter.messageSendError;
                Object[] objArr = new Object[1];
                objArr[c] = Integer.valueOf(newMsgObj2.id);
                notificationCenter.postNotificationName(i4, objArr);
                processSentMessage(newMsgObj2.id);
                removeFromSendingMessages(newMsgObj2.id, scheduled);
            }
        }
    }

    public /* synthetic */ void lambda$null$26$SendMessagesHelper(TLRPC.TL_updateNewMessage newMessage) {
        getMessagesController().processNewDifferenceParams(-1, newMessage.pts, -1, newMessage.pts_count);
    }

    public /* synthetic */ void lambda$null$27$SendMessagesHelper(TLRPC.TL_updateNewChannelMessage newMessage) {
        getMessagesController().processNewChannelDifferenceParams(newMessage.pts, newMessage.pts_count, newMessage.message.to_id.channel_id);
    }

    public /* synthetic */ void lambda$null$29$SendMessagesHelper(final TLRPC.Message message, final int i, final boolean z, ArrayList arrayList, final long j, final int i2) {
        getMessagesStorage().updateMessageStateAndId(message.random_id, Integer.valueOf(i), message.id, 0, false, message.to_id.channel_id, z ? 1 : 0);
        getMessagesStorage().putMessages((ArrayList<TLRPC.Message>) arrayList, true, true, false, 0, z);
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SendMessagesHelper$-MDcrzQOpkXyWMphIBWnHeOe_gQ
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$28$SendMessagesHelper(message, i, j, i2, z);
            }
        });
    }

    public /* synthetic */ void lambda$null$28$SendMessagesHelper(TLRPC.Message newMsgObj, int oldId, long grouped_id, int existFlags, boolean scheduled) {
        getMediaDataController().increasePeerRaiting(newMsgObj.dialog_id);
        getNotificationCenter().postNotificationName(NotificationCenter.messageReceivedByServer, Integer.valueOf(oldId), Integer.valueOf(newMsgObj.id), newMsgObj, Long.valueOf(newMsgObj.dialog_id), Long.valueOf(grouped_id), Integer.valueOf(existFlags), Boolean.valueOf(scheduled));
        processSentMessage(oldId);
        removeFromSendingMessages(oldId, scheduled);
    }

    public /* synthetic */ void lambda$null$30$SendMessagesHelper(TLRPC.Updates updates) throws Exception {
        getMessagesController().processUpdates(updates, false);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void performSendMessageRequest(TLObject req, MessageObject msgObj, String originalPath, DelayedMessage delayedMessage, Object parentObject, boolean scheduled) {
        performSendMessageRequest(req, msgObj, originalPath, null, false, delayedMessage, parentObject, scheduled);
    }

    private DelayedMessage findMaxDelayedMessageForMessageId(int messageId, long dialogId) {
        DelayedMessage maxDelayedMessage = null;
        int maxDalyedMessageId = Integer.MIN_VALUE;
        for (Map.Entry<String, ArrayList<DelayedMessage>> entry : this.delayedMessages.entrySet()) {
            ArrayList<DelayedMessage> messages = entry.getValue();
            int size = messages.size();
            for (int a = 0; a < size; a++) {
                DelayedMessage delayedMessage = messages.get(a);
                if ((delayedMessage.type == 4 || delayedMessage.type == 0) && delayedMessage.peer == dialogId) {
                    int mid = 0;
                    if (delayedMessage.obj != null) {
                        mid = delayedMessage.obj.getId();
                    } else if (delayedMessage.messageObjects != null && !delayedMessage.messageObjects.isEmpty()) {
                        mid = delayedMessage.messageObjects.get(delayedMessage.messageObjects.size() - 1).getId();
                    }
                    if (mid != 0 && mid > messageId && maxDelayedMessage == null && maxDalyedMessageId < mid) {
                        maxDelayedMessage = delayedMessage;
                        maxDalyedMessageId = mid;
                    }
                }
            }
        }
        return maxDelayedMessage;
    }

    protected void performSendMessageRequest(final TLObject req, final MessageObject msgObj, final String originalPath, final DelayedMessage parentMessage, final boolean check, final DelayedMessage delayedMessage, final Object parentObject, final boolean scheduled) {
        DelayedMessage maxDelayedMessage;
        if (!(req instanceof TLRPC.TL_messages_editMessage) && check && (maxDelayedMessage = findMaxDelayedMessageForMessageId(msgObj.getId(), msgObj.getDialogId())) != null) {
            maxDelayedMessage.addDelayedRequest(req, msgObj, originalPath, parentObject, delayedMessage, parentMessage != null ? parentMessage.scheduled : false);
            if (parentMessage != null && parentMessage.requests != null) {
                maxDelayedMessage.requests.addAll(parentMessage.requests);
                return;
            }
            return;
        }
        final TLRPC.Message newMsgObj = msgObj.messageOwner;
        putToSendingMessages(newMsgObj, scheduled);
        newMsgObj.reqId = getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SendMessagesHelper$dM6_gJwEwR1gTBxS2KNiIoWhgz4
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$performSendMessageRequest$44$SendMessagesHelper(req, parentObject, msgObj, originalPath, parentMessage, check, delayedMessage, scheduled, newMsgObj, tLObject, tL_error);
            }
        }, new QuickAckDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SendMessagesHelper$fXEBci5PU7vuDvmpFZSP7b_Sc4Q
            @Override // im.uwrkaxlmjj.tgnet.QuickAckDelegate
            public final void run() {
                this.f$0.lambda$performSendMessageRequest$46$SendMessagesHelper(newMsgObj);
            }
        }, (req instanceof TLRPC.TL_messages_sendMessage ? 128 : 0) | 68);
        if (parentMessage != null) {
            parentMessage.sendDelayedRequests();
        }
    }

    public /* synthetic */ void lambda$performSendMessageRequest$44$SendMessagesHelper(final TLObject req, Object parentObject, final MessageObject msgObj, final String originalPath, DelayedMessage parentMessage, boolean check, final DelayedMessage delayedMessage, final boolean scheduled, final TLRPC.Message newMsgObj, final TLObject response, final TLRPC.TL_error error) {
        if (error != null && (((req instanceof TLRPC.TL_messages_sendMedia) || (req instanceof TLRPC.TL_messages_editMessage)) && FileRefController.isFileRefError(error.text))) {
            if (parentObject != null) {
                getFileRefController().requestReference(parentObject, req, msgObj, originalPath, parentMessage, Boolean.valueOf(check), delayedMessage, Boolean.valueOf(scheduled));
                return;
            } else if (delayedMessage != null) {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.SendMessagesHelper.4
                    @Override // java.lang.Runnable
                    public void run() {
                        SendMessagesHelper.this.removeFromSendingMessages(newMsgObj.id, scheduled);
                        TLObject tLObject = req;
                        if (tLObject instanceof TLRPC.TL_messages_sendMedia) {
                            TLRPC.TL_messages_sendMedia request = (TLRPC.TL_messages_sendMedia) tLObject;
                            if ((request.media instanceof TLRPC.TL_inputMediaPhoto) || (request.media instanceof TLRPC.TL_inputMediaDocument)) {
                                request.media = delayedMessage.inputUploadMedia;
                            }
                        } else if (tLObject instanceof TLRPC.TL_messages_editMessage) {
                            TLRPC.TL_messages_editMessage request2 = (TLRPC.TL_messages_editMessage) tLObject;
                            if ((request2.media instanceof TLRPC.TL_inputMediaPhoto) || (request2.media instanceof TLRPC.TL_inputMediaDocument)) {
                                request2.media = delayedMessage.inputUploadMedia;
                            }
                        }
                        delayedMessage.performMediaUpload = true;
                        SendMessagesHelper.this.performSendDelayedMessage(delayedMessage);
                    }
                });
                return;
            }
        }
        if (req instanceof TLRPC.TL_messages_editMessage) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SendMessagesHelper$40tpIAuyiTadxxdWFJAAGbRq_bs
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$35$SendMessagesHelper(error, newMsgObj, response, msgObj, originalPath, scheduled, req);
                }
            });
        } else {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SendMessagesHelper$hxKWiesfzq6fx1qGN4gUoN7givg
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$43$SendMessagesHelper(error, newMsgObj, response, msgObj, scheduled, originalPath, req);
                }
            });
        }
    }

    public /* synthetic */ void lambda$null$35$SendMessagesHelper(TLRPC.TL_error error, final TLRPC.Message newMsgObj, TLObject response, MessageObject msgObj, String originalPath, final boolean scheduled, TLObject req) {
        TLRPC.Message message;
        if (error == null) {
            String attachPath = newMsgObj.attachPath;
            final TLRPC.Updates updates = (TLRPC.Updates) response;
            ArrayList<TLRPC.Update> updatesArr = ((TLRPC.Updates) response).updates;
            int a = 0;
            while (true) {
                if (a >= updatesArr.size()) {
                    message = null;
                    break;
                }
                TLRPC.Update update = updatesArr.get(a);
                if (update instanceof TLRPC.TL_updateEditMessage) {
                    TLRPC.TL_updateEditMessage newMessage = (TLRPC.TL_updateEditMessage) update;
                    TLRPC.Message message2 = newMessage.message;
                    message = message2;
                    break;
                } else if (update instanceof TLRPC.TL_updateEditChannelMessage) {
                    TLRPC.TL_updateEditChannelMessage newMessage2 = (TLRPC.TL_updateEditChannelMessage) update;
                    TLRPC.Message message3 = newMessage2.message;
                    message = message3;
                    break;
                } else if (!(update instanceof TLRPC.TL_updateNewScheduledMessage)) {
                    a++;
                } else {
                    TLRPC.TL_updateNewScheduledMessage newMessage3 = (TLRPC.TL_updateNewScheduledMessage) update;
                    TLRPC.Message message4 = newMessage3.message;
                    message = message4;
                    break;
                }
            }
            if (message != null) {
                ImageLoader.saveMessageThumbs(message);
                updateMediaPaths(msgObj, message, message.id, originalPath, false);
            }
            Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SendMessagesHelper$izAiO2hc6MjzlFH6YWIJvnuR6WM
                @Override // java.lang.Runnable
                public final void run() throws Exception {
                    this.f$0.lambda$null$34$SendMessagesHelper(updates, newMsgObj, scheduled);
                }
            });
            if (MessageObject.isVideoMessage(newMsgObj) || MessageObject.isRoundVideoMessage(newMsgObj) || MessageObject.isNewGifMessage(newMsgObj)) {
                stopVideoService(attachPath);
            }
            return;
        }
        AlertsCreator.processError(this.currentAccount, error, null, req, new Object[0]);
        if (MessageObject.isVideoMessage(newMsgObj) || MessageObject.isRoundVideoMessage(newMsgObj) || MessageObject.isNewGifMessage(newMsgObj)) {
            stopVideoService(newMsgObj.attachPath);
        }
        removeFromSendingMessages(newMsgObj.id, scheduled);
        revertEditingMessageObject(msgObj);
    }

    public /* synthetic */ void lambda$null$34$SendMessagesHelper(TLRPC.Updates updates, final TLRPC.Message newMsgObj, final boolean scheduled) throws Exception {
        getMessagesController().processUpdates(updates, false);
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SendMessagesHelper$kpApe0mqyUijKg2SZLeYEl7Ko9g
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$33$SendMessagesHelper(newMsgObj, scheduled);
            }
        });
    }

    public /* synthetic */ void lambda$null$33$SendMessagesHelper(TLRPC.Message newMsgObj, boolean scheduled) {
        processSentMessage(newMsgObj.id);
        removeFromSendingMessages(newMsgObj.id, scheduled);
    }

    public /* synthetic */ void lambda$null$43$SendMessagesHelper(TLRPC.TL_error error, final TLRPC.Message newMsgObj, TLObject response, MessageObject msgObj, final boolean scheduled, String originalPath, TLObject req) {
        boolean isSentError;
        String attachPath;
        ArrayList<TLRPC.Message> sentMessages;
        int existFlags;
        TLRPC.Message message;
        int existFlags2;
        TLRPC.Message message2;
        TLRPC.Message message3;
        boolean isSentError2 = false;
        if (error == null) {
            final int oldId = newMsgObj.id;
            ArrayList<TLRPC.Message> sentMessages2 = new ArrayList<>();
            String attachPath2 = newMsgObj.attachPath;
            if (response instanceof TLRPC.TL_updateShortSentMessage) {
                final TLRPC.TL_updateShortSentMessage res = (TLRPC.TL_updateShortSentMessage) response;
                attachPath = attachPath2;
                sentMessages = sentMessages2;
                updateMediaPaths(msgObj, null, res.id, null, false);
                int existFlags3 = msgObj.getMediaExistanceFlags();
                int i = res.id;
                newMsgObj.id = i;
                newMsgObj.local_id = i;
                newMsgObj.date = res.date;
                newMsgObj.entities = res.entities;
                newMsgObj.out = res.out;
                if (res.media != null) {
                    newMsgObj.media = res.media;
                    newMsgObj.flags |= 512;
                    ImageLoader.saveMessageThumbs(newMsgObj);
                }
                if ((res.media instanceof TLRPC.TL_messageMediaGame) && !TextUtils.isEmpty(res.message)) {
                    newMsgObj.message = res.message;
                }
                if (!newMsgObj.entities.isEmpty()) {
                    newMsgObj.flags |= 128;
                }
                Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SendMessagesHelper$ItEJ16LEDdiTnJDQx4TBLtP1teo
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$36$SendMessagesHelper(res);
                    }
                });
                sentMessages.add(newMsgObj);
                existFlags = existFlags3;
                isSentError = false;
            } else {
                attachPath = attachPath2;
                sentMessages = sentMessages2;
                if (response instanceof TLRPC.Updates) {
                    final TLRPC.Updates updates = (TLRPC.Updates) response;
                    ArrayList<TLRPC.Update> updatesArr = ((TLRPC.Updates) response).updates;
                    int a = 0;
                    while (true) {
                        if (a >= updatesArr.size()) {
                            message = null;
                            break;
                        }
                        TLRPC.Update update = updatesArr.get(a);
                        if (update instanceof TLRPC.TL_updateNewMessage) {
                            final TLRPC.TL_updateNewMessage newMessage = (TLRPC.TL_updateNewMessage) update;
                            TLRPC.Message message4 = newMessage.message;
                            sentMessages.add(message4);
                            Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SendMessagesHelper$QtCNlndXUN2eBaa3J3Fls65t20Q
                                @Override // java.lang.Runnable
                                public final void run() {
                                    this.f$0.lambda$null$37$SendMessagesHelper(newMessage);
                                }
                            });
                            updatesArr.remove(a);
                            message = message4;
                            break;
                        }
                        if (update instanceof TLRPC.TL_updateNewChannelMessage) {
                            final TLRPC.TL_updateNewChannelMessage newMessage2 = (TLRPC.TL_updateNewChannelMessage) update;
                            TLRPC.Message message5 = newMessage2.message;
                            sentMessages.add(message5);
                            if ((newMsgObj.flags & Integer.MIN_VALUE) == 0) {
                                message2 = message5;
                            } else {
                                message2 = message5;
                                newMessage2.message.flags |= Integer.MIN_VALUE;
                            }
                            Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SendMessagesHelper$dM8Crl0ubqGByuWlIBtVZlSRab0
                                @Override // java.lang.Runnable
                                public final void run() {
                                    this.f$0.lambda$null$38$SendMessagesHelper(newMessage2);
                                }
                            });
                            updatesArr.remove(a);
                            message = message2;
                        } else if (!(update instanceof TLRPC.TL_updateNewScheduledMessage)) {
                            a++;
                        } else {
                            TLRPC.TL_updateNewScheduledMessage newMessage3 = (TLRPC.TL_updateNewScheduledMessage) update;
                            TLRPC.Message message6 = newMessage3.message;
                            sentMessages.add(message6);
                            if ((newMsgObj.flags & Integer.MIN_VALUE) == 0) {
                                message3 = message6;
                            } else {
                                message3 = message6;
                                newMessage3.message.flags |= Integer.MIN_VALUE;
                            }
                            updatesArr.remove(a);
                            message = message3;
                        }
                    }
                    if (message != null) {
                        ImageLoader.saveMessageThumbs(message);
                        if (!scheduled) {
                            Integer value = getMessagesController().dialogs_read_outbox_max.get(Long.valueOf(message.dialog_id));
                            if (value == null) {
                                value = Integer.valueOf(getMessagesStorage().getDialogReadMax(message.out, message.dialog_id));
                                getMessagesController().dialogs_read_outbox_max.put(Long.valueOf(message.dialog_id), value);
                            }
                            message.unread = value.intValue() < message.id;
                        }
                        updateMediaPaths(msgObj, message, message.id, originalPath, false);
                        existFlags2 = msgObj.getMediaExistanceFlags();
                        newMsgObj.id = message.id;
                        if (newMsgObj.message != null && message.message != null) {
                            newMsgObj.message = message.message;
                            final TLRPC.Message finalMessage = message;
                            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SendMessagesHelper$7Lx8oiqfTkZcZZfUXP2QvPIJFhw
                                @Override // java.lang.Runnable
                                public final void run() {
                                    this.f$0.lambda$null$39$SendMessagesHelper(finalMessage);
                                }
                            });
                        }
                    } else {
                        isSentError2 = true;
                        existFlags2 = 0;
                    }
                    Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SendMessagesHelper$Eq3FbNWEdnjL1N6p-22V2_qr6F8
                        @Override // java.lang.Runnable
                        public final void run() throws Exception {
                            this.f$0.lambda$null$40$SendMessagesHelper(updates);
                        }
                    });
                    existFlags = existFlags2;
                    isSentError = isSentError2;
                } else {
                    existFlags = 0;
                    isSentError = false;
                }
            }
            if (MessageObject.isLiveLocationMessage(newMsgObj)) {
                getLocationController().addSharingLocation(newMsgObj.dialog_id, newMsgObj.id, newMsgObj.media.period, newMsgObj);
            }
            if (!isSentError) {
                getStatsController().incrementSentItemsCount(ApplicationLoader.getCurrentNetworkType(), 1, 1);
                newMsgObj.send_state = 0;
                getNotificationCenter().postNotificationName(NotificationCenter.messageReceivedByServer, Integer.valueOf(oldId), Integer.valueOf(newMsgObj.id), newMsgObj, Long.valueOf(newMsgObj.dialog_id), 0L, Integer.valueOf(existFlags), Boolean.valueOf(scheduled));
                final ArrayList<TLRPC.Message> arrayList = sentMessages;
                final int i2 = existFlags;
                final String str = attachPath;
                getMessagesStorage().getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SendMessagesHelper$J9BMUTzDGEH33XjwXSBOsz_d8hs
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$42$SendMessagesHelper(newMsgObj, oldId, scheduled, arrayList, i2, str);
                    }
                });
            }
        } else {
            AlertsCreator.processError(this.currentAccount, error, null, req, new Object[0]);
            isSentError = true;
        }
        if (isSentError) {
            getMessagesStorage().markMessageAsSendError(newMsgObj, scheduled);
            newMsgObj.send_state = 2;
            getNotificationCenter().postNotificationName(NotificationCenter.messageSendError, Integer.valueOf(newMsgObj.id));
            processSentMessage(newMsgObj.id);
            if (MessageObject.isVideoMessage(newMsgObj) || MessageObject.isRoundVideoMessage(newMsgObj) || MessageObject.isNewGifMessage(newMsgObj)) {
                stopVideoService(newMsgObj.attachPath);
            }
            removeFromSendingMessages(newMsgObj.id, scheduled);
        }
    }

    public /* synthetic */ void lambda$null$36$SendMessagesHelper(TLRPC.TL_updateShortSentMessage res) {
        getMessagesController().processNewDifferenceParams(-1, res.pts, res.date, res.pts_count);
    }

    public /* synthetic */ void lambda$null$37$SendMessagesHelper(TLRPC.TL_updateNewMessage newMessage) {
        getMessagesController().processNewDifferenceParams(-1, newMessage.pts, -1, newMessage.pts_count);
    }

    public /* synthetic */ void lambda$null$38$SendMessagesHelper(TLRPC.TL_updateNewChannelMessage newMessage) {
        getMessagesController().processNewChannelDifferenceParams(newMessage.pts, newMessage.pts_count, newMessage.message.to_id.channel_id);
    }

    public /* synthetic */ void lambda$null$39$SendMessagesHelper(TLRPC.Message finalMessage) {
        getNotificationCenter().postNotificationName(NotificationCenter.updateChatNewmsgMentionText, finalMessage);
    }

    public /* synthetic */ void lambda$null$40$SendMessagesHelper(TLRPC.Updates updates) throws Exception {
        getMessagesController().processUpdates(updates, false);
    }

    public /* synthetic */ void lambda$null$42$SendMessagesHelper(final TLRPC.Message message, final int i, final boolean z, ArrayList arrayList, final int i2, String str) {
        getMessagesStorage().updateMessageStateAndId(message.random_id, Integer.valueOf(i), message.id, 0, false, message.to_id.channel_id, z ? 1 : 0);
        getMessagesStorage().putMessages((ArrayList<TLRPC.Message>) arrayList, true, true, false, 0, z);
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SendMessagesHelper$OYdjXSM3DDRxRrE1ZyDuCCLBpNQ
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$41$SendMessagesHelper(message, i, i2, z);
            }
        });
        if (MessageObject.isVideoMessage(message) || MessageObject.isRoundVideoMessage(message) || MessageObject.isNewGifMessage(message)) {
            stopVideoService(str);
        }
    }

    public /* synthetic */ void lambda$null$41$SendMessagesHelper(TLRPC.Message newMsgObj, int oldId, int existFlags, boolean scheduled) {
        getMediaDataController().increasePeerRaiting(newMsgObj.dialog_id);
        getNotificationCenter().postNotificationName(NotificationCenter.messageReceivedByServer, Integer.valueOf(oldId), Integer.valueOf(newMsgObj.id), newMsgObj, Long.valueOf(newMsgObj.dialog_id), 0L, Integer.valueOf(existFlags), Boolean.valueOf(scheduled));
        processSentMessage(oldId);
        removeFromSendingMessages(oldId, scheduled);
    }

    public /* synthetic */ void lambda$performSendMessageRequest$46$SendMessagesHelper(final TLRPC.Message newMsgObj) {
        final int msg_id = newMsgObj.id;
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SendMessagesHelper$v1NSV6qzkWlz3MXTwwYrQ6HQ6gQ
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$45$SendMessagesHelper(newMsgObj, msg_id);
            }
        });
    }

    public /* synthetic */ void lambda$null$45$SendMessagesHelper(TLRPC.Message newMsgObj, int msg_id) {
        newMsgObj.send_state = 0;
        getNotificationCenter().postNotificationName(NotificationCenter.messageReceivedByAck, Integer.valueOf(msg_id));
    }

    private void updateMediaPaths(MessageObject newMsgObj, TLRPC.Message sentMessage, int newMsgId, String originalPath, boolean post) {
        String str;
        byte[] oldWaveform;
        File cacheFile2;
        TLRPC.Message newMsg = newMsgObj.messageOwner;
        if (newMsg.media != null) {
            TLRPC.PhotoSize strippedOld = null;
            TLRPC.PhotoSize strippedNew = null;
            TLObject photoObject = null;
            if (newMsg.media.photo != null) {
                strippedOld = FileLoader.getClosestPhotoSizeWithSize(newMsg.media.photo.sizes, 40);
                if (sentMessage != null && sentMessage.media != null && sentMessage.media.photo != null) {
                    strippedNew = FileLoader.getClosestPhotoSizeWithSize(sentMessage.media.photo.sizes, 40);
                } else {
                    strippedNew = strippedOld;
                }
                photoObject = newMsg.media.photo;
            } else if (newMsg.media.document != null) {
                strippedOld = FileLoader.getClosestPhotoSizeWithSize(newMsg.media.document.thumbs, 40);
                if (sentMessage != null && sentMessage.media != null && sentMessage.media.document != null) {
                    strippedNew = FileLoader.getClosestPhotoSizeWithSize(sentMessage.media.document.thumbs, 40);
                } else {
                    strippedNew = strippedOld;
                }
                photoObject = newMsg.media.document;
            } else if (newMsg.media.webpage != null) {
                if (newMsg.media.webpage.photo != null) {
                    strippedOld = FileLoader.getClosestPhotoSizeWithSize(newMsg.media.webpage.photo.sizes, 40);
                    if (sentMessage != null && sentMessage.media != null && sentMessage.media.webpage != null && sentMessage.media.webpage.photo != null) {
                        strippedNew = FileLoader.getClosestPhotoSizeWithSize(sentMessage.media.webpage.photo.sizes, 40);
                    } else {
                        strippedNew = strippedOld;
                    }
                    photoObject = newMsg.media.webpage.photo;
                } else if (newMsg.media.webpage.document != null) {
                    strippedOld = FileLoader.getClosestPhotoSizeWithSize(newMsg.media.webpage.document.thumbs, 40);
                    if (sentMessage != null && sentMessage.media != null && sentMessage.media.webpage != null && sentMessage.media.webpage.document != null) {
                        strippedNew = FileLoader.getClosestPhotoSizeWithSize(sentMessage.media.webpage.document.thumbs, 40);
                    } else {
                        strippedNew = strippedOld;
                    }
                    photoObject = newMsg.media.webpage.document;
                }
            }
            if ((strippedNew instanceof TLRPC.TL_photoStrippedSize) && (strippedOld instanceof TLRPC.TL_photoStrippedSize)) {
                String oldKey = "stripped" + FileRefController.getKeyForParentObject(newMsgObj);
                String newKey = sentMessage != null ? "stripped" + FileRefController.getKeyForParentObject(sentMessage) : "strippedmessage" + newMsgId + "_" + newMsgObj.getChannelId();
                ImageLoader.getInstance().replaceImageInCache(oldKey, newKey, ImageLocation.getForObject(strippedNew, photoObject), post);
            }
        }
        if (sentMessage == null) {
            return;
        }
        long j = -2147483648L;
        if ((sentMessage.media instanceof TLRPC.TL_messageMediaPhoto) && sentMessage.media.photo != null && (newMsg.media instanceof TLRPC.TL_messageMediaPhoto) && newMsg.media.photo != null) {
            if (sentMessage.media.ttl_seconds == 0 && !newMsgObj.scheduled) {
                getMessagesStorage().putSentFile(originalPath, sentMessage.media.photo, 0, "sent_" + sentMessage.to_id.channel_id + "_" + sentMessage.id);
            }
            if (newMsg.media.photo.sizes.size() == 1 && (newMsg.media.photo.sizes.get(0).location instanceof TLRPC.TL_fileLocationUnavailable)) {
                newMsg.media.photo.sizes = sentMessage.media.photo.sizes;
            } else {
                int a = 0;
                while (a < sentMessage.media.photo.sizes.size()) {
                    TLRPC.PhotoSize size = sentMessage.media.photo.sizes.get(a);
                    if (size != null && size.location != null && !(size instanceof TLRPC.TL_photoSizeEmpty) && size.type != null) {
                        int b = 0;
                        while (b < newMsg.media.photo.sizes.size()) {
                            TLRPC.PhotoSize size2 = newMsg.media.photo.sizes.get(b);
                            if (size2 == null || size2.location == null || size2.type == null || ((size2.location.volume_id != j || !size.type.equals(size2.type)) && (size.w != size2.w || size.h != size2.h))) {
                                b++;
                                j = -2147483648L;
                            } else {
                                String fileName = size2.location.volume_id + "_" + size2.location.local_id;
                                String fileName2 = size.location.volume_id + "_" + size.location.local_id;
                                if (!fileName.equals(fileName2)) {
                                    File cacheFile = new File(FileLoader.getDirectory(4), fileName + ".jpg");
                                    if (sentMessage.media.ttl_seconds == 0 && (sentMessage.media.photo.sizes.size() == 1 || size.w > 90 || size.h > 90)) {
                                        cacheFile2 = FileLoader.getPathToAttach(size);
                                    } else {
                                        cacheFile2 = new File(FileLoader.getDirectory(4), fileName2 + ".jpg");
                                    }
                                    cacheFile.renameTo(cacheFile2);
                                    ImageLoader.getInstance().replaceImageInCache(fileName, fileName2, ImageLocation.getForPhoto(size, sentMessage.media.photo), post);
                                    size2.location = size.location;
                                    size2.size = size.size;
                                }
                            }
                        }
                    }
                    a++;
                    j = -2147483648L;
                }
            }
            sentMessage.message = newMsg.message;
            sentMessage.attachPath = newMsg.attachPath;
            newMsg.media.photo.id = sentMessage.media.photo.id;
            newMsg.media.photo.access_hash = sentMessage.media.photo.access_hash;
            return;
        }
        if ((sentMessage.media instanceof TLRPC.TL_messageMediaDocument) && sentMessage.media.document != null && (newMsg.media instanceof TLRPC.TL_messageMediaDocument) && newMsg.media.document != null) {
            if (sentMessage.media.ttl_seconds != 0) {
                str = originalPath;
            } else {
                boolean isVideo = MessageObject.isVideoMessage(sentMessage);
                if ((!isVideo && !MessageObject.isGifMessage(sentMessage)) || MessageObject.isGifDocument(sentMessage.media.document) != MessageObject.isGifDocument(newMsg.media.document)) {
                    str = originalPath;
                    if (!MessageObject.isVoiceMessage(sentMessage) && !MessageObject.isRoundVideoMessage(sentMessage) && !newMsgObj.scheduled) {
                        getMessagesStorage().putSentFile(str, sentMessage.media.document, 1, "sent_" + sentMessage.to_id.channel_id + "_" + sentMessage.id);
                    }
                } else {
                    if (newMsgObj.scheduled) {
                        str = originalPath;
                    } else {
                        str = originalPath;
                        getMessagesStorage().putSentFile(str, sentMessage.media.document, 2, "sent_" + sentMessage.to_id.channel_id + "_" + sentMessage.id);
                    }
                    if (isVideo) {
                        sentMessage.attachPath = newMsg.attachPath;
                    }
                }
            }
            TLRPC.PhotoSize size22 = FileLoader.getClosestPhotoSizeWithSize(newMsg.media.document.thumbs, 320);
            TLRPC.PhotoSize size3 = FileLoader.getClosestPhotoSizeWithSize(sentMessage.media.document.thumbs, 320);
            if (size22 != null && size22.location != null && size22.location.volume_id == -2147483648L && size3 != null && size3.location != null && !(size3 instanceof TLRPC.TL_photoSizeEmpty) && !(size22 instanceof TLRPC.TL_photoSizeEmpty)) {
                String fileName3 = size22.location.volume_id + "_" + size22.location.local_id;
                String fileName22 = size3.location.volume_id + "_" + size3.location.local_id;
                if (!fileName3.equals(fileName22)) {
                    new File(FileLoader.getDirectory(4), fileName3 + ".jpg").renameTo(new File(FileLoader.getDirectory(4), fileName22 + ".jpg"));
                    ImageLoader.getInstance().replaceImageInCache(fileName3, fileName22, ImageLocation.getForDocument(size3, sentMessage.media.document), post);
                    size22.location = size3.location;
                    size22.size = size3.size;
                }
            } else if (size22 != null && MessageObject.isStickerMessage(sentMessage) && size22.location != null) {
                size3.location = size22.location;
            } else if (size22 == null || ((size22 != null && (size22.location instanceof TLRPC.TL_fileLocationUnavailable)) || (size22 instanceof TLRPC.TL_photoSizeEmpty))) {
                newMsg.media.document.thumbs = sentMessage.media.document.thumbs;
            }
            newMsg.media.document.dc_id = sentMessage.media.document.dc_id;
            newMsg.media.document.id = sentMessage.media.document.id;
            newMsg.media.document.access_hash = sentMessage.media.document.access_hash;
            int a2 = 0;
            while (true) {
                if (a2 >= newMsg.media.document.attributes.size()) {
                    oldWaveform = null;
                    break;
                }
                TLRPC.DocumentAttribute attribute = newMsg.media.document.attributes.get(a2);
                if (!(attribute instanceof TLRPC.TL_documentAttributeAudio)) {
                    a2++;
                } else {
                    byte[] oldWaveform2 = attribute.waveform;
                    oldWaveform = oldWaveform2;
                    break;
                }
            }
            newMsg.media.document.attributes = sentMessage.media.document.attributes;
            if (oldWaveform != null) {
                for (int a3 = 0; a3 < newMsg.media.document.attributes.size(); a3++) {
                    TLRPC.DocumentAttribute attribute2 = newMsg.media.document.attributes.get(a3);
                    if (attribute2 instanceof TLRPC.TL_documentAttributeAudio) {
                        attribute2.waveform = oldWaveform;
                        attribute2.flags |= 4;
                    }
                }
            }
            newMsg.media.document.size = sentMessage.media.document.size;
            newMsg.media.document.mime_type = sentMessage.media.document.mime_type;
            if ((sentMessage.flags & 4) == 0 && MessageObject.isOut(sentMessage)) {
                if (MessageObject.isNewGifDocument(sentMessage.media.document)) {
                    getMediaDataController().addRecentGif(sentMessage.media.document, sentMessage.date);
                } else if (MessageObject.isStickerDocument(sentMessage.media.document) || MessageObject.isAnimatedStickerDocument(sentMessage.media.document)) {
                    getMediaDataController().addRecentSticker(0, sentMessage, sentMessage.media.document, sentMessage.date, false);
                }
            }
            if (newMsg.attachPath != null && newMsg.attachPath.startsWith(FileLoader.getDirectory(4).getAbsolutePath())) {
                File cacheFile3 = new File(newMsg.attachPath);
                File cacheFile22 = FileLoader.getPathToAttach(sentMessage.media.document, sentMessage.media.ttl_seconds != 0);
                if (!cacheFile3.renameTo(cacheFile22)) {
                    if (cacheFile3.exists()) {
                        sentMessage.attachPath = newMsg.attachPath;
                    } else {
                        newMsgObj.attachPathExists = false;
                    }
                    newMsgObj.mediaExists = cacheFile22.exists();
                    sentMessage.message = newMsg.message;
                    return;
                }
                if (MessageObject.isVideoMessage(sentMessage)) {
                    newMsgObj.attachPathExists = true;
                    return;
                }
                newMsgObj.mediaExists = newMsgObj.attachPathExists;
                newMsgObj.attachPathExists = false;
                newMsg.attachPath = "";
                if (str != null && str.startsWith("http")) {
                    getMessagesStorage().addRecentLocalFile(str, cacheFile22.toString(), newMsg.media.document);
                    return;
                }
                return;
            }
            sentMessage.attachPath = newMsg.attachPath;
            sentMessage.message = newMsg.message;
            return;
        }
        if ((sentMessage.media instanceof TLRPC.TL_messageMediaContact) && (newMsg.media instanceof TLRPC.TL_messageMediaContact)) {
            newMsg.media = sentMessage.media;
            return;
        }
        if (sentMessage.media instanceof TLRPC.TL_messageMediaWebPage) {
            newMsg.media = sentMessage.media;
            return;
        }
        if (sentMessage.media instanceof TLRPC.TL_messageMediaGeo) {
            sentMessage.media.geo.lat = newMsg.media.geo.lat;
            sentMessage.media.geo._long = newMsg.media.geo._long;
            return;
        }
        if (sentMessage.media instanceof TLRPC.TL_messageMediaGame) {
            newMsg.media = sentMessage.media;
            if ((newMsg.media instanceof TLRPC.TL_messageMediaGame) && !TextUtils.isEmpty(sentMessage.message)) {
                newMsg.entities = sentMessage.entities;
                newMsg.message = sentMessage.message;
                return;
            }
            return;
        }
        if (sentMessage.media instanceof TLRPC.TL_messageMediaPoll) {
            newMsg.media = sentMessage.media;
        }
    }

    private void putToDelayedMessages(String location, DelayedMessage message) {
        ArrayList<DelayedMessage> arrayList = this.delayedMessages.get(location);
        if (arrayList == null) {
            arrayList = new ArrayList<>();
            this.delayedMessages.put(location, arrayList);
        }
        arrayList.add(message);
    }

    protected ArrayList<DelayedMessage> getDelayedMessages(String location) {
        return this.delayedMessages.get(location);
    }

    public long getNextRandomId() {
        long val = 0;
        while (val == 0) {
            val = Utilities.random.nextLong();
        }
        return val;
    }

    public void checkUnsentMessages() {
        getMessagesStorage().getUnsentMessages(1000);
    }

    protected void processUnsentMessages(final ArrayList<TLRPC.Message> messages, final ArrayList<TLRPC.Message> scheduledMessages, final ArrayList<TLRPC.User> users, final ArrayList<TLRPC.Chat> chats, final ArrayList<TLRPC.EncryptedChat> encryptedChats) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SendMessagesHelper$2F4EV4lhKZfbCEEdT55kuQqirFk
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$processUnsentMessages$47$SendMessagesHelper(users, chats, encryptedChats, messages, scheduledMessages);
            }
        });
    }

    public /* synthetic */ void lambda$processUnsentMessages$47$SendMessagesHelper(ArrayList users, ArrayList chats, ArrayList encryptedChats, ArrayList messages, ArrayList scheduledMessages) {
        getMessagesController().putUsers(users, true);
        getMessagesController().putChats(chats, true);
        getMessagesController().putEncryptedChats(encryptedChats, true);
        for (int a = 0; a < messages.size(); a++) {
            retrySendMessage(new MessageObject(this.currentAccount, (TLRPC.Message) messages.get(a), false), true);
        }
        if (scheduledMessages != null) {
            for (int a2 = 0; a2 < scheduledMessages.size(); a2++) {
                MessageObject messageObject = new MessageObject(this.currentAccount, (TLRPC.Message) scheduledMessages.get(a2), false);
                messageObject.scheduled = true;
                retrySendMessage(messageObject, true);
            }
        }
    }

    public TLRPC.TL_photo generatePhotoSizes(String path, Uri imageUri, boolean blnOriginalImg) {
        return generatePhotoSizes(null, path, imageUri, blnOriginalImg);
    }

    public TLRPC.TL_photo generatePhotoSizes(TLRPC.TL_photo photo, String path, Uri imageUri, boolean blnOriginalImg) throws FileNotFoundException {
        Bitmap bitmap;
        boolean isPng;
        TLRPC.PhotoSize size;
        TLRPC.TL_photo photo2;
        Bitmap bitmap2 = ImageLoader.loadBitmap(path, imageUri, AndroidUtilities.getPhotoSize(), AndroidUtilities.getPhotoSize(), true);
        if (bitmap2 == null) {
            bitmap = ImageLoader.loadBitmap(path, imageUri, 800.0f, 800.0f, true);
        } else {
            bitmap = bitmap2;
        }
        if (path != null) {
            boolean isPng2 = path.endsWith(".png");
            isPng = isPng2;
        } else {
            isPng = false;
        }
        ArrayList<TLRPC.PhotoSize> sizes = new ArrayList<>();
        TLRPC.PhotoSize size2 = ImageLoader.scaleAndSaveImage(bitmap, 90.0f, 90.0f, 55, true, isPng);
        if (size2 != null) {
            sizes.add(size2);
        }
        if (blnOriginalImg) {
            try {
                size = ImageLoader.SaveImageWithOriginalInternal(null, path, false);
            } catch (Throwable e) {
                FileLog.e(e);
                ImageLoader.getInstance().clearMemory();
                System.gc();
                try {
                    size = ImageLoader.SaveImageWithOriginalInternal(null, path, false);
                } catch (Throwable e2) {
                    FileLog.e(e2);
                    size = null;
                }
            }
        } else {
            size = ImageLoader.scaleAndSaveImage(bitmap, AndroidUtilities.getPhotoSize(), AndroidUtilities.getPhotoSize(), 80, false, 101, 101, isPng);
        }
        if (size != null) {
            sizes.add(size);
        }
        if (bitmap != null) {
            bitmap.recycle();
        }
        if (sizes.isEmpty()) {
            return null;
        }
        getUserConfig().saveConfig(false);
        if (photo != null) {
            photo2 = photo;
        } else {
            photo2 = new TLRPC.TL_photo();
        }
        photo2.date = getConnectionsManager().getCurrentTime();
        photo2.sizes = sizes;
        photo2.file_reference = new byte[0];
        return photo2;
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    /* JADX WARN: Removed duplicated region for block: B:199:0x0388  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private static boolean prepareSendingDocumentInternal(final im.uwrkaxlmjj.messenger.AccountInstance r46, java.lang.String r47, java.lang.String r48, android.net.Uri r49, java.lang.String r50, final long r51, final im.uwrkaxlmjj.messenger.MessageObject r53, java.lang.CharSequence r54, final java.util.ArrayList<im.uwrkaxlmjj.tgnet.TLRPC.MessageEntity> r55, final im.uwrkaxlmjj.messenger.MessageObject r56, boolean r57, final boolean r58, final int r59) throws java.lang.Throwable {
        /*
            Method dump skipped, instruction units count: 1430
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.SendMessagesHelper.prepareSendingDocumentInternal(im.uwrkaxlmjj.messenger.AccountInstance, java.lang.String, java.lang.String, android.net.Uri, java.lang.String, long, im.uwrkaxlmjj.messenger.MessageObject, java.lang.CharSequence, java.util.ArrayList, im.uwrkaxlmjj.messenger.MessageObject, boolean, boolean, int):boolean");
    }

    static /* synthetic */ void lambda$prepareSendingDocumentInternal$48(MessageObject editingMessageObject, AccountInstance accountInstance, TLRPC.TL_document documentFinal, String pathFinal, HashMap params, String parentFinal, long dialog_id, MessageObject reply_to_msg, String captionFinal, ArrayList entities, boolean notify, int scheduleDate) {
        if (editingMessageObject != null) {
            accountInstance.getSendMessagesHelper().editMessageMedia(editingMessageObject, null, null, documentFinal, pathFinal, params, false, parentFinal);
        } else {
            accountInstance.getSendMessagesHelper().sendMessage(documentFinal, null, pathFinal, dialog_id, reply_to_msg, captionFinal, entities, null, params, notify, scheduleDate, 0, parentFinal);
        }
    }

    public static void prepareSendingDocument(AccountInstance accountInstance, String path, String originalPath, Uri uri, String caption, String mine, long dialog_id, MessageObject reply_to_msg, InputContentInfoCompat inputContent, MessageObject editingMessageObject, boolean notify, int scheduleDate) {
        ArrayList<Uri> uris;
        if ((path == null || originalPath == null) && uri == null) {
            return;
        }
        ArrayList<String> paths = new ArrayList<>();
        ArrayList<String> originalPaths = new ArrayList<>();
        if (uri == null) {
            uris = null;
        } else {
            ArrayList<Uri> uris2 = new ArrayList<>();
            uris2.add(uri);
            uris = uris2;
        }
        if (path != null) {
            paths.add(path);
            originalPaths.add(originalPath);
        }
        prepareSendingDocuments(accountInstance, paths, originalPaths, uris, caption, mine, dialog_id, reply_to_msg, inputContent, editingMessageObject, notify, scheduleDate);
    }

    public static void prepareSendingAudioDocuments(final AccountInstance accountInstance, final ArrayList<MessageObject> messageObjects, final long dialog_id, final MessageObject reply_to_msg, final MessageObject editingMessageObject, final boolean notify, final int scheduleDate) {
        new Thread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SendMessagesHelper$HsQcWwvrNA5rJ-fmKXgQaZV829o
            @Override // java.lang.Runnable
            public final void run() throws FileNotFoundException {
                SendMessagesHelper.lambda$prepareSendingAudioDocuments$50(messageObjects, dialog_id, accountInstance, editingMessageObject, reply_to_msg, notify, scheduleDate);
            }
        }).start();
    }

    /* JADX WARN: Removed duplicated region for block: B:21:0x006e  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    static /* synthetic */ void lambda$prepareSendingAudioDocuments$50(java.util.ArrayList r24, final long r25, final im.uwrkaxlmjj.messenger.AccountInstance r27, final im.uwrkaxlmjj.messenger.MessageObject r28, final im.uwrkaxlmjj.messenger.MessageObject r29, final boolean r30, final int r31) throws java.io.FileNotFoundException {
        /*
            Method dump skipped, instruction units count: 202
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.SendMessagesHelper.lambda$prepareSendingAudioDocuments$50(java.util.ArrayList, long, im.uwrkaxlmjj.messenger.AccountInstance, im.uwrkaxlmjj.messenger.MessageObject, im.uwrkaxlmjj.messenger.MessageObject, boolean, int):void");
    }

    static /* synthetic */ void lambda$null$49(MessageObject editingMessageObject, AccountInstance accountInstance, TLRPC.TL_document documentFinal, MessageObject messageObject, HashMap params, String parentFinal, long dialog_id, MessageObject reply_to_msg, boolean notify, int scheduleDate) {
        if (editingMessageObject != null) {
            accountInstance.getSendMessagesHelper().editMessageMedia(editingMessageObject, null, null, documentFinal, messageObject.messageOwner.attachPath, params, false, parentFinal);
        } else {
            accountInstance.getSendMessagesHelper().sendMessage(documentFinal, null, messageObject.messageOwner.attachPath, dialog_id, reply_to_msg, null, null, null, params, notify, scheduleDate, 0, parentFinal);
        }
    }

    public static void prepareSendingDocuments(final AccountInstance accountInstance, final ArrayList<String> paths, final ArrayList<String> originalPaths, final ArrayList<Uri> uris, final String caption, final String mime, final long dialog_id, final MessageObject reply_to_msg, final InputContentInfoCompat inputContent, final MessageObject editingMessageObject, final boolean notify, final int scheduleDate) {
        if (paths == null && originalPaths == null && uris == null) {
            return;
        }
        if (paths != null && originalPaths != null && paths.size() != originalPaths.size()) {
            return;
        }
        new Thread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SendMessagesHelper$NMF4frEAJ5Fkw4GBDLWdl7LBrjQ
            @Override // java.lang.Runnable
            public final void run() {
                SendMessagesHelper.lambda$prepareSendingDocuments$51(paths, accountInstance, originalPaths, mime, dialog_id, reply_to_msg, caption, editingMessageObject, notify, scheduleDate, uris, inputContent);
            }
        }).start();
    }

    static /* synthetic */ void lambda$prepareSendingDocuments$51(ArrayList paths, AccountInstance accountInstance, ArrayList originalPaths, String mime, long dialog_id, MessageObject reply_to_msg, String caption, MessageObject editingMessageObject, boolean notify, int scheduleDate, ArrayList uris, InputContentInfoCompat inputContent) {
        boolean error = false;
        if (paths != null) {
            for (int a = 0; a < paths.size(); a++) {
                if (!prepareSendingDocumentInternal(accountInstance, (String) paths.get(a), (String) originalPaths.get(a), null, mime, dialog_id, reply_to_msg, caption, null, editingMessageObject, false, notify, scheduleDate)) {
                    error = true;
                }
            }
        }
        if (uris != null) {
            for (int a2 = 0; a2 < uris.size(); a2++) {
                if (!prepareSendingDocumentInternal(accountInstance, null, null, (Uri) uris.get(a2), mime, dialog_id, reply_to_msg, caption, null, editingMessageObject, false, notify, scheduleDate)) {
                    error = true;
                }
            }
        }
        if (inputContent != null) {
            inputContent.releasePermission();
        }
        if (error) {
            ToastUtils.show(mpEIGo.juqQQs.esbSDO.R.string.UnsupportedAttachment);
        }
    }

    public static void prepareSendingPhoto(AccountInstance accountInstance, String imageFilePath, Uri imageUri, long dialog_id, MessageObject reply_to_msg, CharSequence caption, ArrayList<TLRPC.MessageEntity> entities, ArrayList<TLRPC.InputDocument> stickers, InputContentInfoCompat inputContent, int ttl, MessageObject editingMessageObject, boolean notify, int scheduleDate) {
        SendingMediaInfo info = new SendingMediaInfo();
        info.path = imageFilePath;
        info.uri = imageUri;
        if (caption != null) {
            info.caption = caption.toString();
        }
        info.entities = entities;
        info.ttl = ttl;
        if (stickers != null && !stickers.isEmpty()) {
            info.masks = new ArrayList<>(stickers);
        }
        ArrayList<SendingMediaInfo> infos = new ArrayList<>();
        infos.add(info);
        prepareSendingMedia(accountInstance, infos, dialog_id, reply_to_msg, inputContent, false, false, editingMessageObject, notify, scheduleDate, false);
    }

    public static void prepareSendingBotContextResult(final AccountInstance accountInstance, final TLRPC.BotInlineResult result, final HashMap<String, String> params, final long dialog_id, final MessageObject reply_to_msg, final boolean notify, final int scheduleDate) {
        if (result == null) {
            return;
        }
        if (result.send_message instanceof TLRPC.TL_botInlineMessageMediaAuto) {
            new Thread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SendMessagesHelper$O5-G1MLm1idi4OgUv0XS-DRvMEY
                @Override // java.lang.Runnable
                public final void run() {
                    SendMessagesHelper.lambda$prepareSendingBotContextResult$53(dialog_id, result, accountInstance, params, reply_to_msg, notify, scheduleDate);
                }
            }).run();
            return;
        }
        if (!(result.send_message instanceof TLRPC.TL_botInlineMessageText)) {
            if (!(result.send_message instanceof TLRPC.TL_botInlineMessageMediaVenue)) {
                if (result.send_message instanceof TLRPC.TL_botInlineMessageMediaGeo) {
                    if (result.send_message.period != 0) {
                        TLRPC.TL_messageMediaGeoLive location = new TLRPC.TL_messageMediaGeoLive();
                        location.period = result.send_message.period;
                        location.geo = result.send_message.geo;
                        accountInstance.getSendMessagesHelper().sendMessage(location, dialog_id, reply_to_msg, result.send_message.reply_markup, params, notify, scheduleDate);
                        return;
                    }
                    TLRPC.TL_messageMediaGeo location2 = new TLRPC.TL_messageMediaGeo();
                    location2.geo = result.send_message.geo;
                    accountInstance.getSendMessagesHelper().sendMessage(location2, dialog_id, reply_to_msg, result.send_message.reply_markup, params, notify, scheduleDate);
                    return;
                }
                if (result.send_message instanceof TLRPC.TL_botInlineMessageMediaContact) {
                    TLRPC.User user = new TLRPC.TL_user();
                    user.phone = result.send_message.phone_number;
                    user.first_name = result.send_message.first_name;
                    user.last_name = result.send_message.last_name;
                    TLRPC.TL_restrictionReason reason = new TLRPC.TL_restrictionReason();
                    reason.text = result.send_message.vcard;
                    reason.platform = "";
                    reason.reason = "";
                    user.restriction_reason.add(reason);
                    accountInstance.getSendMessagesHelper().sendMessage(user, dialog_id, reply_to_msg, result.send_message.reply_markup, params, notify, scheduleDate);
                    return;
                }
                return;
            }
            TLRPC.TL_messageMediaVenue venue = new TLRPC.TL_messageMediaVenue();
            venue.geo = result.send_message.geo;
            venue.address = result.send_message.address;
            venue.title = result.send_message.title;
            venue.provider = result.send_message.provider;
            venue.venue_id = result.send_message.venue_id;
            String str = result.send_message.venue_type;
            venue.venue_id = str;
            venue.venue_type = str;
            if (venue.venue_type == null) {
                venue.venue_type = "";
            }
            accountInstance.getSendMessagesHelper().sendMessage(venue, dialog_id, reply_to_msg, result.send_message.reply_markup, params, notify, scheduleDate);
            return;
        }
        TLRPC.WebPage webPage = null;
        if (((int) dialog_id) == 0) {
            int a = 0;
            while (true) {
                if (a >= result.send_message.entities.size()) {
                    break;
                }
                TLRPC.MessageEntity entity = result.send_message.entities.get(a);
                if (!(entity instanceof TLRPC.TL_messageEntityUrl)) {
                    a++;
                } else {
                    webPage = new TLRPC.TL_webPagePending();
                    webPage.url = result.send_message.message.substring(entity.offset, entity.offset + entity.length);
                    break;
                }
            }
        }
        accountInstance.getSendMessagesHelper().sendMessage(result.send_message.message, dialog_id, reply_to_msg, webPage, !result.send_message.no_webpage, result.send_message.entities, result.send_message.reply_markup, params, notify, scheduleDate);
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    /* JADX WARN: Removed duplicated region for block: B:63:0x013c  */
    /* JADX WARN: Removed duplicated region for block: B:95:0x0209  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    static /* synthetic */ void lambda$prepareSendingBotContextResult$53(final long r21, final im.uwrkaxlmjj.tgnet.TLRPC.BotInlineResult r23, final im.uwrkaxlmjj.messenger.AccountInstance r24, final java.util.HashMap r25, final im.uwrkaxlmjj.messenger.MessageObject r26, final boolean r27, final int r28) {
        /*
            Method dump skipped, instruction units count: 1226
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.SendMessagesHelper.lambda$prepareSendingBotContextResult$53(long, im.uwrkaxlmjj.tgnet.TLRPC$BotInlineResult, im.uwrkaxlmjj.messenger.AccountInstance, java.util.HashMap, im.uwrkaxlmjj.messenger.MessageObject, boolean, int):void");
    }

    static /* synthetic */ void lambda$null$52(TLRPC.TL_document finalDocument, AccountInstance accountInstance, String finalPathFinal, long dialog_id, MessageObject reply_to_msg, TLRPC.BotInlineResult result, HashMap params, boolean notify, int scheduleDate, TLRPC.TL_photo finalPhoto, TLRPC.TL_game finalGame) {
        if (finalDocument != null) {
            accountInstance.getSendMessagesHelper().sendMessage(finalDocument, null, finalPathFinal, dialog_id, reply_to_msg, result.send_message.message, result.send_message.entities, result.send_message.reply_markup, params, notify, scheduleDate, 0, result);
        } else if (finalPhoto != null) {
            accountInstance.getSendMessagesHelper().sendMessage(finalPhoto, result.content != null ? result.content.url : null, dialog_id, reply_to_msg, result.send_message.message, result.send_message.entities, result.send_message.reply_markup, params, notify, scheduleDate, 0, result);
        } else if (finalGame != null) {
            accountInstance.getSendMessagesHelper().sendMessage(finalGame, dialog_id, result.send_message.reply_markup, params, notify, scheduleDate);
        }
    }

    private static String getTrimmedString(String src) {
        String result = src.trim();
        if (result.length() == 0) {
            return result;
        }
        while (src.startsWith(ShellAdbUtils.COMMAND_LINE_END)) {
            src = src.substring(1);
        }
        while (src.endsWith(ShellAdbUtils.COMMAND_LINE_END)) {
            src = src.substring(0, src.length() - 1);
        }
        return src;
    }

    public static void prepareSendingText(final AccountInstance accountInstance, final String text, final long dialog_id, final boolean notify, final int scheduleDate) {
        accountInstance.getMessagesStorage().getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SendMessagesHelper$fGv0PJcBKtANQRLqta0mq5BRRIo
            @Override // java.lang.Runnable
            public final void run() {
                Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SendMessagesHelper$Op4e8CWr3BH2IHYZbsspMbCr8DQ
                    @Override // java.lang.Runnable
                    public final void run() {
                        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SendMessagesHelper$cihs3ljPCJup2nt9ha3awYaAKIs
                            @Override // java.lang.Runnable
                            public final void run() {
                                SendMessagesHelper.lambda$null$54(str, accountInstance, j, z, i);
                            }
                        });
                    }
                });
            }
        });
    }

    static /* synthetic */ void lambda$null$54(String text, AccountInstance accountInstance, long dialog_id, boolean notify, int scheduleDate) {
        String textFinal = getTrimmedString(text);
        if (textFinal.length() != 0) {
            int count = (int) Math.ceil(textFinal.length() / 4096.0f);
            for (int a = 0; a < count; a++) {
                String mess = textFinal.substring(a * 4096, Math.min((a + 1) * 4096, textFinal.length()));
                accountInstance.getSendMessagesHelper().sendMessage(mess, dialog_id, null, null, true, null, null, null, notify, scheduleDate);
            }
        }
    }

    public static void ensureMediaThumbExists(boolean isEncrypted, TLObject object, String path, Uri uri, long startTime) throws FileNotFoundException {
        Bitmap thumb;
        boolean smallExists;
        Bitmap bitmap;
        TLRPC.PhotoSize size;
        if (object instanceof TLRPC.TL_photo) {
            TLRPC.TL_photo photo = (TLRPC.TL_photo) object;
            TLRPC.PhotoSize smallSize = FileLoader.getClosestPhotoSizeWithSize(photo.sizes, 90);
            if (smallSize instanceof TLRPC.TL_photoStrippedSize) {
                smallExists = true;
            } else {
                File smallFile = FileLoader.getPathToAttach(smallSize, true);
                smallExists = smallFile.exists();
            }
            TLRPC.PhotoSize bigSize = FileLoader.getClosestPhotoSizeWithSize(photo.sizes, AndroidUtilities.getPhotoSize());
            File bigFile = FileLoader.getPathToAttach(bigSize, false);
            boolean bigExists = bigFile.exists();
            if (!smallExists || !bigExists) {
                Bitmap bitmap2 = ImageLoader.loadBitmap(path, uri, AndroidUtilities.getPhotoSize(), AndroidUtilities.getPhotoSize(), true);
                if (bitmap2 != null) {
                    bitmap = bitmap2;
                } else {
                    bitmap = ImageLoader.loadBitmap(path, uri, 800.0f, 800.0f, true);
                }
                if (!bigExists) {
                    TLRPC.PhotoSize size2 = ImageLoader.scaleAndSaveImage(bigSize, bitmap, AndroidUtilities.getPhotoSize(), AndroidUtilities.getPhotoSize(), 80, false, 101, 101, false);
                    if (size2 != bigSize) {
                        photo.sizes.add(0, size2);
                    }
                }
                if (!smallExists && (size = ImageLoader.scaleAndSaveImage(smallSize, bitmap, 90.0f, 90.0f, 55, true)) != smallSize) {
                    photo.sizes.add(0, size);
                }
                if (bitmap != null) {
                    bitmap.recycle();
                    return;
                }
                return;
            }
            return;
        }
        if (object instanceof TLRPC.TL_document) {
            TLRPC.TL_document document = (TLRPC.TL_document) object;
            if ((MessageObject.isVideoDocument(document) || MessageObject.isNewGifDocument(document)) && MessageObject.isDocumentHasThumb(document)) {
                TLRPC.PhotoSize photoSize = FileLoader.getClosestPhotoSizeWithSize(document.thumbs, 320);
                if (photoSize instanceof TLRPC.TL_photoStrippedSize) {
                    return;
                }
                File smallFile2 = FileLoader.getPathToAttach(photoSize, true);
                if (!smallFile2.exists()) {
                    Bitmap thumb2 = createVideoThumbnail(path, startTime);
                    if (thumb2 != null) {
                        thumb = thumb2;
                    } else {
                        thumb = ThumbnailUtils.createVideoThumbnail(path, 1);
                    }
                    int side = isEncrypted ? 90 : 320;
                    document.thumbs.set(0, ImageLoader.scaleAndSaveImage(photoSize, thumb, side, side, side > 90 ? 80 : 55, false));
                }
            }
        }
    }

    private static String getKeyForPhotoSize(TLRPC.PhotoSize photoSize, Bitmap[] bitmap, boolean blur) {
        int photoWidth;
        if (photoSize == null) {
            return null;
        }
        if (AndroidUtilities.isTablet()) {
            photoWidth = (int) (AndroidUtilities.getMinTabletSide() * 0.7f);
        } else {
            int maxPhotoWidth = photoSize.w;
            if (maxPhotoWidth >= photoSize.h) {
                photoWidth = Math.min(AndroidUtilities.displaySize.x, AndroidUtilities.displaySize.y) - AndroidUtilities.dp(64.0f);
            } else {
                photoWidth = (int) (Math.min(AndroidUtilities.displaySize.x, AndroidUtilities.displaySize.y) * 0.7f);
            }
        }
        int photoHeight = AndroidUtilities.dp(100.0f) + photoWidth;
        if (photoWidth > AndroidUtilities.getPhotoSize()) {
            photoWidth = AndroidUtilities.getPhotoSize();
        }
        if (photoHeight > AndroidUtilities.getPhotoSize()) {
            photoHeight = AndroidUtilities.getPhotoSize();
        }
        float scale = photoSize.w / photoWidth;
        int w = (int) (photoSize.w / scale);
        int h = (int) (photoSize.h / scale);
        if (w == 0) {
            w = AndroidUtilities.dp(150.0f);
        }
        if (h == 0) {
            h = AndroidUtilities.dp(150.0f);
        }
        if (h > photoHeight) {
            float scale2 = h;
            h = photoHeight;
            w = (int) (w / (scale2 / h));
        } else if (h < AndroidUtilities.dp(120.0f)) {
            h = AndroidUtilities.dp(120.0f);
            float hScale = photoSize.h / h;
            if (photoSize.w / hScale < photoWidth) {
                w = (int) (photoSize.w / hScale);
            }
        }
        if (bitmap != null) {
            try {
                BitmapFactory.Options opts = new BitmapFactory.Options();
                opts.inJustDecodeBounds = true;
                File file = FileLoader.getPathToAttach(photoSize);
                FileInputStream is = new FileInputStream(file);
                BitmapFactory.decodeStream(is, null, opts);
                is.close();
                float photoW = opts.outWidth;
                float photoH = opts.outHeight;
                float scaleFactor = Math.max(photoW / w, photoH / h);
                if (scaleFactor < 1.0f) {
                    scaleFactor = 1.0f;
                }
                opts.inJustDecodeBounds = false;
                opts.inSampleSize = (int) scaleFactor;
                opts.inPreferredConfig = Bitmap.Config.RGB_565;
                if (Build.VERSION.SDK_INT >= 21) {
                    FileInputStream is2 = new FileInputStream(file);
                    bitmap[0] = BitmapFactory.decodeStream(is2, null, opts);
                    is2.close();
                }
            } catch (Throwable th) {
            }
        }
        return String.format(Locale.US, blur ? "%d_%d@%d_%d_b" : "%d_%d@%d_%d", Long.valueOf(photoSize.location.volume_id), Integer.valueOf(photoSize.location.local_id), Integer.valueOf((int) (w / AndroidUtilities.density)), Integer.valueOf((int) (h / AndroidUtilities.density)));
    }

    public static void prepareSendingMedia(final AccountInstance accountInstance, final ArrayList<SendingMediaInfo> media, final long dialog_id, final MessageObject reply_to_msg, final InputContentInfoCompat inputContent, final boolean forceDocument, final boolean groupPhotos, final MessageObject editingMessageObject, final boolean notify, final int scheduleDate, final boolean blnOriginalImg) {
        if (media.isEmpty()) {
            return;
        }
        mediaSendQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SendMessagesHelper$Tdt4XpH0U6_GcU7ViSzDduZfO4k
            @Override // java.lang.Runnable
            public final void run() throws Throwable {
                SendMessagesHelper.lambda$prepareSendingMedia$63(media, dialog_id, accountInstance, forceDocument, groupPhotos, blnOriginalImg, editingMessageObject, reply_to_msg, notify, scheduleDate, inputContent);
            }
        });
    }

    /* JADX WARN: Can't wrap try/catch for region: R(12:449|(1:454)(1:453)|455|(3:457|(2:458|(1:460)(1:546))|461)(1:462)|(1:464)|(7:521|466|467|(0)(1:470)|(2:487|(1:493)(1:492))(1:494)|495|543)(1:473)|527|474|(3:476|533|477)(1:481)|(0)(0)|495|543) */
    /* JADX WARN: Code restructure failed: missing block: B:483:0x0d68, code lost:
    
        r0 = e;
     */
    /* JADX WARN: Removed duplicated region for block: B:106:0x0291  */
    /* JADX WARN: Removed duplicated region for block: B:11:0x0033  */
    /* JADX WARN: Removed duplicated region for block: B:138:0x03b8  */
    /* JADX WARN: Removed duplicated region for block: B:172:0x0456  */
    /* JADX WARN: Removed duplicated region for block: B:173:0x0483  */
    /* JADX WARN: Removed duplicated region for block: B:178:0x04a9  */
    /* JADX WARN: Removed duplicated region for block: B:179:0x04ae  */
    /* JADX WARN: Removed duplicated region for block: B:182:0x04b9  */
    /* JADX WARN: Removed duplicated region for block: B:270:0x0806  */
    /* JADX WARN: Removed duplicated region for block: B:318:0x08f5  */
    /* JADX WARN: Removed duplicated region for block: B:324:0x090f  */
    /* JADX WARN: Removed duplicated region for block: B:329:0x0920  */
    /* JADX WARN: Removed duplicated region for block: B:336:0x0971  */
    /* JADX WARN: Removed duplicated region for block: B:33:0x008e  */
    /* JADX WARN: Removed duplicated region for block: B:347:0x09ac  */
    /* JADX WARN: Removed duplicated region for block: B:384:0x0af3  */
    /* JADX WARN: Removed duplicated region for block: B:392:0x0b10  */
    /* JADX WARN: Removed duplicated region for block: B:397:0x0b5a  */
    /* JADX WARN: Removed duplicated region for block: B:39:0x00b4  */
    /* JADX WARN: Removed duplicated region for block: B:487:0x0d6f  */
    /* JADX WARN: Removed duplicated region for block: B:494:0x0d9b  */
    /* JADX WARN: Removed duplicated region for block: B:504:0x0e5f  */
    /* JADX WARN: Removed duplicated region for block: B:505:0x0e6e  */
    /* JADX WARN: Removed duplicated region for block: B:507:0x0e74  */
    /* JADX WARN: Removed duplicated region for block: B:516:0x0edf  */
    /* JADX WARN: Removed duplicated region for block: B:519:0x0eeb  */
    /* JADX WARN: Removed duplicated region for block: B:51:0x00ff  */
    /* JADX WARN: Removed duplicated region for block: B:544:0x091e A[EDGE_INSN: B:544:0x091e->B:328:0x091e BREAK  A[LOOP:1: B:323:0x090d->B:327:0x091b], SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:557:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:94:0x0268  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    static /* synthetic */ void lambda$prepareSendingMedia$63(java.util.ArrayList r62, final long r63, final im.uwrkaxlmjj.messenger.AccountInstance r65, boolean r66, boolean r67, final boolean r68, final im.uwrkaxlmjj.messenger.MessageObject r69, final im.uwrkaxlmjj.messenger.MessageObject r70, final boolean r71, final int r72, androidx.core.view.inputmethod.InputContentInfoCompat r73) throws java.lang.Throwable {
        /*
            Method dump skipped, instruction units count: 3846
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.SendMessagesHelper.lambda$prepareSendingMedia$63(java.util.ArrayList, long, im.uwrkaxlmjj.messenger.AccountInstance, boolean, boolean, boolean, im.uwrkaxlmjj.messenger.MessageObject, im.uwrkaxlmjj.messenger.MessageObject, boolean, int, androidx.core.view.inputmethod.InputContentInfoCompat):void");
    }

    static /* synthetic */ void lambda$null$57(MediaSendPrepareWorker worker, AccountInstance accountInstance, SendingMediaInfo info, boolean blnOriginalImg, boolean isEncrypted) {
        worker.photo = accountInstance.getSendMessagesHelper().generatePhotoSizes(info.path, info.uri, blnOriginalImg);
        if (isEncrypted && info.canDeleteAfter) {
            new File(info.path).delete();
        }
        worker.sync.countDown();
    }

    static /* synthetic */ void lambda$null$58(MessageObject editingMessageObject, AccountInstance accountInstance, TLRPC.TL_document documentFinal, String pathFinal, HashMap params, String parentFinal, long dialog_id, MessageObject reply_to_msg, SendingMediaInfo info, boolean notify, int scheduleDate) {
        if (editingMessageObject == null) {
            accountInstance.getSendMessagesHelper().sendMessage(documentFinal, null, pathFinal, dialog_id, reply_to_msg, info.caption, info.entities, null, params, notify, scheduleDate, 0, parentFinal);
        } else {
            accountInstance.getSendMessagesHelper().editMessageMedia(editingMessageObject, null, null, documentFinal, pathFinal, params, false, parentFinal);
        }
    }

    static /* synthetic */ void lambda$null$59(MessageObject editingMessageObject, AccountInstance accountInstance, TLRPC.TL_photo photoFinal, boolean needDownloadHttpFinal, SendingMediaInfo info, HashMap params, String parentFinal, long dialog_id, MessageObject reply_to_msg, boolean notify, int scheduleDate) {
        if (editingMessageObject != null) {
            accountInstance.getSendMessagesHelper().editMessageMedia(editingMessageObject, photoFinal, null, null, needDownloadHttpFinal ? info.searchImage.imageUrl : null, params, false, parentFinal);
        } else {
            accountInstance.getSendMessagesHelper().sendMessage(photoFinal, needDownloadHttpFinal ? info.searchImage.imageUrl : null, dialog_id, reply_to_msg, info.caption, info.entities, null, params, notify, scheduleDate, info.ttl, parentFinal);
        }
    }

    static /* synthetic */ void lambda$null$60(Bitmap thumbFinal, String thumbKeyFinal, MessageObject editingMessageObject, AccountInstance accountInstance, VideoEditedInfo videoEditedInfo, TLRPC.TL_document videoFinal, String finalPath, HashMap params, String parentFinal, long dialog_id, MessageObject reply_to_msg, SendingMediaInfo info, boolean notify, int scheduleDate) {
        if (thumbFinal != null && thumbKeyFinal != null) {
            ImageLoader.getInstance().putImageToCache(new BitmapDrawable(thumbFinal), thumbKeyFinal);
        }
        if (editingMessageObject != null) {
            accountInstance.getSendMessagesHelper().editMessageMedia(editingMessageObject, null, videoEditedInfo, videoFinal, finalPath, params, false, parentFinal);
        } else {
            accountInstance.getSendMessagesHelper().sendMessage(videoFinal, videoEditedInfo, finalPath, dialog_id, reply_to_msg, info.caption, info.entities, null, params, notify, scheduleDate, info.ttl, parentFinal);
        }
    }

    static /* synthetic */ void lambda$null$61(Bitmap[] bitmapFinal, String[] keyFinal, MessageObject editingMessageObject, AccountInstance accountInstance, TLRPC.TL_photo photoFinal, HashMap params, String parentFinal, long dialog_id, MessageObject reply_to_msg, SendingMediaInfo info, boolean notify, int scheduleDate) {
        if (bitmapFinal[0] != null && keyFinal[0] != null) {
            ImageLoader.getInstance().putImageToCache(new BitmapDrawable(bitmapFinal[0]), keyFinal[0]);
        }
        if (editingMessageObject == null) {
            accountInstance.getSendMessagesHelper().sendMessage(photoFinal, null, dialog_id, reply_to_msg, info.caption, info.entities, null, params, notify, scheduleDate, info.ttl, parentFinal);
        } else {
            accountInstance.getSendMessagesHelper().editMessageMedia(editingMessageObject, photoFinal, null, null, null, params, false, parentFinal);
        }
    }

    static /* synthetic */ void lambda$null$62(AccountInstance accountInstance, long lastGroupIdFinal, int scheduleDate) {
        SendMessagesHelper instance = accountInstance.getSendMessagesHelper();
        ArrayList<DelayedMessage> arrayList = instance.delayedMessages.get("group_" + lastGroupIdFinal);
        if (arrayList != null && !arrayList.isEmpty()) {
            DelayedMessage message = arrayList.get(0);
            MessageObject prevMessage = message.messageObjects.get(message.messageObjects.size() - 1);
            message.finalGroupMessage = prevMessage.getId();
            prevMessage.messageOwner.params.put("final", "1");
            TLRPC.TL_messages_messages messagesRes = new TLRPC.TL_messages_messages();
            messagesRes.messages.add(prevMessage.messageOwner);
            accountInstance.getMessagesStorage().putMessages((TLRPC.messages_Messages) messagesRes, message.peer, -2, 0, false, scheduleDate != 0);
            instance.sendReadyToSendGroup(message, true, true);
        }
    }

    private static void fillVideoAttribute(String videoPath, TLRPC.TL_documentAttributeVideo attributeVideo, VideoEditedInfo videoEditedInfo) {
        String rotation;
        boolean infoObtained = false;
        MediaMetadataRetriever mediaMetadataRetriever = null;
        try {
            try {
                try {
                    MediaMetadataRetriever mediaMetadataRetriever2 = new MediaMetadataRetriever();
                    mediaMetadataRetriever2.setDataSource(videoPath);
                    String width = mediaMetadataRetriever2.extractMetadata(18);
                    if (width != null) {
                        attributeVideo.w = Integer.parseInt(width);
                    }
                    String height = mediaMetadataRetriever2.extractMetadata(19);
                    if (height != null) {
                        attributeVideo.h = Integer.parseInt(height);
                    }
                    String duration = mediaMetadataRetriever2.extractMetadata(9);
                    if (duration != null) {
                        attributeVideo.duration = (int) Math.ceil(Long.parseLong(duration) / 1000.0f);
                    }
                    if (Build.VERSION.SDK_INT >= 17 && (rotation = mediaMetadataRetriever2.extractMetadata(24)) != null) {
                        int val = Utilities.parseInt(rotation).intValue();
                        if (videoEditedInfo != null) {
                            videoEditedInfo.rotationValue = val;
                        } else if (val == 90 || val == 270) {
                            int temp = attributeVideo.w;
                            attributeVideo.w = attributeVideo.h;
                            attributeVideo.h = temp;
                        }
                    }
                    infoObtained = true;
                    mediaMetadataRetriever2.release();
                } catch (Exception e) {
                    FileLog.e(e);
                }
            } catch (Exception e2) {
                FileLog.e(e2);
                if (0 != 0) {
                    mediaMetadataRetriever.release();
                }
            }
            if (!infoObtained) {
                try {
                    MediaPlayer mp = MediaPlayer.create(ApplicationLoader.applicationContext, Uri.fromFile(new File(videoPath)));
                    if (mp != null) {
                        attributeVideo.duration = (int) Math.ceil(mp.getDuration() / 1000.0f);
                        attributeVideo.w = mp.getVideoWidth();
                        attributeVideo.h = mp.getVideoHeight();
                        mp.release();
                    }
                } catch (Exception e3) {
                    FileLog.e(e3);
                }
            }
        } catch (Throwable th) {
            if (0 != 0) {
                try {
                    mediaMetadataRetriever.release();
                } catch (Exception e4) {
                    FileLog.e(e4);
                }
            }
            throw th;
        }
    }

    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:7:0x0013 -> B:17:0x0021). Please report as a decompilation issue!!! */
    private static Bitmap createVideoThumbnail(String filePath, long time) {
        Bitmap bitmap = null;
        MediaMetadataRetriever retriever = new MediaMetadataRetriever();
        try {
            try {
                retriever.setDataSource(filePath);
                bitmap = retriever.getFrameAtTime(time, 1);
                retriever.release();
            } catch (Exception e) {
                retriever.release();
            } catch (Throwable th) {
                try {
                    retriever.release();
                } catch (Exception e2) {
                }
                throw th;
            }
        } catch (Exception e3) {
        }
        if (bitmap == null) {
            return null;
        }
        return bitmap;
    }

    /* JADX WARN: Removed duplicated region for block: B:95:0x0198  */
    /* JADX WARN: Removed duplicated region for block: B:96:0x01b1  */
    /* JADX WARN: Removed duplicated region for block: B:99:0x01d2  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private static im.uwrkaxlmjj.messenger.VideoEditedInfo createCompressionSettings(java.lang.String r20) {
        /*
            Method dump skipped, instruction units count: 471
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.SendMessagesHelper.createCompressionSettings(java.lang.String):im.uwrkaxlmjj.messenger.VideoEditedInfo");
    }

    public static void prepareSendingVideo(final AccountInstance accountInstance, final String videoPath, final long estimatedSize, final long duration, final int width, final int height, final VideoEditedInfo info, final long dialog_id, final MessageObject reply_to_msg, final CharSequence caption, final ArrayList<TLRPC.MessageEntity> entities, final int ttl, final MessageObject editingMessageObject, final boolean notify, final int scheduleDate) {
        if (videoPath == null || videoPath.length() == 0) {
            return;
        }
        new Thread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SendMessagesHelper$_FmzgcBm8Marrf_AE3_zJUZ1ckQ
            @Override // java.lang.Runnable
            public final void run() throws Throwable {
                SendMessagesHelper.lambda$prepareSendingVideo$65(info, videoPath, dialog_id, duration, ttl, accountInstance, height, width, estimatedSize, caption, editingMessageObject, reply_to_msg, entities, notify, scheduleDate);
            }
        }).start();
    }

    /* JADX WARN: Removed duplicated region for block: B:122:0x0310  */
    /* JADX WARN: Removed duplicated region for block: B:127:0x034a  */
    /* JADX WARN: Removed duplicated region for block: B:130:0x035e  */
    /* JADX WARN: Removed duplicated region for block: B:131:0x0365  */
    /* JADX WARN: Removed duplicated region for block: B:133:0x0369  */
    /* JADX WARN: Removed duplicated region for block: B:55:0x0151  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    static /* synthetic */ void lambda$prepareSendingVideo$65(im.uwrkaxlmjj.messenger.VideoEditedInfo r36, java.lang.String r37, final long r38, long r40, final int r42, final im.uwrkaxlmjj.messenger.AccountInstance r43, int r44, int r45, long r46, java.lang.CharSequence r48, final im.uwrkaxlmjj.messenger.MessageObject r49, final im.uwrkaxlmjj.messenger.MessageObject r50, final java.util.ArrayList r51, final boolean r52, final int r53) throws java.lang.Throwable {
        /*
            Method dump skipped, instruction units count: 912
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.SendMessagesHelper.lambda$prepareSendingVideo$65(im.uwrkaxlmjj.messenger.VideoEditedInfo, java.lang.String, long, long, int, im.uwrkaxlmjj.messenger.AccountInstance, int, int, long, java.lang.CharSequence, im.uwrkaxlmjj.messenger.MessageObject, im.uwrkaxlmjj.messenger.MessageObject, java.util.ArrayList, boolean, int):void");
    }

    static /* synthetic */ void lambda$null$64(Bitmap thumbFinal, String thumbKeyFinal, MessageObject editingMessageObject, AccountInstance accountInstance, VideoEditedInfo videoEditedInfo, TLRPC.TL_document videoFinal, String finalPath, HashMap params, String parentFinal, long dialog_id, MessageObject reply_to_msg, String captionFinal, ArrayList entities, boolean notify, int scheduleDate, int ttl) {
        if (thumbFinal != null && thumbKeyFinal != null) {
            ImageLoader.getInstance().putImageToCache(new BitmapDrawable(thumbFinal), thumbKeyFinal);
        }
        if (editingMessageObject != null) {
            accountInstance.getSendMessagesHelper().editMessageMedia(editingMessageObject, null, videoEditedInfo, videoFinal, finalPath, params, false, parentFinal);
        } else {
            accountInstance.getSendMessagesHelper().sendMessage(videoFinal, videoEditedInfo, finalPath, dialog_id, reply_to_msg, captionFinal, entities, null, params, notify, scheduleDate, ttl, parentFinal);
        }
    }
}
