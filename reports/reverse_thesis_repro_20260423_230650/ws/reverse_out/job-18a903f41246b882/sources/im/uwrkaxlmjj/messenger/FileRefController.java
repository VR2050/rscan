package im.uwrkaxlmjj.messenger;

import android.os.SystemClock;
import im.uwrkaxlmjj.messenger.FileLoadOperation;
import im.uwrkaxlmjj.messenger.SendMessagesHelper;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import org.webrtc.mozi.voiceengine.device.AudioDeviceSwitcher;

/* JADX INFO: loaded from: classes2.dex */
public class FileRefController extends BaseController {
    private static volatile FileRefController[] Instance = new FileRefController[3];
    private long lastCleanupTime;
    private HashMap<String, ArrayList<Requester>> locationRequester;
    private HashMap<TLRPC.TL_messages_sendMultiMedia, Object[]> multiMediaCache;
    private HashMap<String, ArrayList<Requester>> parentRequester;
    private HashMap<String, CachedResult> responseCache;

    /* JADX INFO: Access modifiers changed from: private */
    class Requester {
        private Object[] args;
        private boolean completed;
        private TLRPC.InputFileLocation location;
        private String locationKey;

        private Requester() {
        }
    }

    private class CachedResult {
        private long firstQueryTime;
        private long lastQueryTime;
        private TLObject response;

        private CachedResult() {
        }
    }

    public static FileRefController getInstance(int num) {
        FileRefController localInstance = Instance[num];
        if (localInstance == null) {
            synchronized (FileRefController.class) {
                localInstance = Instance[num];
                if (localInstance == null) {
                    FileRefController[] fileRefControllerArr = Instance;
                    FileRefController fileRefController = new FileRefController(num);
                    localInstance = fileRefController;
                    fileRefControllerArr[num] = fileRefController;
                }
            }
        }
        return localInstance;
    }

    public FileRefController(int instance) {
        super(instance);
        this.locationRequester = new HashMap<>();
        this.parentRequester = new HashMap<>();
        this.responseCache = new HashMap<>();
        this.multiMediaCache = new HashMap<>();
        this.lastCleanupTime = SystemClock.uptimeMillis();
    }

    public static String getKeyForParentObject(Object parentObject) {
        if (parentObject instanceof MessageObject) {
            MessageObject messageObject = (MessageObject) parentObject;
            int channelId = messageObject.getChannelId();
            return "message" + messageObject.getRealId() + "_" + channelId + "_" + messageObject.scheduled;
        }
        if (parentObject instanceof TLRPC.Message) {
            TLRPC.Message message = (TLRPC.Message) parentObject;
            int channelId2 = message.to_id != null ? message.to_id.channel_id : 0;
            return "message" + message.id + "_" + channelId2;
        }
        if (parentObject instanceof TLRPC.WebPage) {
            TLRPC.WebPage webPage = (TLRPC.WebPage) parentObject;
            return "webpage" + webPage.id;
        }
        if (parentObject instanceof TLRPC.User) {
            TLRPC.User user = (TLRPC.User) parentObject;
            return AudioDeviceSwitcher.AUDIO_DEVICE_SWITCH_SOURCE_USER + user.id;
        }
        if (parentObject instanceof TLRPC.Chat) {
            TLRPC.Chat chat = (TLRPC.Chat) parentObject;
            return "chat" + chat.id;
        }
        if (parentObject instanceof String) {
            String string = (String) parentObject;
            return "str" + string;
        }
        if (parentObject instanceof TLRPC.TL_messages_stickerSet) {
            TLRPC.TL_messages_stickerSet stickerSet = (TLRPC.TL_messages_stickerSet) parentObject;
            return "set" + stickerSet.set.id;
        }
        if (parentObject instanceof TLRPC.StickerSetCovered) {
            TLRPC.StickerSetCovered stickerSet2 = (TLRPC.StickerSetCovered) parentObject;
            return "set" + stickerSet2.set.id;
        }
        if (parentObject instanceof TLRPC.InputStickerSet) {
            TLRPC.InputStickerSet inputStickerSet = (TLRPC.InputStickerSet) parentObject;
            return "set" + inputStickerSet.id;
        }
        if (parentObject instanceof TLRPC.TL_wallPaper) {
            TLRPC.TL_wallPaper wallPaper = (TLRPC.TL_wallPaper) parentObject;
            return "wallpaper" + wallPaper.id;
        }
        if (parentObject instanceof TLRPC.TL_theme) {
            TLRPC.TL_theme theme = (TLRPC.TL_theme) parentObject;
            return "theme" + theme.id;
        }
        if (parentObject == null) {
            return null;
        }
        return "" + parentObject;
    }

    public void requestReference(Object parentObject, Object... args) {
        TLRPC.InputFileLocation location;
        String locationKey;
        if (BuildVars.LOGS_ENABLED) {
            FileLog.d("start loading request reference for parent = " + parentObject + " args = " + args[0]);
        }
        if (args[0] instanceof TLRPC.TL_inputSingleMedia) {
            TLRPC.TL_inputSingleMedia req = (TLRPC.TL_inputSingleMedia) args[0];
            if (req.media instanceof TLRPC.TL_inputMediaDocument) {
                TLRPC.TL_inputMediaDocument mediaDocument = (TLRPC.TL_inputMediaDocument) req.media;
                locationKey = "file_" + mediaDocument.id.id;
                location = new TLRPC.TL_inputDocumentFileLocation();
                location.id = mediaDocument.id.id;
            } else if (req.media instanceof TLRPC.TL_inputMediaPhoto) {
                TLRPC.TL_inputMediaPhoto mediaPhoto = (TLRPC.TL_inputMediaPhoto) req.media;
                String locationKey2 = "photo_" + mediaPhoto.id.id;
                location = new TLRPC.TL_inputPhotoFileLocation();
                location.id = mediaPhoto.id.id;
                locationKey = locationKey2;
            } else {
                sendErrorToObject(args, 0);
                return;
            }
        } else {
            if (args[0] instanceof TLRPC.TL_messages_sendMultiMedia) {
                TLRPC.TL_messages_sendMultiMedia req2 = (TLRPC.TL_messages_sendMultiMedia) args[0];
                ArrayList<Object> parentObjects = (ArrayList) parentObject;
                this.multiMediaCache.put(req2, args);
                int size = req2.multi_media.size();
                for (int a = 0; a < size; a++) {
                    Object media = (TLRPC.TL_inputSingleMedia) req2.multi_media.get(a);
                    Object parentObject2 = parentObjects.get(a);
                    if (parentObject2 != null) {
                        requestReference(parentObject2, media, req2);
                    }
                }
                return;
            }
            if (args[0] instanceof TLRPC.TL_messages_sendMedia) {
                TLRPC.TL_messages_sendMedia req3 = (TLRPC.TL_messages_sendMedia) args[0];
                if (req3.media instanceof TLRPC.TL_inputMediaDocument) {
                    TLRPC.TL_inputMediaDocument mediaDocument2 = (TLRPC.TL_inputMediaDocument) req3.media;
                    locationKey = "file_" + mediaDocument2.id.id;
                    location = new TLRPC.TL_inputDocumentFileLocation();
                    location.id = mediaDocument2.id.id;
                } else if (req3.media instanceof TLRPC.TL_inputMediaPhoto) {
                    TLRPC.TL_inputMediaPhoto mediaPhoto2 = (TLRPC.TL_inputMediaPhoto) req3.media;
                    String locationKey3 = "photo_" + mediaPhoto2.id.id;
                    location = new TLRPC.TL_inputPhotoFileLocation();
                    location.id = mediaPhoto2.id.id;
                    locationKey = locationKey3;
                } else {
                    sendErrorToObject(args, 0);
                    return;
                }
            } else if (args[0] instanceof TLRPC.TL_messages_editMessage) {
                TLRPC.TL_messages_editMessage req4 = (TLRPC.TL_messages_editMessage) args[0];
                if (req4.media instanceof TLRPC.TL_inputMediaDocument) {
                    TLRPC.TL_inputMediaDocument mediaDocument3 = (TLRPC.TL_inputMediaDocument) req4.media;
                    locationKey = "file_" + mediaDocument3.id.id;
                    location = new TLRPC.TL_inputDocumentFileLocation();
                    location.id = mediaDocument3.id.id;
                } else if (req4.media instanceof TLRPC.TL_inputMediaPhoto) {
                    TLRPC.TL_inputMediaPhoto mediaPhoto3 = (TLRPC.TL_inputMediaPhoto) req4.media;
                    String locationKey4 = "photo_" + mediaPhoto3.id.id;
                    location = new TLRPC.TL_inputPhotoFileLocation();
                    location.id = mediaPhoto3.id.id;
                    locationKey = locationKey4;
                } else {
                    sendErrorToObject(args, 0);
                    return;
                }
            } else if (args[0] instanceof TLRPC.TL_messages_saveGif) {
                TLRPC.TL_messages_saveGif req5 = (TLRPC.TL_messages_saveGif) args[0];
                locationKey = "file_" + req5.id.id;
                location = new TLRPC.TL_inputDocumentFileLocation();
                location.id = req5.id.id;
            } else if (args[0] instanceof TLRPC.TL_messages_saveRecentSticker) {
                TLRPC.TL_messages_saveRecentSticker req6 = (TLRPC.TL_messages_saveRecentSticker) args[0];
                locationKey = "file_" + req6.id.id;
                location = new TLRPC.TL_inputDocumentFileLocation();
                location.id = req6.id.id;
            } else if (args[0] instanceof TLRPC.TL_messages_faveSticker) {
                TLRPC.TL_messages_faveSticker req7 = (TLRPC.TL_messages_faveSticker) args[0];
                locationKey = "file_" + req7.id.id;
                location = new TLRPC.TL_inputDocumentFileLocation();
                location.id = req7.id.id;
            } else if (args[0] instanceof TLRPC.TL_messages_getAttachedStickers) {
                TLRPC.TL_messages_getAttachedStickers req8 = (TLRPC.TL_messages_getAttachedStickers) args[0];
                if (req8.media instanceof TLRPC.TL_inputStickeredMediaDocument) {
                    TLRPC.TL_inputStickeredMediaDocument mediaDocument4 = (TLRPC.TL_inputStickeredMediaDocument) req8.media;
                    locationKey = "file_" + mediaDocument4.id.id;
                    location = new TLRPC.TL_inputDocumentFileLocation();
                    location.id = mediaDocument4.id.id;
                } else if (req8.media instanceof TLRPC.TL_inputStickeredMediaPhoto) {
                    TLRPC.TL_inputStickeredMediaPhoto mediaPhoto4 = (TLRPC.TL_inputStickeredMediaPhoto) req8.media;
                    String locationKey5 = "photo_" + mediaPhoto4.id.id;
                    location = new TLRPC.TL_inputPhotoFileLocation();
                    location.id = mediaPhoto4.id.id;
                    locationKey = locationKey5;
                } else {
                    sendErrorToObject(args, 0);
                    return;
                }
            } else if (args[0] instanceof TLRPC.TL_inputFileLocation) {
                location = (TLRPC.TL_inputFileLocation) args[0];
                locationKey = "loc_" + location.local_id + "_" + location.volume_id;
            } else if (args[0] instanceof TLRPC.TL_inputDocumentFileLocation) {
                location = (TLRPC.TL_inputDocumentFileLocation) args[0];
                locationKey = "file_" + location.id;
            } else if (args[0] instanceof TLRPC.TL_inputPhotoFileLocation) {
                location = (TLRPC.TL_inputPhotoFileLocation) args[0];
                locationKey = "photo_" + location.id;
            } else {
                sendErrorToObject(args, 0);
                return;
            }
        }
        if (parentObject instanceof MessageObject) {
            MessageObject messageObject = (MessageObject) parentObject;
            if (messageObject.getRealId() < 0 && messageObject.messageOwner.media.webpage != null) {
                parentObject = messageObject.messageOwner.media.webpage;
            }
        }
        String parentKey = getKeyForParentObject(parentObject);
        if (parentKey == null) {
            sendErrorToObject(args, 0);
            return;
        }
        Requester requester = new Requester();
        requester.args = args;
        requester.location = location;
        requester.locationKey = locationKey;
        int added = 0;
        ArrayList<Requester> arrayList = this.locationRequester.get(locationKey);
        if (arrayList == null) {
            arrayList = new ArrayList<>();
            this.locationRequester.put(locationKey, arrayList);
            added = 0 + 1;
        }
        arrayList.add(requester);
        ArrayList<Requester> arrayList2 = this.parentRequester.get(parentKey);
        if (arrayList2 == null) {
            arrayList2 = new ArrayList<>();
            this.parentRequester.put(parentKey, arrayList2);
            added++;
        }
        arrayList2.add(requester);
        if (added != 2) {
            return;
        }
        cleanupCache();
        CachedResult cachedResult = getCachedResponse(locationKey);
        if (cachedResult != null) {
            if (!onRequestComplete(locationKey, parentKey, cachedResult.response, false)) {
                this.responseCache.remove(locationKey);
            } else {
                return;
            }
        } else {
            CachedResult cachedResult2 = getCachedResponse(parentKey);
            if (cachedResult2 != null) {
                if (!onRequestComplete(locationKey, parentKey, cachedResult2.response, false)) {
                    this.responseCache.remove(parentKey);
                } else {
                    return;
                }
            }
        }
        requestReferenceFromServer(parentObject, locationKey, parentKey, args);
    }

    private void requestReferenceFromServer(Object parentObject, final String locationKey, final String parentKey, Object[] args) {
        if (parentObject instanceof MessageObject) {
            MessageObject messageObject = (MessageObject) parentObject;
            int channelId = messageObject.getChannelId();
            if (messageObject.scheduled) {
                TLRPC.TL_messages_getScheduledMessages req = new TLRPC.TL_messages_getScheduledMessages();
                req.peer = getMessagesController().getInputPeer((int) messageObject.getDialogId());
                req.id.add(Integer.valueOf(messageObject.getRealId()));
                getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileRefController$YSSdOEesjoiLO9vQ2AkxHEaH4ME
                    @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                    public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                        this.f$0.lambda$requestReferenceFromServer$0$FileRefController(locationKey, parentKey, tLObject, tL_error);
                    }
                });
                return;
            }
            if (channelId != 0) {
                TLRPC.TL_channels_getMessages req2 = new TLRPC.TL_channels_getMessages();
                req2.channel = getMessagesController().getInputChannel(channelId);
                req2.id.add(Integer.valueOf(messageObject.getRealId()));
                getConnectionsManager().sendRequest(req2, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileRefController$cXltNhKlPmuqBB2x_aQN3JtKOuM
                    @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                    public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                        this.f$0.lambda$requestReferenceFromServer$1$FileRefController(locationKey, parentKey, tLObject, tL_error);
                    }
                });
                return;
            }
            TLRPC.TL_messages_getMessages req3 = new TLRPC.TL_messages_getMessages();
            req3.id.add(Integer.valueOf(messageObject.getRealId()));
            getConnectionsManager().sendRequest(req3, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileRefController$HT_QBK7CWznDnJemAWlZWDsbBOM
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$requestReferenceFromServer$2$FileRefController(locationKey, parentKey, tLObject, tL_error);
                }
            });
            return;
        }
        if (parentObject instanceof TLRPC.TL_wallPaper) {
            TLRPC.TL_wallPaper wallPaper = (TLRPC.TL_wallPaper) parentObject;
            TLRPC.TL_account_getWallPaper req4 = new TLRPC.TL_account_getWallPaper();
            TLRPC.TL_inputWallPaper inputWallPaper = new TLRPC.TL_inputWallPaper();
            inputWallPaper.id = wallPaper.id;
            inputWallPaper.access_hash = wallPaper.access_hash;
            req4.wallpaper = inputWallPaper;
            getConnectionsManager().sendRequest(req4, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileRefController$n9bE8fNLAQV-03_qTz8SXEzZMRQ
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$requestReferenceFromServer$3$FileRefController(locationKey, parentKey, tLObject, tL_error);
                }
            });
            return;
        }
        if (parentObject instanceof TLRPC.TL_theme) {
            TLRPC.TL_theme theme = (TLRPC.TL_theme) parentObject;
            TLRPC.TL_account_getTheme req5 = new TLRPC.TL_account_getTheme();
            TLRPC.TL_inputTheme inputTheme = new TLRPC.TL_inputTheme();
            inputTheme.id = theme.id;
            inputTheme.access_hash = theme.access_hash;
            req5.theme = inputTheme;
            req5.format = "android";
            getConnectionsManager().sendRequest(req5, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileRefController$13mv5xCYcyB79xDCKIJ_rKQGOgU
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$requestReferenceFromServer$4$FileRefController(locationKey, parentKey, tLObject, tL_error);
                }
            });
            return;
        }
        if (parentObject instanceof TLRPC.WebPage) {
            TLRPC.WebPage webPage = (TLRPC.WebPage) parentObject;
            TLRPC.TL_messages_getWebPage req6 = new TLRPC.TL_messages_getWebPage();
            req6.url = webPage.url;
            req6.hash = 0;
            getConnectionsManager().sendRequest(req6, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileRefController$ESqi_JiiHySJGk02-XccXz_gTXw
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$requestReferenceFromServer$5$FileRefController(locationKey, parentKey, tLObject, tL_error);
                }
            });
            return;
        }
        if (parentObject instanceof TLRPC.User) {
            TLRPC.User user = (TLRPC.User) parentObject;
            TLRPC.TL_users_getUsers req7 = new TLRPC.TL_users_getUsers();
            req7.id.add(getMessagesController().getInputUser(user));
            getConnectionsManager().sendRequest(req7, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileRefController$zAv6_ZkQoVpHCPNzVryXHSWBh5g
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$requestReferenceFromServer$6$FileRefController(locationKey, parentKey, tLObject, tL_error);
                }
            });
            return;
        }
        if (parentObject instanceof TLRPC.Chat) {
            TLRPC.Chat chat = (TLRPC.Chat) parentObject;
            if (chat instanceof TLRPC.TL_chat) {
                TLRPC.TL_messages_getChats req8 = new TLRPC.TL_messages_getChats();
                req8.id.add(Integer.valueOf(chat.id));
                getConnectionsManager().sendRequest(req8, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileRefController$H4lMMhc4Jkul9_FUaK5y0lDEVtU
                    @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                    public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                        this.f$0.lambda$requestReferenceFromServer$7$FileRefController(locationKey, parentKey, tLObject, tL_error);
                    }
                });
                return;
            } else {
                if (chat instanceof TLRPC.TL_channel) {
                    TLRPC.TL_channels_getChannels req9 = new TLRPC.TL_channels_getChannels();
                    req9.id.add(MessagesController.getInputChannel(chat));
                    getConnectionsManager().sendRequest(req9, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileRefController$_cYFDlcsg4HSMO71ux0FfEPRtKs
                        @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                        public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                            this.f$0.lambda$requestReferenceFromServer$8$FileRefController(locationKey, parentKey, tLObject, tL_error);
                        }
                    });
                    return;
                }
                return;
            }
        }
        if (!(parentObject instanceof String)) {
            if (parentObject instanceof TLRPC.TL_messages_stickerSet) {
                TLRPC.TL_messages_stickerSet stickerSet = (TLRPC.TL_messages_stickerSet) parentObject;
                TLRPC.TL_messages_getStickerSet req10 = new TLRPC.TL_messages_getStickerSet();
                req10.stickerset = new TLRPC.TL_inputStickerSetID();
                req10.stickerset.id = stickerSet.set.id;
                req10.stickerset.access_hash = stickerSet.set.access_hash;
                getConnectionsManager().sendRequest(req10, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileRefController$sZUQ25uFpP57hzhzeuarwCTDuYQ
                    @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                    public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                        this.f$0.lambda$requestReferenceFromServer$17$FileRefController(locationKey, parentKey, tLObject, tL_error);
                    }
                });
                return;
            }
            if (!(parentObject instanceof TLRPC.StickerSetCovered)) {
                if (parentObject instanceof TLRPC.InputStickerSet) {
                    TLRPC.TL_messages_getStickerSet req11 = new TLRPC.TL_messages_getStickerSet();
                    req11.stickerset = (TLRPC.InputStickerSet) parentObject;
                    getConnectionsManager().sendRequest(req11, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileRefController$OBJREuBOQHMuGUQY_O9Qo5DK7bs
                        @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                        public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                            this.f$0.lambda$requestReferenceFromServer$19$FileRefController(locationKey, parentKey, tLObject, tL_error);
                        }
                    });
                    return;
                }
                sendErrorToObject(args, 0);
                return;
            }
            TLRPC.StickerSetCovered stickerSet2 = (TLRPC.StickerSetCovered) parentObject;
            TLRPC.TL_messages_getStickerSet req12 = new TLRPC.TL_messages_getStickerSet();
            req12.stickerset = new TLRPC.TL_inputStickerSetID();
            req12.stickerset.id = stickerSet2.set.id;
            req12.stickerset.access_hash = stickerSet2.set.access_hash;
            getConnectionsManager().sendRequest(req12, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileRefController$guvuwEyMJU_5hTsyLU4-z-XMa0g
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$requestReferenceFromServer$18$FileRefController(locationKey, parentKey, tLObject, tL_error);
                }
            });
            return;
        }
        String string = (String) parentObject;
        if ("wallpaper".equals(string)) {
            getConnectionsManager().sendRequest(new TLRPC.TL_account_getWallPapers(), new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileRefController$gmefNFFed-Dbyziy4cw5ufcA8rs
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$requestReferenceFromServer$9$FileRefController(locationKey, parentKey, tLObject, tL_error);
                }
            });
            return;
        }
        if (string.startsWith("gif")) {
            getConnectionsManager().sendRequest(new TLRPC.TL_messages_getSavedGifs(), new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileRefController$JmpvTK9F20KN5uTCH1520Ml0nTU
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$requestReferenceFromServer$10$FileRefController(locationKey, parentKey, tLObject, tL_error);
                }
            });
            return;
        }
        if ("recent".equals(string)) {
            getConnectionsManager().sendRequest(new TLRPC.TL_messages_getRecentStickers(), new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileRefController$iax5xSXZhUUt_pUEgQB31nkRHjg
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$requestReferenceFromServer$11$FileRefController(locationKey, parentKey, tLObject, tL_error);
                }
            });
            return;
        }
        if ("fav".equals(string)) {
            getConnectionsManager().sendRequest(new TLRPC.TL_messages_getFavedStickers(), new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileRefController$UxR99v_V-89KHP_sb82urZahWDk
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$requestReferenceFromServer$12$FileRefController(locationKey, parentKey, tLObject, tL_error);
                }
            });
            return;
        }
        if (string.startsWith("avatar_")) {
            int id = Utilities.parseInt(string).intValue();
            if (id > 0) {
                TLRPC.TL_photos_getUserPhotos req13 = new TLRPC.TL_photos_getUserPhotos();
                req13.limit = 80;
                req13.offset = 0;
                req13.max_id = 0L;
                req13.user_id = getMessagesController().getInputUser(id);
                getConnectionsManager().sendRequest(req13, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileRefController$F7d_pqDJin9giJdXK4u4mMX0MLs
                    @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                    public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                        this.f$0.lambda$requestReferenceFromServer$13$FileRefController(locationKey, parentKey, tLObject, tL_error);
                    }
                });
                return;
            }
            TLRPC.TL_messages_search req14 = new TLRPC.TL_messages_search();
            req14.filter = new TLRPC.TL_inputMessagesFilterChatPhotos();
            req14.limit = 80;
            req14.offset_id = 0;
            req14.q = "";
            req14.peer = getMessagesController().getInputPeer(id);
            getConnectionsManager().sendRequest(req14, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileRefController$DUVrhrFIFDg66Jz76aWZhAn-OpQ
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$requestReferenceFromServer$14$FileRefController(locationKey, parentKey, tLObject, tL_error);
                }
            });
            return;
        }
        if (string.startsWith("sent_")) {
            String[] params = string.split("_");
            if (params.length == 3) {
                int channelId2 = Utilities.parseInt(params[1]).intValue();
                if (channelId2 != 0) {
                    TLRPC.TL_channels_getMessages req15 = new TLRPC.TL_channels_getMessages();
                    req15.channel = getMessagesController().getInputChannel(channelId2);
                    req15.id.add(Utilities.parseInt(params[2]));
                    getConnectionsManager().sendRequest(req15, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileRefController$6opyuQKHjIbR6vK1nsPP50aHCDw
                        @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                        public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                            this.f$0.lambda$requestReferenceFromServer$15$FileRefController(locationKey, parentKey, tLObject, tL_error);
                        }
                    });
                    return;
                }
                TLRPC.TL_messages_getMessages req16 = new TLRPC.TL_messages_getMessages();
                req16.id.add(Utilities.parseInt(params[2]));
                getConnectionsManager().sendRequest(req16, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileRefController$_P_gbBgoLK1WjR56TF-yl0ROMlY
                    @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                    public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                        this.f$0.lambda$requestReferenceFromServer$16$FileRefController(locationKey, parentKey, tLObject, tL_error);
                    }
                });
                return;
            }
            sendErrorToObject(args, 0);
            return;
        }
        sendErrorToObject(args, 0);
    }

    public /* synthetic */ void lambda$requestReferenceFromServer$0$FileRefController(String locationKey, String parentKey, TLObject response, TLRPC.TL_error error) {
        onRequestComplete(locationKey, parentKey, response, true);
    }

    public /* synthetic */ void lambda$requestReferenceFromServer$1$FileRefController(String locationKey, String parentKey, TLObject response, TLRPC.TL_error error) {
        onRequestComplete(locationKey, parentKey, response, true);
    }

    public /* synthetic */ void lambda$requestReferenceFromServer$2$FileRefController(String locationKey, String parentKey, TLObject response, TLRPC.TL_error error) {
        onRequestComplete(locationKey, parentKey, response, true);
    }

    public /* synthetic */ void lambda$requestReferenceFromServer$3$FileRefController(String locationKey, String parentKey, TLObject response, TLRPC.TL_error error) {
        onRequestComplete(locationKey, parentKey, response, true);
    }

    public /* synthetic */ void lambda$requestReferenceFromServer$4$FileRefController(String locationKey, String parentKey, TLObject response, TLRPC.TL_error error) {
        onRequestComplete(locationKey, parentKey, response, true);
    }

    public /* synthetic */ void lambda$requestReferenceFromServer$5$FileRefController(String locationKey, String parentKey, TLObject response, TLRPC.TL_error error) {
        onRequestComplete(locationKey, parentKey, response, true);
    }

    public /* synthetic */ void lambda$requestReferenceFromServer$6$FileRefController(String locationKey, String parentKey, TLObject response, TLRPC.TL_error error) {
        onRequestComplete(locationKey, parentKey, response, true);
    }

    public /* synthetic */ void lambda$requestReferenceFromServer$7$FileRefController(String locationKey, String parentKey, TLObject response, TLRPC.TL_error error) {
        onRequestComplete(locationKey, parentKey, response, true);
    }

    public /* synthetic */ void lambda$requestReferenceFromServer$8$FileRefController(String locationKey, String parentKey, TLObject response, TLRPC.TL_error error) {
        onRequestComplete(locationKey, parentKey, response, true);
    }

    public /* synthetic */ void lambda$requestReferenceFromServer$9$FileRefController(String locationKey, String parentKey, TLObject response, TLRPC.TL_error error) {
        onRequestComplete(locationKey, parentKey, response, true);
    }

    public /* synthetic */ void lambda$requestReferenceFromServer$10$FileRefController(String locationKey, String parentKey, TLObject response, TLRPC.TL_error error) {
        onRequestComplete(locationKey, parentKey, response, true);
    }

    public /* synthetic */ void lambda$requestReferenceFromServer$11$FileRefController(String locationKey, String parentKey, TLObject response, TLRPC.TL_error error) {
        onRequestComplete(locationKey, parentKey, response, true);
    }

    public /* synthetic */ void lambda$requestReferenceFromServer$12$FileRefController(String locationKey, String parentKey, TLObject response, TLRPC.TL_error error) {
        onRequestComplete(locationKey, parentKey, response, true);
    }

    public /* synthetic */ void lambda$requestReferenceFromServer$13$FileRefController(String locationKey, String parentKey, TLObject response, TLRPC.TL_error error) {
        onRequestComplete(locationKey, parentKey, response, true);
    }

    public /* synthetic */ void lambda$requestReferenceFromServer$14$FileRefController(String locationKey, String parentKey, TLObject response, TLRPC.TL_error error) {
        onRequestComplete(locationKey, parentKey, response, true);
    }

    public /* synthetic */ void lambda$requestReferenceFromServer$15$FileRefController(String locationKey, String parentKey, TLObject response, TLRPC.TL_error error) {
        onRequestComplete(locationKey, parentKey, response, false);
    }

    public /* synthetic */ void lambda$requestReferenceFromServer$16$FileRefController(String locationKey, String parentKey, TLObject response, TLRPC.TL_error error) {
        onRequestComplete(locationKey, parentKey, response, false);
    }

    public /* synthetic */ void lambda$requestReferenceFromServer$17$FileRefController(String locationKey, String parentKey, TLObject response, TLRPC.TL_error error) {
        onRequestComplete(locationKey, parentKey, response, true);
    }

    public /* synthetic */ void lambda$requestReferenceFromServer$18$FileRefController(String locationKey, String parentKey, TLObject response, TLRPC.TL_error error) {
        onRequestComplete(locationKey, parentKey, response, true);
    }

    public /* synthetic */ void lambda$requestReferenceFromServer$19$FileRefController(String locationKey, String parentKey, TLObject response, TLRPC.TL_error error) {
        onRequestComplete(locationKey, parentKey, response, true);
    }

    private void onUpdateObjectReference(final Requester requester, byte[] file_reference, TLRPC.InputFileLocation locationReplacement) {
        if (BuildVars.DEBUG_VERSION) {
            FileLog.d("fileref updated for " + requester.args[0] + " " + requester.locationKey);
        }
        if (requester.args[0] instanceof TLRPC.TL_inputSingleMedia) {
            final TLRPC.TL_messages_sendMultiMedia multiMedia = (TLRPC.TL_messages_sendMultiMedia) requester.args[1];
            final Object[] objects = this.multiMediaCache.get(multiMedia);
            if (objects != null) {
                TLRPC.TL_inputSingleMedia req = (TLRPC.TL_inputSingleMedia) requester.args[0];
                if (req.media instanceof TLRPC.TL_inputMediaDocument) {
                    TLRPC.TL_inputMediaDocument mediaDocument = (TLRPC.TL_inputMediaDocument) req.media;
                    mediaDocument.id.file_reference = file_reference;
                } else if (req.media instanceof TLRPC.TL_inputMediaPhoto) {
                    TLRPC.TL_inputMediaPhoto mediaPhoto = (TLRPC.TL_inputMediaPhoto) req.media;
                    mediaPhoto.id.file_reference = file_reference;
                }
                int index = multiMedia.multi_media.indexOf(req);
                if (index < 0) {
                    return;
                }
                ArrayList<Object> parentObjects = (ArrayList) objects[3];
                parentObjects.set(index, null);
                boolean done = true;
                for (int a = 0; a < parentObjects.size(); a++) {
                    if (parentObjects.get(a) != null) {
                        done = false;
                    }
                }
                if (done) {
                    this.multiMediaCache.remove(multiMedia);
                    AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileRefController$6ZWjMIO1TqWpbt3YGvh4ypma7PI
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$onUpdateObjectReference$20$FileRefController(multiMedia, objects);
                        }
                    });
                    return;
                }
                return;
            }
            return;
        }
        if (requester.args[0] instanceof TLRPC.TL_messages_sendMedia) {
            TLRPC.TL_messages_sendMedia req2 = (TLRPC.TL_messages_sendMedia) requester.args[0];
            if (req2.media instanceof TLRPC.TL_inputMediaDocument) {
                TLRPC.TL_inputMediaDocument mediaDocument2 = (TLRPC.TL_inputMediaDocument) req2.media;
                mediaDocument2.id.file_reference = file_reference;
            } else if (req2.media instanceof TLRPC.TL_inputMediaPhoto) {
                TLRPC.TL_inputMediaPhoto mediaPhoto2 = (TLRPC.TL_inputMediaPhoto) req2.media;
                mediaPhoto2.id.file_reference = file_reference;
            }
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileRefController$mcnbRyYeEv-9rIf9kF9kRpVdMxQ
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onUpdateObjectReference$21$FileRefController(requester);
                }
            });
            return;
        }
        if (requester.args[0] instanceof TLRPC.TL_messages_editMessage) {
            TLRPC.TL_messages_editMessage req3 = (TLRPC.TL_messages_editMessage) requester.args[0];
            if (req3.media instanceof TLRPC.TL_inputMediaDocument) {
                TLRPC.TL_inputMediaDocument mediaDocument3 = (TLRPC.TL_inputMediaDocument) req3.media;
                mediaDocument3.id.file_reference = file_reference;
            } else if (req3.media instanceof TLRPC.TL_inputMediaPhoto) {
                TLRPC.TL_inputMediaPhoto mediaPhoto3 = (TLRPC.TL_inputMediaPhoto) req3.media;
                mediaPhoto3.id.file_reference = file_reference;
            }
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileRefController$JNP3_IFjF7L5zRgl-O5zcnUgdRg
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onUpdateObjectReference$22$FileRefController(requester);
                }
            });
            return;
        }
        if (requester.args[0] instanceof TLRPC.TL_messages_saveGif) {
            TLRPC.TL_messages_saveGif req4 = (TLRPC.TL_messages_saveGif) requester.args[0];
            req4.id.file_reference = file_reference;
            getConnectionsManager().sendRequest(req4, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileRefController$XUGyECr4ubZbpwO_f45Ymr23Kw0
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    FileRefController.lambda$onUpdateObjectReference$23(tLObject, tL_error);
                }
            });
            return;
        }
        if (requester.args[0] instanceof TLRPC.TL_messages_saveRecentSticker) {
            TLRPC.TL_messages_saveRecentSticker req5 = (TLRPC.TL_messages_saveRecentSticker) requester.args[0];
            req5.id.file_reference = file_reference;
            getConnectionsManager().sendRequest(req5, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileRefController$dGHA-uvWtmprR8hXUyB3AvqfpBA
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    FileRefController.lambda$onUpdateObjectReference$24(tLObject, tL_error);
                }
            });
            return;
        }
        if (requester.args[0] instanceof TLRPC.TL_messages_faveSticker) {
            TLRPC.TL_messages_faveSticker req6 = (TLRPC.TL_messages_faveSticker) requester.args[0];
            req6.id.file_reference = file_reference;
            getConnectionsManager().sendRequest(req6, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileRefController$s72GEbTe5bzME9WwNXpRAC8z0PM
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    FileRefController.lambda$onUpdateObjectReference$25(tLObject, tL_error);
                }
            });
            return;
        }
        if (requester.args[0] instanceof TLRPC.TL_messages_getAttachedStickers) {
            TLRPC.TL_messages_getAttachedStickers req7 = (TLRPC.TL_messages_getAttachedStickers) requester.args[0];
            if (req7.media instanceof TLRPC.TL_inputStickeredMediaDocument) {
                TLRPC.TL_inputStickeredMediaDocument mediaDocument4 = (TLRPC.TL_inputStickeredMediaDocument) req7.media;
                mediaDocument4.id.file_reference = file_reference;
            } else if (req7.media instanceof TLRPC.TL_inputStickeredMediaPhoto) {
                TLRPC.TL_inputStickeredMediaPhoto mediaPhoto4 = (TLRPC.TL_inputStickeredMediaPhoto) req7.media;
                mediaPhoto4.id.file_reference = file_reference;
            }
            getConnectionsManager().sendRequest(req7, (RequestDelegate) requester.args[1]);
            return;
        }
        if (requester.args[1] instanceof FileLoadOperation) {
            FileLoadOperation fileLoadOperation = (FileLoadOperation) requester.args[1];
            if (locationReplacement == null) {
                requester.location.file_reference = file_reference;
            } else {
                fileLoadOperation.location = locationReplacement;
            }
            fileLoadOperation.requestingReference = false;
            fileLoadOperation.startDownloadRequest();
        }
    }

    public /* synthetic */ void lambda$onUpdateObjectReference$20$FileRefController(TLRPC.TL_messages_sendMultiMedia multiMedia, Object[] objects) {
        getSendMessagesHelper().performSendMessageRequestMulti(multiMedia, (ArrayList) objects[1], (ArrayList) objects[2], null, (SendMessagesHelper.DelayedMessage) objects[4], ((Boolean) objects[5]).booleanValue());
    }

    public /* synthetic */ void lambda$onUpdateObjectReference$21$FileRefController(Requester requester) {
        getSendMessagesHelper().performSendMessageRequest((TLObject) requester.args[0], (MessageObject) requester.args[1], (String) requester.args[2], (SendMessagesHelper.DelayedMessage) requester.args[3], ((Boolean) requester.args[4]).booleanValue(), (SendMessagesHelper.DelayedMessage) requester.args[5], null, ((Boolean) requester.args[6]).booleanValue());
    }

    public /* synthetic */ void lambda$onUpdateObjectReference$22$FileRefController(Requester requester) {
        getSendMessagesHelper().performSendMessageRequest((TLObject) requester.args[0], (MessageObject) requester.args[1], (String) requester.args[2], (SendMessagesHelper.DelayedMessage) requester.args[3], ((Boolean) requester.args[4]).booleanValue(), (SendMessagesHelper.DelayedMessage) requester.args[5], null, ((Boolean) requester.args[6]).booleanValue());
    }

    static /* synthetic */ void lambda$onUpdateObjectReference$23(TLObject response, TLRPC.TL_error error) {
    }

    static /* synthetic */ void lambda$onUpdateObjectReference$24(TLObject response, TLRPC.TL_error error) {
    }

    static /* synthetic */ void lambda$onUpdateObjectReference$25(TLObject response, TLRPC.TL_error error) {
    }

    private void sendErrorToObject(final Object[] args, int reason) {
        if (!(args[0] instanceof TLRPC.TL_inputSingleMedia)) {
            if ((args[0] instanceof TLRPC.TL_messages_sendMedia) || (args[0] instanceof TLRPC.TL_messages_editMessage)) {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileRefController$vyWlmYBtmkTZjWPv-ijNcALsBkc
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$sendErrorToObject$27$FileRefController(args);
                    }
                });
                return;
            }
            if (!(args[0] instanceof TLRPC.TL_messages_saveGif)) {
                if (!(args[0] instanceof TLRPC.TL_messages_saveRecentSticker)) {
                    if (!(args[0] instanceof TLRPC.TL_messages_faveSticker)) {
                        if (args[0] instanceof TLRPC.TL_messages_getAttachedStickers) {
                            getConnectionsManager().sendRequest((TLRPC.TL_messages_getAttachedStickers) args[0], (RequestDelegate) args[1]);
                            return;
                        }
                        if (reason == 0) {
                            TLRPC.TL_error error = new TLRPC.TL_error();
                            error.text = "not found parent object to request reference";
                            error.code = 400;
                            if (args[1] instanceof FileLoadOperation) {
                                FileLoadOperation fileLoadOperation = (FileLoadOperation) args[1];
                                fileLoadOperation.requestingReference = false;
                                fileLoadOperation.processRequestResult((FileLoadOperation.RequestInfo) args[2], error);
                                return;
                            }
                            return;
                        }
                        if (reason == 1 && (args[1] instanceof FileLoadOperation)) {
                            FileLoadOperation fileLoadOperation2 = (FileLoadOperation) args[1];
                            fileLoadOperation2.requestingReference = false;
                            fileLoadOperation2.onFail(false, 0);
                            return;
                        }
                        return;
                    }
                    return;
                }
                return;
            }
            return;
        }
        final TLRPC.TL_messages_sendMultiMedia req = (TLRPC.TL_messages_sendMultiMedia) args[1];
        final Object[] objects = this.multiMediaCache.get(req);
        if (objects != null) {
            this.multiMediaCache.remove(req);
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileRefController$Qwmw1V0Of7dwzdnb1RCm56R9_Ys
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$sendErrorToObject$26$FileRefController(req, objects);
                }
            });
        }
    }

    public /* synthetic */ void lambda$sendErrorToObject$26$FileRefController(TLRPC.TL_messages_sendMultiMedia req, Object[] objects) {
        getSendMessagesHelper().performSendMessageRequestMulti(req, (ArrayList) objects[1], (ArrayList) objects[2], null, (SendMessagesHelper.DelayedMessage) objects[4], ((Boolean) objects[5]).booleanValue());
    }

    public /* synthetic */ void lambda$sendErrorToObject$27$FileRefController(Object[] args) {
        getSendMessagesHelper().performSendMessageRequest((TLObject) args[0], (MessageObject) args[1], (String) args[2], (SendMessagesHelper.DelayedMessage) args[3], ((Boolean) args[4]).booleanValue(), (SendMessagesHelper.DelayedMessage) args[5], null, ((Boolean) args[6]).booleanValue());
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r7v0 */
    /* JADX WARN: Type inference failed for: r7v23 */
    /* JADX WARN: Type inference failed for: r7v24 */
    /* JADX WARN: Type inference failed for: r7v45 */
    /* JADX WARN: Type inference failed for: r7v46 */
    private boolean onRequestComplete(String str, String str2, TLObject tLObject, boolean z) {
        ArrayList<Requester> arrayList;
        TLRPC.InputFileLocation inputFileLocation;
        TLRPC.Vector vector;
        int i;
        byte[] bArr;
        byte[] bArr2;
        int i2;
        byte[] bArr3;
        ArrayList<Requester> arrayList2;
        boolean z2 = false;
        TLRPC.InputFileLocation inputFileLocation2 = null;
        int i3 = 1;
        if (str2 != null && (arrayList2 = this.parentRequester.get(str2)) != null) {
            int size = arrayList2.size();
            for (int i4 = 0; i4 < size; i4++) {
                Requester requester = arrayList2.get(i4);
                if (!requester.completed) {
                    if (onRequestComplete(requester.locationKey, null, tLObject, z && !z2)) {
                        z2 = true;
                    }
                }
            }
            if (z2) {
                putReponseToCache(str2, tLObject);
            }
            this.parentRequester.remove(str2);
        }
        byte[] fileReference = null;
        TLRPC.InputFileLocation[] inputFileLocationArr = null;
        boolean[] zArr = null;
        ArrayList<Requester> arrayList3 = this.locationRequester.get(str);
        if (arrayList3 == null) {
            return z2;
        }
        int i5 = 0;
        int size2 = arrayList3.size();
        while (i5 < size2) {
            Requester requester2 = arrayList3.get(i5);
            if (!requester2.completed) {
                if (requester2.location instanceof TLRPC.TL_inputFileLocation) {
                    inputFileLocationArr = new TLRPC.InputFileLocation[i3];
                    zArr = new boolean[i3];
                }
                requester2.completed = i3;
                if (tLObject instanceof TLRPC.messages_Messages) {
                    TLRPC.messages_Messages messages_messages = (TLRPC.messages_Messages) tLObject;
                    if (messages_messages.messages.isEmpty()) {
                        arrayList = arrayList3;
                    } else {
                        int i6 = 0;
                        int size3 = messages_messages.messages.size();
                        while (true) {
                            if (i6 >= size3) {
                                arrayList = arrayList3;
                                break;
                            }
                            TLRPC.Message message = messages_messages.messages.get(i6);
                            if (message.media != null) {
                                if (message.media.document != null) {
                                    i2 = size3;
                                    fileReference = getFileReference(message.media.document, requester2.location, zArr, inputFileLocationArr);
                                } else {
                                    i2 = size3;
                                    if (message.media.game != null) {
                                        byte[] fileReference2 = getFileReference(message.media.game.document, requester2.location, zArr, inputFileLocationArr);
                                        fileReference = fileReference2 == null ? getFileReference(message.media.game.photo, requester2.location, zArr, inputFileLocationArr) : fileReference2;
                                    } else if (message.media.photo != null) {
                                        fileReference = getFileReference(message.media.photo, requester2.location, zArr, inputFileLocationArr);
                                    } else if (message.media.webpage != null) {
                                        fileReference = getFileReference(message.media.webpage, requester2.location, zArr, inputFileLocationArr);
                                    }
                                }
                            } else {
                                i2 = size3;
                                if (message.action instanceof TLRPC.TL_messageActionChatEditPhoto) {
                                    fileReference = getFileReference(message.action.photo, requester2.location, zArr, inputFileLocationArr);
                                }
                            }
                            if (fileReference == null) {
                                i6++;
                                size3 = i2;
                            } else {
                                if (!z) {
                                    bArr3 = fileReference;
                                    arrayList = arrayList3;
                                } else {
                                    if (message.to_id == null || message.to_id.channel_id == 0) {
                                        bArr3 = fileReference;
                                        arrayList = arrayList3;
                                    } else {
                                        int i7 = 0;
                                        int size4 = messages_messages.chats.size();
                                        while (true) {
                                            if (i7 >= size4) {
                                                bArr3 = fileReference;
                                                arrayList = arrayList3;
                                                break;
                                            }
                                            int i8 = size4;
                                            TLRPC.Chat chat = messages_messages.chats.get(i7);
                                            bArr3 = fileReference;
                                            arrayList = arrayList3;
                                            if (chat.id != message.to_id.channel_id) {
                                                i7++;
                                                size4 = i8;
                                                fileReference = bArr3;
                                                arrayList3 = arrayList;
                                            } else if (chat.megagroup) {
                                                message.flags |= Integer.MIN_VALUE;
                                            }
                                        }
                                    }
                                    getMessagesStorage().replaceMessageIfExists(message, this.currentAccount, messages_messages.users, messages_messages.chats, false);
                                }
                                fileReference = bArr3;
                            }
                        }
                        if (fileReference == null) {
                            getMessagesStorage().replaceMessageIfExists(messages_messages.messages.get(0), this.currentAccount, messages_messages.users, messages_messages.chats, true);
                            if (BuildVars.DEBUG_VERSION) {
                                FileLog.d("file ref not found in messages, replacing message");
                            }
                        }
                    }
                    inputFileLocation = null;
                } else {
                    arrayList = arrayList3;
                    if (tLObject instanceof TLRPC.WebPage) {
                        fileReference = getFileReference((TLRPC.WebPage) tLObject, requester2.location, zArr, inputFileLocationArr);
                        inputFileLocation = null;
                    } else if (tLObject instanceof TLRPC.TL_account_wallPapers) {
                        TLRPC.TL_account_wallPapers tL_account_wallPapers = (TLRPC.TL_account_wallPapers) tLObject;
                        int size5 = tL_account_wallPapers.wallpapers.size();
                        for (int i9 = 0; i9 < size5; i9++) {
                            fileReference = getFileReference(((TLRPC.TL_wallPaper) tL_account_wallPapers.wallpapers.get(i9)).document, requester2.location, zArr, inputFileLocationArr);
                            if (fileReference != null) {
                                break;
                            }
                        }
                        if (fileReference != null && z) {
                            getMessagesStorage().putWallpapers(tL_account_wallPapers.wallpapers, 1);
                        }
                        inputFileLocation = null;
                    } else if (tLObject instanceof TLRPC.TL_wallPaper) {
                        TLRPC.TL_wallPaper tL_wallPaper = (TLRPC.TL_wallPaper) tLObject;
                        fileReference = getFileReference(tL_wallPaper.document, requester2.location, zArr, inputFileLocationArr);
                        if (fileReference != null && z) {
                            ArrayList<TLRPC.WallPaper> arrayList4 = new ArrayList<>();
                            arrayList4.add(tL_wallPaper);
                            getMessagesStorage().putWallpapers(arrayList4, 0);
                        }
                        inputFileLocation = null;
                    } else if (tLObject instanceof TLRPC.TL_theme) {
                        final TLRPC.TL_theme tL_theme = (TLRPC.TL_theme) tLObject;
                        fileReference = getFileReference(tL_theme.document, requester2.location, zArr, inputFileLocationArr);
                        if (fileReference != null && z) {
                            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileRefController$e7k92bqFm0KwH3u8DfNa3s-O2Ro
                                @Override // java.lang.Runnable
                                public final void run() {
                                    Theme.setThemeFileReference(tL_theme);
                                }
                            });
                        }
                        inputFileLocation = null;
                    } else if (tLObject instanceof TLRPC.Vector) {
                        TLRPC.Vector vector2 = (TLRPC.Vector) tLObject;
                        if (!vector2.objects.isEmpty()) {
                            int i10 = 0;
                            int size6 = vector2.objects.size();
                            while (i10 < size6) {
                                Object obj = vector2.objects.get(i10);
                                if (obj instanceof TLRPC.User) {
                                    final TLRPC.User user = (TLRPC.User) obj;
                                    byte[] fileReference3 = getFileReference(user, requester2.location, zArr, inputFileLocationArr);
                                    if (!z || fileReference3 == null) {
                                        vector = vector2;
                                        i = size6;
                                        bArr2 = fileReference3;
                                    } else {
                                        ArrayList<TLRPC.User> arrayList5 = new ArrayList<>();
                                        arrayList5.add(user);
                                        vector = vector2;
                                        i = size6;
                                        bArr2 = fileReference3;
                                        getMessagesStorage().putUsersAndChats(arrayList5, null, true, true);
                                        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileRefController$rEEsAEOYUmelxWQPV4-YjVDzMAg
                                            @Override // java.lang.Runnable
                                            public final void run() {
                                                this.f$0.lambda$onRequestComplete$29$FileRefController(user);
                                            }
                                        });
                                    }
                                    fileReference = bArr2;
                                } else {
                                    vector = vector2;
                                    i = size6;
                                    if (obj instanceof TLRPC.Chat) {
                                        final TLRPC.Chat chat2 = (TLRPC.Chat) obj;
                                        byte[] fileReference4 = getFileReference(chat2, requester2.location, zArr, inputFileLocationArr);
                                        if (!z || fileReference4 == null) {
                                            bArr = fileReference4;
                                        } else {
                                            ArrayList<TLRPC.Chat> arrayList6 = new ArrayList<>();
                                            arrayList6.add(chat2);
                                            bArr = fileReference4;
                                            getMessagesStorage().putUsersAndChats(null, arrayList6, true, true);
                                            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileRefController$PpgzsL-tpoQk9lCW4TiHXMHGjH4
                                                @Override // java.lang.Runnable
                                                public final void run() {
                                                    this.f$0.lambda$onRequestComplete$30$FileRefController(chat2);
                                                }
                                            });
                                        }
                                        fileReference = bArr;
                                    }
                                }
                                if (fileReference != null) {
                                    break;
                                }
                                i10++;
                                vector2 = vector;
                                size6 = i;
                            }
                        }
                        inputFileLocation = null;
                    } else if (tLObject instanceof TLRPC.TL_messages_chats) {
                        TLRPC.TL_messages_chats tL_messages_chats = (TLRPC.TL_messages_chats) tLObject;
                        if (tL_messages_chats.chats.isEmpty()) {
                            inputFileLocation = null;
                        } else {
                            int i11 = 0;
                            int size7 = tL_messages_chats.chats.size();
                            while (true) {
                                if (i11 >= size7) {
                                    inputFileLocation = null;
                                    break;
                                }
                                final TLRPC.Chat chat3 = tL_messages_chats.chats.get(i11);
                                fileReference = getFileReference(chat3, requester2.location, zArr, inputFileLocationArr);
                                if (fileReference == null) {
                                    i11++;
                                    tL_messages_chats = tL_messages_chats;
                                } else if (z) {
                                    ArrayList<TLRPC.Chat> arrayList7 = new ArrayList<>();
                                    arrayList7.add(chat3);
                                    inputFileLocation = null;
                                    getMessagesStorage().putUsersAndChats(null, arrayList7, true, true);
                                    AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileRefController$xcCqZttnrAVIQ1qenzMQ5oy5BCM
                                        @Override // java.lang.Runnable
                                        public final void run() {
                                            this.f$0.lambda$onRequestComplete$31$FileRefController(chat3);
                                        }
                                    });
                                } else {
                                    inputFileLocation = null;
                                }
                            }
                        }
                    } else {
                        inputFileLocation = null;
                        if (tLObject instanceof TLRPC.TL_messages_savedGifs) {
                            TLRPC.TL_messages_savedGifs tL_messages_savedGifs = (TLRPC.TL_messages_savedGifs) tLObject;
                            int size8 = tL_messages_savedGifs.gifs.size();
                            for (int i12 = 0; i12 < size8; i12++) {
                                fileReference = getFileReference(tL_messages_savedGifs.gifs.get(i12), requester2.location, zArr, inputFileLocationArr);
                                if (fileReference != null) {
                                    break;
                                }
                            }
                            if (z) {
                                getMediaDataController().processLoadedRecentDocuments(0, tL_messages_savedGifs.gifs, true, 0, true);
                            }
                        } else if (tLObject instanceof TLRPC.TL_messages_stickerSet) {
                            final TLRPC.TL_messages_stickerSet tL_messages_stickerSet = (TLRPC.TL_messages_stickerSet) tLObject;
                            if (fileReference == null) {
                                int size9 = tL_messages_stickerSet.documents.size();
                                for (int i13 = 0; i13 < size9; i13++) {
                                    fileReference = getFileReference(tL_messages_stickerSet.documents.get(i13), requester2.location, zArr, inputFileLocationArr);
                                    if (fileReference != null) {
                                        break;
                                    }
                                }
                            }
                            if (z) {
                                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileRefController$MNWcuF-vb0JEx7tDIRnqXPyf9dE
                                    @Override // java.lang.Runnable
                                    public final void run() {
                                        this.f$0.lambda$onRequestComplete$32$FileRefController(tL_messages_stickerSet);
                                    }
                                });
                            }
                        } else if (tLObject instanceof TLRPC.TL_messages_recentStickers) {
                            TLRPC.TL_messages_recentStickers tL_messages_recentStickers = (TLRPC.TL_messages_recentStickers) tLObject;
                            int size10 = tL_messages_recentStickers.stickers.size();
                            for (int i14 = 0; i14 < size10; i14++) {
                                fileReference = getFileReference(tL_messages_recentStickers.stickers.get(i14), requester2.location, zArr, inputFileLocationArr);
                                if (fileReference != null) {
                                    break;
                                }
                            }
                            if (z) {
                                getMediaDataController().processLoadedRecentDocuments(0, tL_messages_recentStickers.stickers, false, 0, true);
                            }
                        } else if (tLObject instanceof TLRPC.TL_messages_favedStickers) {
                            TLRPC.TL_messages_favedStickers tL_messages_favedStickers = (TLRPC.TL_messages_favedStickers) tLObject;
                            int size11 = tL_messages_favedStickers.stickers.size();
                            for (int i15 = 0; i15 < size11; i15++) {
                                fileReference = getFileReference(tL_messages_favedStickers.stickers.get(i15), requester2.location, zArr, inputFileLocationArr);
                                if (fileReference != null) {
                                    break;
                                }
                            }
                            if (z) {
                                getMediaDataController().processLoadedRecentDocuments(2, tL_messages_favedStickers.stickers, false, 0, true);
                            }
                        } else if (tLObject instanceof TLRPC.photos_Photos) {
                            TLRPC.photos_Photos photos_photos = (TLRPC.photos_Photos) tLObject;
                            int size12 = photos_photos.photos.size();
                            for (int i16 = 0; i16 < size12; i16++) {
                                fileReference = getFileReference(photos_photos.photos.get(i16), requester2.location, zArr, inputFileLocationArr);
                                if (fileReference != null) {
                                    break;
                                }
                            }
                        }
                    }
                }
                if (fileReference != null) {
                    onUpdateObjectReference(requester2, fileReference, inputFileLocationArr != null ? inputFileLocationArr[0] : inputFileLocation);
                    z2 = true;
                    i3 = 1;
                } else {
                    i3 = 1;
                    sendErrorToObject(requester2.args, 1);
                }
            } else {
                inputFileLocation = inputFileLocation2;
                arrayList = arrayList3;
            }
            i5++;
            inputFileLocation2 = inputFileLocation;
            arrayList3 = arrayList;
            i3 = i3;
        }
        this.locationRequester.remove(str);
        if (z2) {
            putReponseToCache(str, tLObject);
        }
        return z2;
    }

    public /* synthetic */ void lambda$onRequestComplete$29$FileRefController(TLRPC.User user) {
        getMessagesController().putUser(user, false);
    }

    public /* synthetic */ void lambda$onRequestComplete$30$FileRefController(TLRPC.Chat chat) {
        getMessagesController().putChat(chat, false);
    }

    public /* synthetic */ void lambda$onRequestComplete$31$FileRefController(TLRPC.Chat chat) {
        getMessagesController().putChat(chat, false);
    }

    public /* synthetic */ void lambda$onRequestComplete$32$FileRefController(TLRPC.TL_messages_stickerSet stickerSet) {
        getMediaDataController().replaceStickerSet(stickerSet);
    }

    private void cleanupCache() {
        if (Math.abs(SystemClock.uptimeMillis() - this.lastCleanupTime) < 600000) {
            return;
        }
        this.lastCleanupTime = SystemClock.uptimeMillis();
        ArrayList<String> keysToDelete = null;
        for (Map.Entry<String, CachedResult> entry : this.responseCache.entrySet()) {
            CachedResult cachedResult = entry.getValue();
            if (Math.abs(SystemClock.uptimeMillis() - cachedResult.firstQueryTime) >= 600000) {
                if (keysToDelete == null) {
                    keysToDelete = new ArrayList<>();
                }
                keysToDelete.add(entry.getKey());
            }
        }
        if (keysToDelete != null) {
            int size = keysToDelete.size();
            for (int a = 0; a < size; a++) {
                this.responseCache.remove(keysToDelete.get(a));
            }
        }
    }

    private CachedResult getCachedResponse(String key) {
        CachedResult cachedResult = this.responseCache.get(key);
        if (cachedResult != null && Math.abs(SystemClock.uptimeMillis() - cachedResult.firstQueryTime) >= 600000) {
            this.responseCache.remove(key);
            return null;
        }
        return cachedResult;
    }

    private void putReponseToCache(String key, TLObject response) {
        CachedResult cachedResult = this.responseCache.get(key);
        if (cachedResult == null) {
            cachedResult = new CachedResult();
            cachedResult.response = response;
            cachedResult.firstQueryTime = SystemClock.uptimeMillis();
            this.responseCache.put(key, cachedResult);
        }
        cachedResult.lastQueryTime = SystemClock.uptimeMillis();
    }

    private byte[] getFileReference(TLRPC.Document document, TLRPC.InputFileLocation location, boolean[] needReplacement, TLRPC.InputFileLocation[] replacement) {
        if (document == null || location == null) {
            return null;
        }
        if (!(location instanceof TLRPC.TL_inputDocumentFileLocation)) {
            int size = document.thumbs.size();
            for (int a = 0; a < size; a++) {
                TLRPC.PhotoSize photoSize = document.thumbs.get(a);
                byte[] result = getFileReference(photoSize, location, needReplacement);
                if (needReplacement != null && needReplacement[0]) {
                    replacement[0] = new TLRPC.TL_inputDocumentFileLocation();
                    replacement[0].id = document.id;
                    replacement[0].volume_id = location.volume_id;
                    replacement[0].local_id = location.local_id;
                    replacement[0].access_hash = document.access_hash;
                    replacement[0].file_reference = document.file_reference;
                    replacement[0].thumb_size = photoSize.type;
                    return document.file_reference;
                }
                if (result != null) {
                    return result;
                }
            }
        } else if (document.id == location.id) {
            return document.file_reference;
        }
        return null;
    }

    private boolean getPeerReferenceReplacement(TLRPC.User user, TLRPC.Chat chat, boolean z, TLRPC.InputFileLocation inputFileLocation, TLRPC.InputFileLocation[] inputFileLocationArr, boolean[] zArr) {
        TLRPC.InputPeer inputPeer;
        if (zArr == null || !zArr[0]) {
            return false;
        }
        inputFileLocationArr[0] = new TLRPC.TL_inputPeerPhotoFileLocation();
        inputFileLocationArr[0].id = inputFileLocation.volume_id;
        inputFileLocationArr[0].volume_id = inputFileLocation.volume_id;
        inputFileLocationArr[0].local_id = inputFileLocation.local_id;
        inputFileLocationArr[0].big = z;
        if (user != null) {
            TLRPC.TL_inputPeerUser tL_inputPeerUser = new TLRPC.TL_inputPeerUser();
            tL_inputPeerUser.user_id = user.id;
            tL_inputPeerUser.access_hash = user.access_hash;
            inputPeer = tL_inputPeerUser;
        } else if (ChatObject.isChannel(chat)) {
            TLRPC.TL_inputPeerChat tL_inputPeerChat = new TLRPC.TL_inputPeerChat();
            tL_inputPeerChat.chat_id = chat.id;
            inputPeer = tL_inputPeerChat;
        } else {
            TLRPC.TL_inputPeerChannel tL_inputPeerChannel = new TLRPC.TL_inputPeerChannel();
            tL_inputPeerChannel.channel_id = chat.id;
            tL_inputPeerChannel.access_hash = chat.access_hash;
            inputPeer = tL_inputPeerChannel;
        }
        inputFileLocationArr[0].peer = inputPeer;
        return true;
    }

    private byte[] getFileReference(TLRPC.User user, TLRPC.InputFileLocation location, boolean[] needReplacement, TLRPC.InputFileLocation[] replacement) {
        if (user == null || user.photo == null || !(location instanceof TLRPC.TL_inputFileLocation)) {
            return null;
        }
        byte[] result = getFileReference(user.photo.photo_small, location, needReplacement);
        if (getPeerReferenceReplacement(user, null, false, location, replacement, needReplacement)) {
            return new byte[0];
        }
        if (result == null) {
            result = getFileReference(user.photo.photo_big, location, needReplacement);
            if (getPeerReferenceReplacement(user, null, true, location, replacement, needReplacement)) {
                return new byte[0];
            }
        }
        return result;
    }

    private byte[] getFileReference(TLRPC.Chat chat, TLRPC.InputFileLocation location, boolean[] needReplacement, TLRPC.InputFileLocation[] replacement) {
        if (chat == null || chat.photo == null || !(location instanceof TLRPC.TL_inputFileLocation)) {
            return null;
        }
        byte[] result = getFileReference(chat.photo.photo_small, location, needReplacement);
        if (getPeerReferenceReplacement(null, chat, false, location, replacement, needReplacement)) {
            return new byte[0];
        }
        if (result == null) {
            result = getFileReference(chat.photo.photo_big, location, needReplacement);
            if (getPeerReferenceReplacement(null, chat, true, location, replacement, needReplacement)) {
                return new byte[0];
            }
        }
        return result;
    }

    private byte[] getFileReference(TLRPC.Photo photo, TLRPC.InputFileLocation location, boolean[] needReplacement, TLRPC.InputFileLocation[] replacement) {
        if (photo == null) {
            return null;
        }
        if (location instanceof TLRPC.TL_inputPhotoFileLocation) {
            if (photo.id == location.id) {
                return photo.file_reference;
            }
            return null;
        }
        if (location instanceof TLRPC.TL_inputFileLocation) {
            int size = photo.sizes.size();
            for (int a = 0; a < size; a++) {
                TLRPC.PhotoSize photoSize = photo.sizes.get(a);
                byte[] result = getFileReference(photoSize, location, needReplacement);
                if (needReplacement != null && needReplacement[0]) {
                    replacement[0] = new TLRPC.TL_inputPhotoFileLocation();
                    replacement[0].id = photo.id;
                    replacement[0].volume_id = location.volume_id;
                    replacement[0].local_id = location.local_id;
                    replacement[0].access_hash = photo.access_hash;
                    replacement[0].file_reference = photo.file_reference;
                    replacement[0].thumb_size = photoSize.type;
                    return photo.file_reference;
                }
                if (result != null) {
                    return result;
                }
            }
        }
        return null;
    }

    private byte[] getFileReference(TLRPC.PhotoSize photoSize, TLRPC.InputFileLocation location, boolean[] needReplacement) {
        if (photoSize == null || !(location instanceof TLRPC.TL_inputFileLocation)) {
            return null;
        }
        return getFileReference(photoSize.location, location, needReplacement);
    }

    private byte[] getFileReference(TLRPC.FileLocation fileLocation, TLRPC.InputFileLocation location, boolean[] needReplacement) {
        if (fileLocation == null || !(location instanceof TLRPC.TL_inputFileLocation) || fileLocation.local_id != location.local_id || fileLocation.volume_id != location.volume_id) {
            return null;
        }
        if (fileLocation.file_reference == null && needReplacement != null) {
            needReplacement[0] = true;
        }
        return fileLocation.file_reference;
    }

    private byte[] getFileReference(TLRPC.WebPage webpage, TLRPC.InputFileLocation location, boolean[] needReplacement, TLRPC.InputFileLocation[] replacement) {
        byte[] result = getFileReference(webpage.document, location, needReplacement, replacement);
        if (result != null) {
            return result;
        }
        byte[] result2 = getFileReference(webpage.photo, location, needReplacement, replacement);
        if (result2 != null) {
            return result2;
        }
        if (result2 == null && webpage.cached_page != null) {
            int size2 = webpage.cached_page.documents.size();
            for (int b = 0; b < size2; b++) {
                byte[] result3 = getFileReference(webpage.cached_page.documents.get(b), location, needReplacement, replacement);
                if (result3 != null) {
                    return result3;
                }
            }
            int size22 = webpage.cached_page.photos.size();
            for (int b2 = 0; b2 < size22; b2++) {
                byte[] result4 = getFileReference(webpage.cached_page.photos.get(b2), location, needReplacement, replacement);
                if (result4 != null) {
                    return result4;
                }
            }
            return null;
        }
        return null;
    }

    public static boolean isFileRefError(String error) {
        return "FILEREF_EXPIRED".equals(error) || "FILE_REFERENCE_EXPIRED".equals(error) || "FILE_REFERENCE_EMPTY".equals(error) || (error != null && error.startsWith("FILE_REFERENCE_"));
    }
}
