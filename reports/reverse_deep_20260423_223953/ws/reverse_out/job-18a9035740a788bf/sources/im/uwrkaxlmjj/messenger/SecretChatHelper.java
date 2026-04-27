package im.uwrkaxlmjj.messenger;

import android.app.Activity;
import android.content.Context;
import android.content.DialogInterface;
import android.util.LongSparseArray;
import android.util.SparseArray;
import com.google.android.exoplayer2.util.MimeTypes;
import im.uwrkaxlmjj.messenger.SecretChatHelper;
import im.uwrkaxlmjj.messenger.SendMessagesHelper;
import im.uwrkaxlmjj.sqlite.SQLiteCursor;
import im.uwrkaxlmjj.tgnet.AbstractSerializedData;
import im.uwrkaxlmjj.tgnet.NativeByteBuffer;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import java.io.File;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;

/* JADX INFO: loaded from: classes2.dex */
public class SecretChatHelper extends BaseController {
    public static final int CURRENT_SECRET_CHAT_LAYER = 101;
    private static volatile SecretChatHelper[] Instance = new SecretChatHelper[3];
    private SparseArray<TLRPC.EncryptedChat> acceptingChats;
    public ArrayList<TLRPC.Update> delayedEncryptedChatUpdates;
    private ArrayList<Long> pendingEncMessagesToDelete;
    private SparseArray<ArrayList<TL_decryptedMessageHolder>> secretHolesQueue;
    private ArrayList<Integer> sendingNotifyLayer;
    private boolean startingSecretChat;

    public static class TL_decryptedMessageHolder extends TLObject {
        public static int constructor = 1431655929;
        public int date;
        public int decryptedWithVersion;
        public TLRPC.EncryptedFile file;
        public TLRPC.TL_decryptedMessageLayer layer;
        public boolean new_key_used;

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void readParams(AbstractSerializedData stream, boolean exception) {
            stream.readInt64(exception);
            this.date = stream.readInt32(exception);
            this.layer = TLRPC.TL_decryptedMessageLayer.TLdeserialize(stream, stream.readInt32(exception), exception);
            if (stream.readBool(exception)) {
                this.file = TLRPC.EncryptedFile.TLdeserialize(stream, stream.readInt32(exception), exception);
            }
            this.new_key_used = stream.readBool(exception);
        }

        @Override // im.uwrkaxlmjj.tgnet.TLObject
        public void serializeToStream(AbstractSerializedData stream) {
            stream.writeInt32(constructor);
            stream.writeInt64(0L);
            stream.writeInt32(this.date);
            this.layer.serializeToStream(stream);
            stream.writeBool(this.file != null);
            TLRPC.EncryptedFile encryptedFile = this.file;
            if (encryptedFile != null) {
                encryptedFile.serializeToStream(stream);
            }
            stream.writeBool(this.new_key_used);
        }
    }

    public static SecretChatHelper getInstance(int num) {
        SecretChatHelper localInstance = Instance[num];
        if (localInstance == null) {
            synchronized (SecretChatHelper.class) {
                localInstance = Instance[num];
                if (localInstance == null) {
                    SecretChatHelper[] secretChatHelperArr = Instance;
                    SecretChatHelper secretChatHelper = new SecretChatHelper(num);
                    localInstance = secretChatHelper;
                    secretChatHelperArr[num] = secretChatHelper;
                }
            }
        }
        return localInstance;
    }

    public SecretChatHelper(int instance) {
        super(instance);
        this.sendingNotifyLayer = new ArrayList<>();
        this.secretHolesQueue = new SparseArray<>();
        this.acceptingChats = new SparseArray<>();
        this.delayedEncryptedChatUpdates = new ArrayList<>();
        this.pendingEncMessagesToDelete = new ArrayList<>();
        this.startingSecretChat = false;
    }

    public void cleanup() {
        this.sendingNotifyLayer.clear();
        this.acceptingChats.clear();
        this.secretHolesQueue.clear();
        this.delayedEncryptedChatUpdates.clear();
        this.pendingEncMessagesToDelete.clear();
        this.startingSecretChat = false;
    }

    protected void processPendingEncMessages() {
        if (!this.pendingEncMessagesToDelete.isEmpty()) {
            final ArrayList<Long> pendingEncMessagesToDeleteCopy = new ArrayList<>(this.pendingEncMessagesToDelete);
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SecretChatHelper$0ZJaC1kXsM04HtcE4oQ_v34jjAA
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$processPendingEncMessages$0$SecretChatHelper(pendingEncMessagesToDeleteCopy);
                }
            });
            ArrayList<Long> arr = new ArrayList<>(this.pendingEncMessagesToDelete);
            getMessagesStorage().markMessagesAsDeletedByRandoms(arr);
            this.pendingEncMessagesToDelete.clear();
        }
    }

    public /* synthetic */ void lambda$processPendingEncMessages$0$SecretChatHelper(ArrayList pendingEncMessagesToDeleteCopy) {
        for (int a = 0; a < pendingEncMessagesToDeleteCopy.size(); a++) {
            MessageObject messageObject = getMessagesController().dialogMessagesByRandomIds.get(((Long) pendingEncMessagesToDeleteCopy.get(a)).longValue());
            if (messageObject != null) {
                messageObject.deleted = true;
            }
        }
    }

    private TLRPC.TL_messageService createServiceSecretMessage(TLRPC.EncryptedChat encryptedChat, TLRPC.DecryptedMessageAction decryptedMessage) {
        TLRPC.TL_messageService newMsg = new TLRPC.TL_messageService();
        newMsg.action = new TLRPC.TL_messageEncryptedAction();
        newMsg.action.encryptedAction = decryptedMessage;
        int newMessageId = getUserConfig().getNewMessageId();
        newMsg.id = newMessageId;
        newMsg.local_id = newMessageId;
        newMsg.from_id = getUserConfig().getClientUserId();
        newMsg.unread = true;
        newMsg.out = true;
        newMsg.flags = 256;
        newMsg.dialog_id = ((long) encryptedChat.id) << 32;
        newMsg.to_id = new TLRPC.TL_peerUser();
        newMsg.send_state = 1;
        if (encryptedChat.participant_id == getUserConfig().getClientUserId()) {
            newMsg.to_id.user_id = encryptedChat.admin_id;
        } else {
            newMsg.to_id.user_id = encryptedChat.participant_id;
        }
        if ((decryptedMessage instanceof TLRPC.TL_decryptedMessageActionScreenshotMessages) || (decryptedMessage instanceof TLRPC.TL_decryptedMessageActionSetMessageTTL)) {
            newMsg.date = getConnectionsManager().getCurrentTime();
        } else {
            newMsg.date = 0;
        }
        newMsg.random_id = getSendMessagesHelper().getNextRandomId();
        getUserConfig().saveConfig(false);
        ArrayList<TLRPC.Message> arr = new ArrayList<>();
        arr.add(newMsg);
        getMessagesStorage().putMessages(arr, false, true, true, 0, false);
        return newMsg;
    }

    public void sendMessagesReadMessage(TLRPC.EncryptedChat encryptedChat, ArrayList<Long> random_ids, TLRPC.Message resendMessage) {
        TLRPC.Message message;
        if (!(encryptedChat instanceof TLRPC.TL_encryptedChat)) {
            return;
        }
        TLRPC.TL_decryptedMessageService reqSend = new TLRPC.TL_decryptedMessageService();
        if (resendMessage != null) {
            reqSend.action = resendMessage.action.encryptedAction;
            message = resendMessage;
        } else {
            reqSend.action = new TLRPC.TL_decryptedMessageActionReadMessages();
            reqSend.action.random_ids = random_ids;
            message = createServiceSecretMessage(encryptedChat, reqSend.action);
        }
        reqSend.random_id = message.random_id;
        performSendEncryptedRequest(reqSend, message, encryptedChat, null, null, null);
    }

    protected void processUpdateEncryption(TLRPC.TL_updateEncryption update, ConcurrentHashMap<Integer, TLRPC.User> usersDict) {
        final TLRPC.EncryptedChat newChat = update.chat;
        long dialog_id = ((long) newChat.id) << 32;
        final TLRPC.EncryptedChat existingChat = getMessagesController().getEncryptedChatDB(newChat.id, false);
        if ((newChat instanceof TLRPC.TL_encryptedChatRequested) && existingChat == null) {
            int user_id = newChat.participant_id;
            if (user_id == getUserConfig().getClientUserId()) {
                user_id = newChat.admin_id;
            }
            TLRPC.User user = getMessagesController().getUser(Integer.valueOf(user_id));
            if (user == null) {
                user = usersDict.get(Integer.valueOf(user_id));
            }
            newChat.user_id = user_id;
            final TLRPC.Dialog dialog = new TLRPC.TL_dialog();
            dialog.id = dialog_id;
            dialog.unread_count = 0;
            dialog.top_message = 0;
            dialog.last_message_date = update.date;
            getMessagesController().putEncryptedChat(newChat, false);
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SecretChatHelper$-63miSKQmYIPMBkweYPMV9lHntM
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$processUpdateEncryption$1$SecretChatHelper(dialog);
                }
            });
            getMessagesStorage().putEncryptedChat(newChat, user, dialog);
            acceptSecretChat(newChat);
            return;
        }
        if (newChat instanceof TLRPC.TL_encryptedChat) {
            if ((existingChat instanceof TLRPC.TL_encryptedChatWaiting) && (existingChat.auth_key == null || existingChat.auth_key.length == 1)) {
                newChat.a_or_b = existingChat.a_or_b;
                newChat.user_id = existingChat.user_id;
                processAcceptedSecretChat(newChat);
                return;
            } else {
                if (existingChat == null && this.startingSecretChat) {
                    this.delayedEncryptedChatUpdates.add(update);
                    return;
                }
                return;
            }
        }
        if (existingChat != null) {
            newChat.user_id = existingChat.user_id;
            newChat.auth_key = existingChat.auth_key;
            newChat.key_create_date = existingChat.key_create_date;
            newChat.key_use_count_in = existingChat.key_use_count_in;
            newChat.key_use_count_out = existingChat.key_use_count_out;
            newChat.ttl = existingChat.ttl;
            newChat.seq_in = existingChat.seq_in;
            newChat.seq_out = existingChat.seq_out;
            newChat.admin_id = existingChat.admin_id;
            newChat.mtproto_seq = existingChat.mtproto_seq;
        }
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SecretChatHelper$8Y2zUhwlw47SgKQgDBwMVyQuguc
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$processUpdateEncryption$2$SecretChatHelper(existingChat, newChat);
            }
        });
    }

    public /* synthetic */ void lambda$processUpdateEncryption$1$SecretChatHelper(TLRPC.Dialog dialog) {
        getMessagesController().dialogs_dict.put(dialog.id, dialog);
        getMessagesController().allDialogs.add(dialog);
        getMessagesController().sortDialogs(null);
        getNotificationCenter().postNotificationName(NotificationCenter.dialogsNeedReload, new Object[0]);
    }

    public /* synthetic */ void lambda$processUpdateEncryption$2$SecretChatHelper(TLRPC.EncryptedChat exist, TLRPC.EncryptedChat newChat) {
        if (exist != null) {
            getMessagesController().putEncryptedChat(newChat, false);
        }
        getMessagesStorage().updateEncryptedChat(newChat);
        getNotificationCenter().postNotificationName(NotificationCenter.encryptedChatUpdated, newChat);
    }

    public void sendMessagesDeleteMessage(TLRPC.EncryptedChat encryptedChat, ArrayList<Long> random_ids, TLRPC.Message resendMessage) {
        TLRPC.Message message;
        if (!(encryptedChat instanceof TLRPC.TL_encryptedChat)) {
            return;
        }
        TLRPC.TL_decryptedMessageService reqSend = new TLRPC.TL_decryptedMessageService();
        if (resendMessage != null) {
            reqSend.action = resendMessage.action.encryptedAction;
            message = resendMessage;
        } else {
            reqSend.action = new TLRPC.TL_decryptedMessageActionDeleteMessages();
            reqSend.action.random_ids = random_ids;
            message = createServiceSecretMessage(encryptedChat, reqSend.action);
        }
        reqSend.random_id = message.random_id;
        performSendEncryptedRequest(reqSend, message, encryptedChat, null, null, null);
    }

    public void sendClearHistoryMessage(TLRPC.EncryptedChat encryptedChat, TLRPC.Message resendMessage) {
        TLRPC.Message message;
        if (!(encryptedChat instanceof TLRPC.TL_encryptedChat)) {
            return;
        }
        TLRPC.TL_decryptedMessageService reqSend = new TLRPC.TL_decryptedMessageService();
        if (resendMessage != null) {
            reqSend.action = resendMessage.action.encryptedAction;
            message = resendMessage;
        } else {
            reqSend.action = new TLRPC.TL_decryptedMessageActionFlushHistory();
            message = createServiceSecretMessage(encryptedChat, reqSend.action);
        }
        reqSend.random_id = message.random_id;
        performSendEncryptedRequest(reqSend, message, encryptedChat, null, null, null);
    }

    public void sendNotifyLayerMessage(TLRPC.EncryptedChat encryptedChat, TLRPC.Message resendMessage) {
        TLRPC.Message message;
        if (!(encryptedChat instanceof TLRPC.TL_encryptedChat) || this.sendingNotifyLayer.contains(Integer.valueOf(encryptedChat.id))) {
            return;
        }
        this.sendingNotifyLayer.add(Integer.valueOf(encryptedChat.id));
        TLRPC.TL_decryptedMessageService reqSend = new TLRPC.TL_decryptedMessageService();
        if (resendMessage != null) {
            reqSend.action = resendMessage.action.encryptedAction;
            message = resendMessage;
        } else {
            reqSend.action = new TLRPC.TL_decryptedMessageActionNotifyLayer();
            reqSend.action.layer = 101;
            message = createServiceSecretMessage(encryptedChat, reqSend.action);
        }
        reqSend.random_id = message.random_id;
        performSendEncryptedRequest(reqSend, message, encryptedChat, null, null, null);
    }

    public void sendRequestKeyMessage(TLRPC.EncryptedChat encryptedChat, TLRPC.Message resendMessage) {
        TLRPC.Message message;
        if (!(encryptedChat instanceof TLRPC.TL_encryptedChat)) {
            return;
        }
        TLRPC.TL_decryptedMessageService reqSend = new TLRPC.TL_decryptedMessageService();
        if (resendMessage != null) {
            reqSend.action = resendMessage.action.encryptedAction;
            message = resendMessage;
        } else {
            reqSend.action = new TLRPC.TL_decryptedMessageActionRequestKey();
            reqSend.action.exchange_id = encryptedChat.exchange_id;
            reqSend.action.g_a = encryptedChat.g_a;
            message = createServiceSecretMessage(encryptedChat, reqSend.action);
        }
        reqSend.random_id = message.random_id;
        performSendEncryptedRequest(reqSend, message, encryptedChat, null, null, null);
    }

    public void sendAcceptKeyMessage(TLRPC.EncryptedChat encryptedChat, TLRPC.Message resendMessage) {
        TLRPC.Message message;
        if (!(encryptedChat instanceof TLRPC.TL_encryptedChat)) {
            return;
        }
        TLRPC.TL_decryptedMessageService reqSend = new TLRPC.TL_decryptedMessageService();
        if (resendMessage != null) {
            reqSend.action = resendMessage.action.encryptedAction;
            message = resendMessage;
        } else {
            reqSend.action = new TLRPC.TL_decryptedMessageActionAcceptKey();
            reqSend.action.exchange_id = encryptedChat.exchange_id;
            reqSend.action.key_fingerprint = encryptedChat.future_key_fingerprint;
            reqSend.action.g_b = encryptedChat.g_a_or_b;
            message = createServiceSecretMessage(encryptedChat, reqSend.action);
        }
        reqSend.random_id = message.random_id;
        performSendEncryptedRequest(reqSend, message, encryptedChat, null, null, null);
    }

    public void sendCommitKeyMessage(TLRPC.EncryptedChat encryptedChat, TLRPC.Message resendMessage) {
        TLRPC.Message message;
        if (!(encryptedChat instanceof TLRPC.TL_encryptedChat)) {
            return;
        }
        TLRPC.TL_decryptedMessageService reqSend = new TLRPC.TL_decryptedMessageService();
        if (resendMessage != null) {
            reqSend.action = resendMessage.action.encryptedAction;
            message = resendMessage;
        } else {
            reqSend.action = new TLRPC.TL_decryptedMessageActionCommitKey();
            reqSend.action.exchange_id = encryptedChat.exchange_id;
            reqSend.action.key_fingerprint = encryptedChat.future_key_fingerprint;
            message = createServiceSecretMessage(encryptedChat, reqSend.action);
        }
        reqSend.random_id = message.random_id;
        performSendEncryptedRequest(reqSend, message, encryptedChat, null, null, null);
    }

    public void sendAbortKeyMessage(TLRPC.EncryptedChat encryptedChat, TLRPC.Message resendMessage, long excange_id) {
        TLRPC.Message message;
        if (!(encryptedChat instanceof TLRPC.TL_encryptedChat)) {
            return;
        }
        TLRPC.TL_decryptedMessageService reqSend = new TLRPC.TL_decryptedMessageService();
        if (resendMessage != null) {
            reqSend.action = resendMessage.action.encryptedAction;
            message = resendMessage;
        } else {
            reqSend.action = new TLRPC.TL_decryptedMessageActionAbortKey();
            reqSend.action.exchange_id = excange_id;
            message = createServiceSecretMessage(encryptedChat, reqSend.action);
        }
        reqSend.random_id = message.random_id;
        performSendEncryptedRequest(reqSend, message, encryptedChat, null, null, null);
    }

    public void sendNoopMessage(TLRPC.EncryptedChat encryptedChat, TLRPC.Message resendMessage) {
        TLRPC.Message message;
        if (!(encryptedChat instanceof TLRPC.TL_encryptedChat)) {
            return;
        }
        TLRPC.TL_decryptedMessageService reqSend = new TLRPC.TL_decryptedMessageService();
        if (resendMessage != null) {
            reqSend.action = resendMessage.action.encryptedAction;
            message = resendMessage;
        } else {
            reqSend.action = new TLRPC.TL_decryptedMessageActionNoop();
            message = createServiceSecretMessage(encryptedChat, reqSend.action);
        }
        reqSend.random_id = message.random_id;
        performSendEncryptedRequest(reqSend, message, encryptedChat, null, null, null);
    }

    public void sendTTLMessage(TLRPC.EncryptedChat encryptedChat, TLRPC.Message resendMessage) {
        TLRPC.Message message;
        if (!(encryptedChat instanceof TLRPC.TL_encryptedChat)) {
            return;
        }
        TLRPC.TL_decryptedMessageService reqSend = new TLRPC.TL_decryptedMessageService();
        if (resendMessage != null) {
            reqSend.action = resendMessage.action.encryptedAction;
            message = resendMessage;
        } else {
            reqSend.action = new TLRPC.TL_decryptedMessageActionSetMessageTTL();
            reqSend.action.ttl_seconds = encryptedChat.ttl;
            TLRPC.TL_messageService message2 = createServiceSecretMessage(encryptedChat, reqSend.action);
            MessageObject newMsgObj = new MessageObject(this.currentAccount, message2, false);
            newMsgObj.messageOwner.send_state = 1;
            ArrayList<MessageObject> objArr = new ArrayList<>();
            objArr.add(newMsgObj);
            getMessagesController().updateInterfaceWithMessages(message2.dialog_id, objArr, false);
            getNotificationCenter().postNotificationName(NotificationCenter.dialogsNeedReload, new Object[0]);
            message = message2;
        }
        reqSend.random_id = message.random_id;
        performSendEncryptedRequest(reqSend, message, encryptedChat, null, null, null);
    }

    public void sendScreenshotMessage(TLRPC.EncryptedChat encryptedChat, ArrayList<Long> random_ids, TLRPC.Message resendMessage) {
        TLRPC.Message message;
        if (!(encryptedChat instanceof TLRPC.TL_encryptedChat)) {
            return;
        }
        TLRPC.TL_decryptedMessageService reqSend = new TLRPC.TL_decryptedMessageService();
        if (resendMessage != null) {
            reqSend.action = resendMessage.action.encryptedAction;
            message = resendMessage;
        } else {
            reqSend.action = new TLRPC.TL_decryptedMessageActionScreenshotMessages();
            reqSend.action.random_ids = random_ids;
            TLRPC.TL_messageService message2 = createServiceSecretMessage(encryptedChat, reqSend.action);
            MessageObject newMsgObj = new MessageObject(this.currentAccount, message2, false);
            newMsgObj.messageOwner.send_state = 1;
            ArrayList<MessageObject> objArr = new ArrayList<>();
            objArr.add(newMsgObj);
            getMessagesController().updateInterfaceWithMessages(message2.dialog_id, objArr, false);
            getNotificationCenter().postNotificationName(NotificationCenter.dialogsNeedReload, new Object[0]);
            message = message2;
        }
        reqSend.random_id = message.random_id;
        performSendEncryptedRequest(reqSend, message, encryptedChat, null, null, null);
    }

    private void updateMediaPaths(MessageObject newMsgObj, TLRPC.EncryptedFile file, TLRPC.DecryptedMessage decryptedMessage, String originalPath) {
        TLRPC.Message newMsg = newMsgObj.messageOwner;
        if (file != null) {
            if ((newMsg.media instanceof TLRPC.TL_messageMediaPhoto) && newMsg.media.photo != null) {
                TLRPC.PhotoSize size = newMsg.media.photo.sizes.get(newMsg.media.photo.sizes.size() - 1);
                String fileName = size.location.volume_id + "_" + size.location.local_id;
                size.location = new TLRPC.TL_fileEncryptedLocation();
                size.location.key = decryptedMessage.media.key;
                size.location.iv = decryptedMessage.media.iv;
                size.location.dc_id = file.dc_id;
                size.location.volume_id = file.id;
                size.location.secret = file.access_hash;
                size.location.local_id = file.key_fingerprint;
                String fileName2 = size.location.volume_id + "_" + size.location.local_id;
                File cacheFile = new File(FileLoader.getDirectory(4), fileName + ".jpg");
                File cacheFile2 = FileLoader.getPathToAttach(size);
                cacheFile.renameTo(cacheFile2);
                ImageLoader.getInstance().replaceImageInCache(fileName, fileName2, ImageLocation.getForPhoto(size, newMsg.media.photo), true);
                ArrayList<TLRPC.Message> arr = new ArrayList<>();
                arr.add(newMsg);
                getMessagesStorage().putMessages(arr, false, true, false, 0, false);
                return;
            }
            if ((newMsg.media instanceof TLRPC.TL_messageMediaDocument) && newMsg.media.document != null) {
                TLRPC.Document document = newMsg.media.document;
                newMsg.media.document = new TLRPC.TL_documentEncrypted();
                newMsg.media.document.id = file.id;
                newMsg.media.document.access_hash = file.access_hash;
                newMsg.media.document.date = document.date;
                newMsg.media.document.attributes = document.attributes;
                newMsg.media.document.mime_type = document.mime_type;
                newMsg.media.document.size = file.size;
                newMsg.media.document.key = decryptedMessage.media.key;
                newMsg.media.document.iv = decryptedMessage.media.iv;
                newMsg.media.document.thumbs = document.thumbs;
                newMsg.media.document.dc_id = file.dc_id;
                if (newMsg.media.document.thumbs.isEmpty()) {
                    TLRPC.PhotoSize thumb = new TLRPC.TL_photoSizeEmpty();
                    thumb.type = "s";
                    newMsg.media.document.thumbs.add(thumb);
                }
                if (newMsg.attachPath != null && newMsg.attachPath.startsWith(FileLoader.getDirectory(4).getAbsolutePath())) {
                    File cacheFile3 = new File(newMsg.attachPath);
                    File cacheFile22 = FileLoader.getPathToAttach(newMsg.media.document);
                    if (cacheFile3.renameTo(cacheFile22)) {
                        newMsgObj.mediaExists = newMsgObj.attachPathExists;
                        newMsgObj.attachPathExists = false;
                        newMsg.attachPath = "";
                    }
                }
                ArrayList<TLRPC.Message> arr2 = new ArrayList<>();
                arr2.add(newMsg);
                getMessagesStorage().putMessages(arr2, false, true, false, 0, false);
            }
        }
    }

    public static boolean isSecretVisibleMessage(TLRPC.Message message) {
        return (message.action instanceof TLRPC.TL_messageEncryptedAction) && ((message.action.encryptedAction instanceof TLRPC.TL_decryptedMessageActionScreenshotMessages) || (message.action.encryptedAction instanceof TLRPC.TL_decryptedMessageActionSetMessageTTL));
    }

    public static boolean isSecretInvisibleMessage(TLRPC.Message message) {
        return (!(message.action instanceof TLRPC.TL_messageEncryptedAction) || (message.action.encryptedAction instanceof TLRPC.TL_decryptedMessageActionScreenshotMessages) || (message.action.encryptedAction instanceof TLRPC.TL_decryptedMessageActionSetMessageTTL)) ? false : true;
    }

    protected void performSendEncryptedRequest(TLRPC.TL_messages_sendEncryptedMultiMedia req, SendMessagesHelper.DelayedMessage message) {
        for (int a = 0; a < req.files.size(); a++) {
            performSendEncryptedRequest(req.messages.get(a), message.messages.get(a), message.encryptedChat, req.files.get(a), message.originalPaths.get(a), message.messageObjects.get(a));
        }
    }

    protected void performSendEncryptedRequest(final TLRPC.DecryptedMessage req, final TLRPC.Message newMsgObj, final TLRPC.EncryptedChat chat, final TLRPC.InputEncryptedFile encryptedFile, final String originalPath, final MessageObject newMsg) {
        if (req != null && chat.auth_key != null && !(chat instanceof TLRPC.TL_encryptedChatRequested)) {
            if (chat instanceof TLRPC.TL_encryptedChatWaiting) {
                return;
            }
            getSendMessagesHelper().putToSendingMessages(newMsgObj, false);
            Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SecretChatHelper$nhWkFLEck9HfajzRSqCKP3FCGlA
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$performSendEncryptedRequest$7$SecretChatHelper(chat, req, newMsgObj, encryptedFile, newMsg, originalPath);
                }
            });
        }
    }

    public /* synthetic */ void lambda$performSendEncryptedRequest$7$SecretChatHelper(final TLRPC.EncryptedChat chat, final TLRPC.DecryptedMessage req, final TLRPC.Message newMsgObj, TLRPC.InputEncryptedFile encryptedFile, final MessageObject newMsg, final String originalPath) {
        int extraLen;
        byte[] messageKeyFull;
        TLObject reqToSend;
        try {
            TLRPC.TL_decryptedMessageLayer layer = new TLRPC.TL_decryptedMessageLayer();
            int myLayer = Math.max(46, AndroidUtilities.getMyLayerVersion(chat.layer));
            layer.layer = Math.min(myLayer, Math.max(46, AndroidUtilities.getPeerLayerVersion(chat.layer)));
            layer.message = req;
            layer.random_bytes = new byte[15];
            Utilities.random.nextBytes(layer.random_bytes);
            int mtprotoVersion = AndroidUtilities.getPeerLayerVersion(chat.layer) >= 73 ? 2 : 1;
            if (chat.seq_in == 0 && chat.seq_out == 0) {
                if (chat.admin_id == getUserConfig().getClientUserId()) {
                    chat.seq_out = 1;
                    chat.seq_in = -2;
                } else {
                    chat.seq_in = -1;
                }
            }
            if (newMsgObj.seq_in == 0 && newMsgObj.seq_out == 0) {
                layer.in_seq_no = chat.seq_in > 0 ? chat.seq_in : chat.seq_in + 2;
                layer.out_seq_no = chat.seq_out;
                chat.seq_out += 2;
                if (AndroidUtilities.getPeerLayerVersion(chat.layer) >= 20) {
                    if (chat.key_create_date == 0) {
                        chat.key_create_date = getConnectionsManager().getCurrentTime();
                    }
                    chat.key_use_count_out = (short) (chat.key_use_count_out + 1);
                    if ((chat.key_use_count_out >= 100 || chat.key_create_date < getConnectionsManager().getCurrentTime() - 604800) && chat.exchange_id == 0 && chat.future_key_fingerprint == 0) {
                        requestNewSecretChatKey(chat);
                    }
                }
                getMessagesStorage().updateEncryptedChatSeq(chat, false);
                if (newMsgObj != null) {
                    newMsgObj.seq_in = layer.in_seq_no;
                    newMsgObj.seq_out = layer.out_seq_no;
                    getMessagesStorage().setMessageSeq(newMsgObj.id, newMsgObj.seq_in, newMsgObj.seq_out);
                }
            } else {
                layer.in_seq_no = newMsgObj.seq_in;
                layer.out_seq_no = newMsgObj.seq_out;
            }
            if (BuildVars.LOGS_ENABLED) {
                FileLog.d(req + " send message with in_seq = " + layer.in_seq_no + " out_seq = " + layer.out_seq_no);
            }
            int len = layer.getObjectSize();
            NativeByteBuffer toEncrypt = new NativeByteBuffer(len + 4);
            toEncrypt.writeInt32(len);
            layer.serializeToStream(toEncrypt);
            int len2 = toEncrypt.length();
            int extraLen2 = len2 % 16 != 0 ? 16 - (len2 % 16) : 0;
            if (mtprotoVersion != 2) {
                extraLen = extraLen2;
            } else {
                extraLen = extraLen2 + ((Utilities.random.nextInt(3) + 2) * 16);
            }
            NativeByteBuffer dataForEncryption = new NativeByteBuffer(len2 + extraLen);
            toEncrypt.position(0);
            dataForEncryption.writeBytes(toEncrypt);
            if (extraLen != 0) {
                byte[] b = new byte[extraLen];
                Utilities.random.nextBytes(b);
                dataForEncryption.writeBytes(b);
            }
            byte[] b2 = new byte[16];
            boolean incoming = mtprotoVersion == 2 && chat.admin_id != getUserConfig().getClientUserId();
            if (mtprotoVersion == 2) {
                byte[] messageKeyFull2 = Utilities.computeSHA256(chat.auth_key, 88 + (incoming ? 8 : 0), 32, dataForEncryption.buffer, 0, dataForEncryption.buffer.limit());
                System.arraycopy(messageKeyFull2, 8, b2, 0, 16);
                messageKeyFull = messageKeyFull2;
            } else {
                byte[] messageKeyFull3 = Utilities.computeSHA1(toEncrypt.buffer);
                System.arraycopy(messageKeyFull3, messageKeyFull3.length - 16, b2, 0, 16);
                messageKeyFull = messageKeyFull3;
            }
            toEncrypt.reuse();
            MessageKeyData keyData = MessageKeyData.generateMessageKeyData(chat.auth_key, b2, incoming, mtprotoVersion);
            Utilities.aesIgeEncryption(dataForEncryption.buffer, keyData.aesKey, keyData.aesIv, true, false, 0, dataForEncryption.limit());
            NativeByteBuffer data = new NativeByteBuffer(b2.length + 8 + dataForEncryption.length());
            dataForEncryption.position(0);
            data.writeInt64(chat.key_fingerprint);
            data.writeBytes(b2);
            data.writeBytes(dataForEncryption);
            dataForEncryption.reuse();
            data.position(0);
            if (encryptedFile == null) {
                if (req instanceof TLRPC.TL_decryptedMessageService) {
                    TLRPC.TL_messages_sendEncryptedService req2 = new TLRPC.TL_messages_sendEncryptedService();
                    req2.data = data;
                    req2.random_id = req.random_id;
                    req2.peer = new TLRPC.TL_inputEncryptedChat();
                    req2.peer.chat_id = chat.id;
                    req2.peer.access_hash = chat.access_hash;
                    reqToSend = req2;
                } else {
                    TLRPC.TL_messages_sendEncrypted req22 = new TLRPC.TL_messages_sendEncrypted();
                    req22.data = data;
                    req22.random_id = req.random_id;
                    req22.peer = new TLRPC.TL_inputEncryptedChat();
                    req22.peer.chat_id = chat.id;
                    req22.peer.access_hash = chat.access_hash;
                    reqToSend = req22;
                }
            } else {
                TLRPC.TL_messages_sendEncryptedFile req23 = new TLRPC.TL_messages_sendEncryptedFile();
                req23.data = data;
                req23.random_id = req.random_id;
                req23.peer = new TLRPC.TL_inputEncryptedChat();
                req23.peer.chat_id = chat.id;
                req23.peer.access_hash = chat.access_hash;
                req23.file = encryptedFile;
                reqToSend = req23;
            }
            getConnectionsManager().sendRequest(reqToSend, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SecretChatHelper$StUhp5zYe4a0nl7DKS-AR3Sy6bo
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$null$6$SecretChatHelper(req, chat, newMsgObj, newMsg, originalPath, tLObject, tL_error);
                }
            }, 64);
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public /* synthetic */ void lambda$null$6$SecretChatHelper(TLRPC.DecryptedMessage req, TLRPC.EncryptedChat chat, final TLRPC.Message newMsgObj, MessageObject newMsg, String originalPath, TLObject response, TLRPC.TL_error error) {
        int existFlags;
        TLRPC.EncryptedChat currentChat;
        if (error == null && (req.action instanceof TLRPC.TL_decryptedMessageActionNotifyLayer)) {
            TLRPC.EncryptedChat currentChat2 = getMessagesController().getEncryptedChat(Integer.valueOf(chat.id));
            if (currentChat2 != null) {
                currentChat = currentChat2;
            } else {
                currentChat = chat;
            }
            if (currentChat.key_hash == null) {
                currentChat.key_hash = AndroidUtilities.calcAuthKeyHash(currentChat.auth_key);
            }
            if (AndroidUtilities.getPeerLayerVersion(currentChat.layer) >= 46 && currentChat.key_hash.length == 16) {
                try {
                    byte[] sha256 = Utilities.computeSHA256(chat.auth_key, 0, chat.auth_key.length);
                    byte[] key_hash = new byte[36];
                    System.arraycopy(chat.key_hash, 0, key_hash, 0, 16);
                    System.arraycopy(sha256, 0, key_hash, 16, 20);
                    currentChat.key_hash = key_hash;
                    getMessagesStorage().updateEncryptedChat(currentChat);
                } catch (Throwable e) {
                    FileLog.e(e);
                }
            }
            this.sendingNotifyLayer.remove(Integer.valueOf(currentChat.id));
            currentChat.layer = AndroidUtilities.setMyLayerVersion(currentChat.layer, 101);
            getMessagesStorage().updateEncryptedChatLayer(currentChat);
        }
        if (newMsgObj != null) {
            if (error != null) {
                getMessagesStorage().markMessageAsSendError(newMsgObj, false);
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SecretChatHelper$1_MhRAQYyDQ5mO8M3YaQM3FCfqw
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$5$SecretChatHelper(newMsgObj);
                    }
                });
                return;
            }
            final String attachPath = newMsgObj.attachPath;
            final TLRPC.messages_SentEncryptedMessage res = (TLRPC.messages_SentEncryptedMessage) response;
            if (isSecretVisibleMessage(newMsgObj)) {
                newMsgObj.date = res.date;
            }
            if (newMsg != null && (res.file instanceof TLRPC.TL_encryptedFile)) {
                updateMediaPaths(newMsg, res.file, req, originalPath);
                existFlags = newMsg.getMediaExistanceFlags();
            } else {
                existFlags = 0;
            }
            final int i = existFlags;
            getMessagesStorage().getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SecretChatHelper$4inX1VooaCnI1cdPbbFHJogbw9w
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$4$SecretChatHelper(newMsgObj, res, i, attachPath);
                }
            });
        }
    }

    public /* synthetic */ void lambda$null$4$SecretChatHelper(final TLRPC.Message newMsgObj, TLRPC.messages_SentEncryptedMessage res, final int existFlags, final String attachPath) {
        if (isSecretInvisibleMessage(newMsgObj)) {
            res.date = 0;
        }
        getMessagesStorage().updateMessageStateAndId(newMsgObj.random_id, Integer.valueOf(newMsgObj.id), newMsgObj.id, res.date, false, 0, 0);
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SecretChatHelper$udrE2CnXy6Dk25NJXMSQLJnNUuY
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$3$SecretChatHelper(newMsgObj, existFlags, attachPath);
            }
        });
    }

    public /* synthetic */ void lambda$null$3$SecretChatHelper(TLRPC.Message newMsgObj, int existFlags, String attachPath) {
        newMsgObj.send_state = 0;
        getNotificationCenter().postNotificationName(NotificationCenter.messageReceivedByServer, Integer.valueOf(newMsgObj.id), Integer.valueOf(newMsgObj.id), newMsgObj, Long.valueOf(newMsgObj.dialog_id), 0L, Integer.valueOf(existFlags), false);
        getSendMessagesHelper().processSentMessage(newMsgObj.id);
        if (MessageObject.isVideoMessage(newMsgObj) || MessageObject.isNewGifMessage(newMsgObj) || MessageObject.isRoundVideoMessage(newMsgObj)) {
            getSendMessagesHelper().stopVideoService(attachPath);
        }
        getSendMessagesHelper().removeFromSendingMessages(newMsgObj.id, false);
    }

    public /* synthetic */ void lambda$null$5$SecretChatHelper(TLRPC.Message newMsgObj) {
        newMsgObj.send_state = 2;
        getNotificationCenter().postNotificationName(NotificationCenter.messageSendError, Integer.valueOf(newMsgObj.id));
        getSendMessagesHelper().processSentMessage(newMsgObj.id);
        if (MessageObject.isVideoMessage(newMsgObj) || MessageObject.isNewGifMessage(newMsgObj) || MessageObject.isRoundVideoMessage(newMsgObj)) {
            getSendMessagesHelper().stopVideoService(newMsgObj.attachPath);
        }
        getSendMessagesHelper().removeFromSendingMessages(newMsgObj.id, false);
    }

    private void applyPeerLayer(final TLRPC.EncryptedChat chat, int newPeerLayer) {
        int currentPeerLayer = AndroidUtilities.getPeerLayerVersion(chat.layer);
        if (newPeerLayer <= currentPeerLayer) {
            return;
        }
        if (chat.key_hash.length == 16 && currentPeerLayer >= 46) {
            try {
                byte[] sha256 = Utilities.computeSHA256(chat.auth_key, 0, chat.auth_key.length);
                byte[] key_hash = new byte[36];
                System.arraycopy(chat.key_hash, 0, key_hash, 0, 16);
                System.arraycopy(sha256, 0, key_hash, 16, 20);
                chat.key_hash = key_hash;
                getMessagesStorage().updateEncryptedChat(chat);
            } catch (Throwable e) {
                FileLog.e(e);
            }
        }
        chat.layer = AndroidUtilities.setPeerLayerVersion(chat.layer, newPeerLayer);
        getMessagesStorage().updateEncryptedChatLayer(chat);
        if (currentPeerLayer < 101) {
            sendNotifyLayerMessage(chat, null);
        }
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SecretChatHelper$WwzggWBE9ia7zzSyVcVb8Py4OFQ
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$applyPeerLayer$8$SecretChatHelper(chat);
            }
        });
    }

    public /* synthetic */ void lambda$applyPeerLayer$8$SecretChatHelper(TLRPC.EncryptedChat chat) {
        getNotificationCenter().postNotificationName(NotificationCenter.encryptedChatUpdated, chat);
    }

    public TLRPC.Message processDecryptedObject(TLRPC.EncryptedChat chat, TLRPC.EncryptedFile file, int date, TLObject object, boolean new_key_used) {
        int i;
        TLRPC.TL_message newMessage;
        TLRPC.PhotoSize photoSize;
        TLRPC.PhotoSize photoSize2;
        if (object != null) {
            int from_id = chat.admin_id;
            if (from_id == getUserConfig().getClientUserId()) {
                from_id = chat.participant_id;
            }
            if (AndroidUtilities.getPeerLayerVersion(chat.layer) >= 20 && chat.exchange_id == 0 && chat.future_key_fingerprint == 0 && chat.key_use_count_in >= 120) {
                requestNewSecretChatKey(chat);
            }
            if (chat.exchange_id == 0 && chat.future_key_fingerprint != 0 && !new_key_used) {
                chat.future_auth_key = new byte[256];
                chat.future_key_fingerprint = 0L;
                getMessagesStorage().updateEncryptedChat(chat);
            } else if (chat.exchange_id != 0 && new_key_used) {
                chat.key_fingerprint = chat.future_key_fingerprint;
                chat.auth_key = chat.future_auth_key;
                chat.key_create_date = getConnectionsManager().getCurrentTime();
                chat.future_auth_key = new byte[256];
                chat.future_key_fingerprint = 0L;
                chat.key_use_count_in = (short) 0;
                chat.key_use_count_out = (short) 0;
                chat.exchange_id = 0L;
                getMessagesStorage().updateEncryptedChat(chat);
            }
            if (object instanceof TLRPC.TL_decryptedMessage) {
                TLRPC.TL_decryptedMessage decryptedMessage = (TLRPC.TL_decryptedMessage) object;
                if (AndroidUtilities.getPeerLayerVersion(chat.layer) >= 17) {
                    newMessage = new TLRPC.TL_message_secret();
                    newMessage.ttl = decryptedMessage.ttl;
                    newMessage.entities = decryptedMessage.entities;
                } else {
                    newMessage = new TLRPC.TL_message();
                    newMessage.ttl = chat.ttl;
                }
                newMessage.message = decryptedMessage.message;
                newMessage.date = date;
                int newMessageId = getUserConfig().getNewMessageId();
                newMessage.id = newMessageId;
                newMessage.local_id = newMessageId;
                getUserConfig().saveConfig(false);
                newMessage.from_id = from_id;
                newMessage.to_id = new TLRPC.TL_peerUser();
                newMessage.random_id = decryptedMessage.random_id;
                newMessage.to_id.user_id = getUserConfig().getClientUserId();
                newMessage.unread = true;
                newMessage.flags = 768;
                if (decryptedMessage.via_bot_name != null && decryptedMessage.via_bot_name.length() > 0) {
                    newMessage.via_bot_name = decryptedMessage.via_bot_name;
                    newMessage.flags |= 2048;
                }
                if (decryptedMessage.grouped_id != 0) {
                    newMessage.grouped_id = decryptedMessage.grouped_id;
                    newMessage.flags |= 131072;
                }
                newMessage.dialog_id = ((long) chat.id) << 32;
                if (decryptedMessage.reply_to_random_id != 0) {
                    newMessage.reply_to_random_id = decryptedMessage.reply_to_random_id;
                    newMessage.flags |= 8;
                }
                if (decryptedMessage.media == null || (decryptedMessage.media instanceof TLRPC.TL_decryptedMessageMediaEmpty)) {
                    newMessage.media = new TLRPC.TL_messageMediaEmpty();
                } else if (decryptedMessage.media instanceof TLRPC.TL_decryptedMessageMediaWebPage) {
                    newMessage.media = new TLRPC.TL_messageMediaWebPage();
                    newMessage.media.webpage = new TLRPC.TL_webPageUrlPending();
                    newMessage.media.webpage.url = decryptedMessage.media.url;
                } else {
                    if (decryptedMessage.media instanceof TLRPC.TL_decryptedMessageMediaContact) {
                        newMessage.media = new TLRPC.TL_messageMediaContact();
                        newMessage.media.last_name = decryptedMessage.media.last_name;
                        newMessage.media.first_name = decryptedMessage.media.first_name;
                        newMessage.media.phone_number = decryptedMessage.media.phone_number;
                        newMessage.media.user_id = decryptedMessage.media.user_id;
                        newMessage.media.vcard = "";
                    } else if (decryptedMessage.media instanceof TLRPC.TL_decryptedMessageMediaGeoPoint) {
                        newMessage.media = new TLRPC.TL_messageMediaGeo();
                        newMessage.media.geo = new TLRPC.TL_geoPoint();
                        newMessage.media.geo.lat = decryptedMessage.media.lat;
                        newMessage.media.geo._long = decryptedMessage.media._long;
                    } else if (decryptedMessage.media instanceof TLRPC.TL_decryptedMessageMediaPhoto) {
                        if (decryptedMessage.media.key == null || decryptedMessage.media.key.length != 32 || decryptedMessage.media.iv == null || decryptedMessage.media.iv.length != 32) {
                            return null;
                        }
                        newMessage.media = new TLRPC.TL_messageMediaPhoto();
                        newMessage.media.flags |= 3;
                        newMessage.message = decryptedMessage.media.caption != null ? decryptedMessage.media.caption : "";
                        newMessage.media.photo = new TLRPC.TL_photo();
                        newMessage.media.photo.file_reference = new byte[0];
                        newMessage.media.photo.date = newMessage.date;
                        byte[] thumb = ((TLRPC.TL_decryptedMessageMediaPhoto) decryptedMessage.media).thumb;
                        if (thumb != null && thumb.length != 0 && thumb.length <= 6000 && decryptedMessage.media.thumb_w <= 100 && decryptedMessage.media.thumb_h <= 100) {
                            TLRPC.TL_photoCachedSize small = new TLRPC.TL_photoCachedSize();
                            small.w = decryptedMessage.media.thumb_w;
                            small.h = decryptedMessage.media.thumb_h;
                            small.bytes = thumb;
                            small.type = "s";
                            small.location = new TLRPC.TL_fileLocationUnavailable();
                            newMessage.media.photo.sizes.add(small);
                        }
                        if (newMessage.ttl != 0) {
                            newMessage.media.ttl_seconds = newMessage.ttl;
                            newMessage.media.flags |= 4;
                        }
                        TLRPC.TL_photoSize big = new TLRPC.TL_photoSize();
                        big.w = decryptedMessage.media.w;
                        big.h = decryptedMessage.media.h;
                        big.type = "x";
                        big.size = file.size;
                        big.location = new TLRPC.TL_fileEncryptedLocation();
                        big.location.key = decryptedMessage.media.key;
                        big.location.iv = decryptedMessage.media.iv;
                        big.location.dc_id = file.dc_id;
                        big.location.volume_id = file.id;
                        big.location.secret = file.access_hash;
                        big.location.local_id = file.key_fingerprint;
                        newMessage.media.photo.sizes.add(big);
                    } else if (decryptedMessage.media instanceof TLRPC.TL_decryptedMessageMediaVideo) {
                        if (decryptedMessage.media.key == null || decryptedMessage.media.key.length != 32 || decryptedMessage.media.iv == null || decryptedMessage.media.iv.length != 32) {
                            return null;
                        }
                        newMessage.media = new TLRPC.TL_messageMediaDocument();
                        newMessage.media.flags |= 3;
                        newMessage.media.document = new TLRPC.TL_documentEncrypted();
                        newMessage.media.document.key = decryptedMessage.media.key;
                        newMessage.media.document.iv = decryptedMessage.media.iv;
                        newMessage.media.document.dc_id = file.dc_id;
                        newMessage.message = decryptedMessage.media.caption != null ? decryptedMessage.media.caption : "";
                        newMessage.media.document.date = date;
                        newMessage.media.document.size = file.size;
                        newMessage.media.document.id = file.id;
                        newMessage.media.document.access_hash = file.access_hash;
                        newMessage.media.document.mime_type = decryptedMessage.media.mime_type;
                        if (newMessage.media.document.mime_type == null) {
                            newMessage.media.document.mime_type = MimeTypes.VIDEO_MP4;
                        }
                        byte[] thumb2 = ((TLRPC.TL_decryptedMessageMediaVideo) decryptedMessage.media).thumb;
                        if (thumb2 != null && thumb2.length != 0 && thumb2.length <= 6000 && decryptedMessage.media.thumb_w <= 100 && decryptedMessage.media.thumb_h <= 100) {
                            photoSize2 = new TLRPC.TL_photoCachedSize();
                            photoSize2.bytes = thumb2;
                            photoSize2.w = decryptedMessage.media.thumb_w;
                            photoSize2.h = decryptedMessage.media.thumb_h;
                            photoSize2.type = "s";
                            photoSize2.location = new TLRPC.TL_fileLocationUnavailable();
                        } else {
                            photoSize2 = new TLRPC.TL_photoSizeEmpty();
                            photoSize2.type = "s";
                        }
                        newMessage.media.document.thumbs.add(photoSize2);
                        newMessage.media.document.flags |= 1;
                        TLRPC.TL_documentAttributeVideo attributeVideo = new TLRPC.TL_documentAttributeVideo();
                        attributeVideo.w = decryptedMessage.media.w;
                        attributeVideo.h = decryptedMessage.media.h;
                        attributeVideo.duration = decryptedMessage.media.duration;
                        attributeVideo.supports_streaming = false;
                        newMessage.media.document.attributes.add(attributeVideo);
                        if (newMessage.ttl != 0) {
                            newMessage.media.ttl_seconds = newMessage.ttl;
                            newMessage.media.flags |= 4;
                        }
                        if (newMessage.ttl != 0) {
                            newMessage.ttl = Math.max(decryptedMessage.media.duration + 1, newMessage.ttl);
                        }
                    } else if (decryptedMessage.media instanceof TLRPC.TL_decryptedMessageMediaDocument) {
                        if (decryptedMessage.media.key == null || decryptedMessage.media.key.length != 32 || decryptedMessage.media.iv == null || decryptedMessage.media.iv.length != 32) {
                            return null;
                        }
                        newMessage.media = new TLRPC.TL_messageMediaDocument();
                        newMessage.media.flags |= 3;
                        newMessage.message = decryptedMessage.media.caption != null ? decryptedMessage.media.caption : "";
                        newMessage.media.document = new TLRPC.TL_documentEncrypted();
                        newMessage.media.document.id = file.id;
                        newMessage.media.document.access_hash = file.access_hash;
                        newMessage.media.document.date = date;
                        if (decryptedMessage.media instanceof TLRPC.TL_decryptedMessageMediaDocument_layer8) {
                            TLRPC.TL_documentAttributeFilename fileName = new TLRPC.TL_documentAttributeFilename();
                            fileName.file_name = decryptedMessage.media.file_name;
                            newMessage.media.document.attributes.add(fileName);
                        } else {
                            newMessage.media.document.attributes = decryptedMessage.media.attributes;
                        }
                        newMessage.media.document.mime_type = decryptedMessage.media.mime_type;
                        newMessage.media.document.size = decryptedMessage.media.size != 0 ? Math.min(decryptedMessage.media.size, file.size) : file.size;
                        newMessage.media.document.key = decryptedMessage.media.key;
                        newMessage.media.document.iv = decryptedMessage.media.iv;
                        if (newMessage.media.document.mime_type == null) {
                            newMessage.media.document.mime_type = "";
                        }
                        byte[] thumb3 = ((TLRPC.TL_decryptedMessageMediaDocument) decryptedMessage.media).thumb;
                        if (thumb3 != null && thumb3.length != 0 && thumb3.length <= 6000 && decryptedMessage.media.thumb_w <= 100 && decryptedMessage.media.thumb_h <= 100) {
                            photoSize = new TLRPC.TL_photoCachedSize();
                            photoSize.bytes = thumb3;
                            photoSize.w = decryptedMessage.media.thumb_w;
                            photoSize.h = decryptedMessage.media.thumb_h;
                            photoSize.type = "s";
                            photoSize.location = new TLRPC.TL_fileLocationUnavailable();
                        } else {
                            photoSize = new TLRPC.TL_photoSizeEmpty();
                            photoSize.type = "s";
                        }
                        newMessage.media.document.thumbs.add(photoSize);
                        newMessage.media.document.flags |= 1;
                        newMessage.media.document.dc_id = file.dc_id;
                        if (MessageObject.isVoiceMessage(newMessage) || MessageObject.isRoundVideoMessage(newMessage)) {
                            newMessage.media_unread = true;
                        }
                    } else if (decryptedMessage.media instanceof TLRPC.TL_decryptedMessageMediaExternalDocument) {
                        newMessage.media = new TLRPC.TL_messageMediaDocument();
                        newMessage.media.flags |= 3;
                        newMessage.message = "";
                        newMessage.media.document = new TLRPC.TL_document();
                        newMessage.media.document.id = decryptedMessage.media.id;
                        newMessage.media.document.access_hash = decryptedMessage.media.access_hash;
                        newMessage.media.document.file_reference = new byte[0];
                        newMessage.media.document.date = decryptedMessage.media.date;
                        newMessage.media.document.attributes = decryptedMessage.media.attributes;
                        newMessage.media.document.mime_type = decryptedMessage.media.mime_type;
                        newMessage.media.document.dc_id = decryptedMessage.media.dc_id;
                        newMessage.media.document.size = decryptedMessage.media.size;
                        newMessage.media.document.thumbs.add(((TLRPC.TL_decryptedMessageMediaExternalDocument) decryptedMessage.media).thumb);
                        newMessage.media.document.flags |= 1;
                        if (newMessage.media.document.mime_type == null) {
                            newMessage.media.document.mime_type = "";
                        }
                    } else if (decryptedMessage.media instanceof TLRPC.TL_decryptedMessageMediaAudio) {
                        if (decryptedMessage.media.key == null || decryptedMessage.media.key.length != 32 || decryptedMessage.media.iv == null || decryptedMessage.media.iv.length != 32) {
                            return null;
                        }
                        newMessage.media = new TLRPC.TL_messageMediaDocument();
                        newMessage.media.flags |= 3;
                        newMessage.media.document = new TLRPC.TL_documentEncrypted();
                        newMessage.media.document.key = decryptedMessage.media.key;
                        newMessage.media.document.iv = decryptedMessage.media.iv;
                        newMessage.media.document.id = file.id;
                        newMessage.media.document.access_hash = file.access_hash;
                        newMessage.media.document.date = date;
                        newMessage.media.document.size = file.size;
                        newMessage.media.document.dc_id = file.dc_id;
                        newMessage.media.document.mime_type = decryptedMessage.media.mime_type;
                        newMessage.message = decryptedMessage.media.caption != null ? decryptedMessage.media.caption : "";
                        if (newMessage.media.document.mime_type == null) {
                            newMessage.media.document.mime_type = "audio/ogg";
                        }
                        TLRPC.TL_documentAttributeAudio attributeAudio = new TLRPC.TL_documentAttributeAudio();
                        attributeAudio.duration = decryptedMessage.media.duration;
                        attributeAudio.voice = true;
                        newMessage.media.document.attributes.add(attributeAudio);
                        if (newMessage.ttl != 0) {
                            newMessage.ttl = Math.max(decryptedMessage.media.duration + 1, newMessage.ttl);
                        }
                        if (newMessage.media.document.thumbs.isEmpty()) {
                            TLRPC.PhotoSize thumb4 = new TLRPC.TL_photoSizeEmpty();
                            thumb4.type = "s";
                            newMessage.media.document.thumbs.add(thumb4);
                        }
                    } else if (decryptedMessage.media instanceof TLRPC.TL_decryptedMessageMediaVenue) {
                        newMessage.media = new TLRPC.TL_messageMediaVenue();
                        newMessage.media.geo = new TLRPC.TL_geoPoint();
                        newMessage.media.geo.lat = decryptedMessage.media.lat;
                        newMessage.media.geo._long = decryptedMessage.media._long;
                        newMessage.media.title = decryptedMessage.media.title;
                        newMessage.media.address = decryptedMessage.media.address;
                        newMessage.media.provider = decryptedMessage.media.provider;
                        newMessage.media.venue_id = decryptedMessage.media.venue_id;
                        newMessage.media.venue_type = "";
                    } else {
                        return null;
                    }
                }
                if (newMessage.ttl != 0 && newMessage.media.ttl_seconds == 0) {
                    newMessage.media.ttl_seconds = newMessage.ttl;
                    newMessage.media.flags |= 4;
                }
                if (newMessage.message != null) {
                    newMessage.message = newMessage.message.replace((char) 8238, ' ');
                }
                return newMessage;
            }
            int from_id2 = from_id;
            if (!(object instanceof TLRPC.TL_decryptedMessageService)) {
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.e("unknown message " + object);
                    return null;
                }
                return null;
            }
            TLRPC.TL_decryptedMessageService serviceMessage = (TLRPC.TL_decryptedMessageService) object;
            if ((serviceMessage.action instanceof TLRPC.TL_decryptedMessageActionSetMessageTTL) || (serviceMessage.action instanceof TLRPC.TL_decryptedMessageActionScreenshotMessages)) {
                TLRPC.TL_messageService newMessage2 = new TLRPC.TL_messageService();
                if (serviceMessage.action instanceof TLRPC.TL_decryptedMessageActionSetMessageTTL) {
                    newMessage2.action = new TLRPC.TL_messageEncryptedAction();
                    if (serviceMessage.action.ttl_seconds < 0 || serviceMessage.action.ttl_seconds > 31536000) {
                        serviceMessage.action.ttl_seconds = 31536000;
                    }
                    chat.ttl = serviceMessage.action.ttl_seconds;
                    newMessage2.action.encryptedAction = serviceMessage.action;
                    getMessagesStorage().updateEncryptedChatTTL(chat);
                } else if (serviceMessage.action instanceof TLRPC.TL_decryptedMessageActionScreenshotMessages) {
                    newMessage2.action = new TLRPC.TL_messageEncryptedAction();
                    newMessage2.action.encryptedAction = serviceMessage.action;
                }
                int newMessageId2 = getUserConfig().getNewMessageId();
                newMessage2.id = newMessageId2;
                newMessage2.local_id = newMessageId2;
                getUserConfig().saveConfig(false);
                newMessage2.unread = true;
                newMessage2.flags = 256;
                newMessage2.date = date;
                newMessage2.from_id = from_id2;
                newMessage2.to_id = new TLRPC.TL_peerUser();
                newMessage2.to_id.user_id = getUserConfig().getClientUserId();
                newMessage2.dialog_id = ((long) chat.id) << 32;
                return newMessage2;
            }
            if (serviceMessage.action instanceof TLRPC.TL_decryptedMessageActionFlushHistory) {
                final long did = ((long) chat.id) << 32;
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SecretChatHelper$MiVnEgQXZ_truPWZOwOZIOeOPWc
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$processDecryptedObject$11$SecretChatHelper(did);
                    }
                });
                return null;
            }
            if (serviceMessage.action instanceof TLRPC.TL_decryptedMessageActionDeleteMessages) {
                if (!serviceMessage.action.random_ids.isEmpty()) {
                    this.pendingEncMessagesToDelete.addAll(serviceMessage.action.random_ids);
                    return null;
                }
                return null;
            }
            if (serviceMessage.action instanceof TLRPC.TL_decryptedMessageActionReadMessages) {
                if (!serviceMessage.action.random_ids.isEmpty()) {
                    int time = getConnectionsManager().getCurrentTime();
                    getMessagesStorage().createTaskForSecretChat(chat.id, time, time, 1, serviceMessage.action.random_ids);
                    return null;
                }
                return null;
            }
            if (serviceMessage.action instanceof TLRPC.TL_decryptedMessageActionNotifyLayer) {
                applyPeerLayer(chat, serviceMessage.action.layer);
                return null;
            }
            if (serviceMessage.action instanceof TLRPC.TL_decryptedMessageActionRequestKey) {
                if (chat.exchange_id != 0) {
                    if (chat.exchange_id <= serviceMessage.action.exchange_id) {
                        sendAbortKeyMessage(chat, null, chat.exchange_id);
                    } else {
                        if (BuildVars.LOGS_ENABLED) {
                            FileLog.d("we already have request key with higher exchange_id");
                            return null;
                        }
                        return null;
                    }
                }
                byte[] salt = new byte[256];
                Utilities.random.nextBytes(salt);
                BigInteger p = new BigInteger(1, getMessagesStorage().getSecretPBytes());
                BigInteger g_b = BigInteger.valueOf(getMessagesStorage().getSecretG());
                BigInteger g_b2 = g_b.modPow(new BigInteger(1, salt), p);
                BigInteger g_a = new BigInteger(1, serviceMessage.action.g_a);
                if (!Utilities.isGoodGaAndGb(g_a, p)) {
                    sendAbortKeyMessage(chat, null, serviceMessage.action.exchange_id);
                    return null;
                }
                byte[] g_b_bytes = g_b2.toByteArray();
                if (g_b_bytes.length <= 256) {
                    i = 1;
                } else {
                    byte[] correctedAuth = new byte[256];
                    i = 1;
                    System.arraycopy(g_b_bytes, 1, correctedAuth, 0, 256);
                    g_b_bytes = correctedAuth;
                }
                byte[] authKey = g_a.modPow(new BigInteger(i, salt), p).toByteArray();
                if (authKey.length > 256) {
                    byte[] correctedAuth2 = new byte[256];
                    System.arraycopy(authKey, authKey.length - 256, correctedAuth2, 0, 256);
                    authKey = correctedAuth2;
                } else if (authKey.length < 256) {
                    byte[] correctedAuth3 = new byte[256];
                    System.arraycopy(authKey, 0, correctedAuth3, 256 - authKey.length, authKey.length);
                    for (int a = 0; a < 256 - authKey.length; a++) {
                        correctedAuth3[a] = 0;
                    }
                    authKey = correctedAuth3;
                }
                byte[] authKeyHash = Utilities.computeSHA1(authKey);
                byte[] authKeyId = new byte[8];
                System.arraycopy(authKeyHash, authKeyHash.length - 8, authKeyId, 0, 8);
                chat.exchange_id = serviceMessage.action.exchange_id;
                chat.future_auth_key = authKey;
                chat.future_key_fingerprint = Utilities.bytesToLong(authKeyId);
                chat.g_a_or_b = g_b_bytes;
                getMessagesStorage().updateEncryptedChat(chat);
                sendAcceptKeyMessage(chat, null);
                return null;
            }
            if (!(serviceMessage.action instanceof TLRPC.TL_decryptedMessageActionAcceptKey)) {
                if (!(serviceMessage.action instanceof TLRPC.TL_decryptedMessageActionCommitKey)) {
                    if (serviceMessage.action instanceof TLRPC.TL_decryptedMessageActionAbortKey) {
                        if (chat.exchange_id == serviceMessage.action.exchange_id) {
                            chat.future_auth_key = new byte[256];
                            chat.future_key_fingerprint = 0L;
                            chat.exchange_id = 0L;
                            getMessagesStorage().updateEncryptedChat(chat);
                            return null;
                        }
                        return null;
                    }
                    if ((serviceMessage.action instanceof TLRPC.TL_decryptedMessageActionNoop) || !(serviceMessage.action instanceof TLRPC.TL_decryptedMessageActionResend) || serviceMessage.action.end_seq_no < chat.in_seq_no || serviceMessage.action.end_seq_no < serviceMessage.action.start_seq_no) {
                        return null;
                    }
                    if (serviceMessage.action.start_seq_no < chat.in_seq_no) {
                        serviceMessage.action.start_seq_no = chat.in_seq_no;
                    }
                    resendMessages(serviceMessage.action.start_seq_no, serviceMessage.action.end_seq_no, chat);
                    return null;
                }
                if (chat.exchange_id == serviceMessage.action.exchange_id && chat.future_key_fingerprint == serviceMessage.action.key_fingerprint) {
                    long old_fingerpring = chat.key_fingerprint;
                    byte[] old_key = chat.auth_key;
                    chat.key_fingerprint = chat.future_key_fingerprint;
                    chat.auth_key = chat.future_auth_key;
                    chat.key_create_date = getConnectionsManager().getCurrentTime();
                    chat.future_auth_key = old_key;
                    chat.future_key_fingerprint = old_fingerpring;
                    chat.key_use_count_in = (short) 0;
                    chat.key_use_count_out = (short) 0;
                    chat.exchange_id = 0L;
                    getMessagesStorage().updateEncryptedChat(chat);
                    sendNoopMessage(chat, null);
                    return null;
                }
                chat.future_auth_key = new byte[256];
                chat.future_key_fingerprint = 0L;
                chat.exchange_id = 0L;
                getMessagesStorage().updateEncryptedChat(chat);
                sendAbortKeyMessage(chat, null, serviceMessage.action.exchange_id);
                return null;
            }
            if (chat.exchange_id == serviceMessage.action.exchange_id) {
                BigInteger p2 = new BigInteger(1, getMessagesStorage().getSecretPBytes());
                BigInteger i_authKey = new BigInteger(1, serviceMessage.action.g_b);
                if (!Utilities.isGoodGaAndGb(i_authKey, p2)) {
                    chat.future_auth_key = new byte[256];
                    chat.future_key_fingerprint = 0L;
                    chat.exchange_id = 0L;
                    getMessagesStorage().updateEncryptedChat(chat);
                    sendAbortKeyMessage(chat, null, serviceMessage.action.exchange_id);
                    return null;
                }
                byte[] authKey2 = i_authKey.modPow(new BigInteger(1, chat.a_or_b), p2).toByteArray();
                if (authKey2.length > 256) {
                    byte[] correctedAuth4 = new byte[256];
                    System.arraycopy(authKey2, authKey2.length - 256, correctedAuth4, 0, 256);
                    authKey2 = correctedAuth4;
                } else if (authKey2.length < 256) {
                    byte[] correctedAuth5 = new byte[256];
                    byte b = 0;
                    System.arraycopy(authKey2, 0, correctedAuth5, 256 - authKey2.length, authKey2.length);
                    int a2 = 0;
                    while (a2 < 256 - authKey2.length) {
                        correctedAuth5[a2] = b;
                        a2++;
                        b = 0;
                    }
                    authKey2 = correctedAuth5;
                }
                byte[] authKeyHash2 = Utilities.computeSHA1(authKey2);
                byte[] authKeyId2 = new byte[8];
                System.arraycopy(authKeyHash2, authKeyHash2.length - 8, authKeyId2, 0, 8);
                long fingerprint = Utilities.bytesToLong(authKeyId2);
                if (serviceMessage.action.key_fingerprint == fingerprint) {
                    chat.future_auth_key = authKey2;
                    chat.future_key_fingerprint = fingerprint;
                    getMessagesStorage().updateEncryptedChat(chat);
                    sendCommitKeyMessage(chat, null);
                    return null;
                }
                chat.future_auth_key = new byte[256];
                chat.future_key_fingerprint = 0L;
                chat.exchange_id = 0L;
                getMessagesStorage().updateEncryptedChat(chat);
                sendAbortKeyMessage(chat, null, serviceMessage.action.exchange_id);
                return null;
            }
            chat.future_auth_key = new byte[256];
            chat.future_key_fingerprint = 0L;
            chat.exchange_id = 0L;
            getMessagesStorage().updateEncryptedChat(chat);
            sendAbortKeyMessage(chat, null, serviceMessage.action.exchange_id);
            return null;
        }
        if (BuildVars.LOGS_ENABLED) {
            FileLog.e("unknown TLObject");
            return null;
        }
        return null;
    }

    public /* synthetic */ void lambda$processDecryptedObject$11$SecretChatHelper(final long did) {
        TLRPC.Dialog dialog = getMessagesController().dialogs_dict.get(did);
        if (dialog != null) {
            dialog.unread_count = 0;
            getMessagesController().dialogMessage.remove(dialog.id);
        }
        getMessagesStorage().getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SecretChatHelper$gKGEpjcRRrRtOlAJyBySCcp9Dv8
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$10$SecretChatHelper(did);
            }
        });
        getMessagesStorage().deleteDialog(did, 1);
        getNotificationCenter().postNotificationName(NotificationCenter.dialogsNeedReload, new Object[0]);
        getNotificationCenter().postNotificationName(NotificationCenter.removeAllMessagesFromDialog, Long.valueOf(did), false);
    }

    public /* synthetic */ void lambda$null$10$SecretChatHelper(final long did) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SecretChatHelper$o1dNvYYwQcxzccR0cOlVFL14F7w
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$9$SecretChatHelper(did);
            }
        });
    }

    public /* synthetic */ void lambda$null$9$SecretChatHelper(long did) {
        getNotificationsController().processReadMessages(null, did, 0, Integer.MAX_VALUE, false);
        LongSparseArray<Integer> dialogsToUpdate = new LongSparseArray<>(1);
        dialogsToUpdate.put(did, 0);
        getNotificationsController().processDialogsUpdateRead(dialogsToUpdate);
    }

    private TLRPC.Message createDeleteMessage(int mid, int seq_out, int seq_in, long random_id, TLRPC.EncryptedChat encryptedChat) {
        TLRPC.TL_messageService newMsg = new TLRPC.TL_messageService();
        newMsg.action = new TLRPC.TL_messageEncryptedAction();
        newMsg.action.encryptedAction = new TLRPC.TL_decryptedMessageActionDeleteMessages();
        newMsg.action.encryptedAction.random_ids.add(Long.valueOf(random_id));
        newMsg.id = mid;
        newMsg.local_id = mid;
        newMsg.from_id = getUserConfig().getClientUserId();
        newMsg.unread = true;
        newMsg.out = true;
        newMsg.flags = 256;
        newMsg.dialog_id = ((long) encryptedChat.id) << 32;
        newMsg.to_id = new TLRPC.TL_peerUser();
        newMsg.send_state = 1;
        newMsg.seq_in = seq_in;
        newMsg.seq_out = seq_out;
        if (encryptedChat.participant_id == getUserConfig().getClientUserId()) {
            newMsg.to_id.user_id = encryptedChat.admin_id;
        } else {
            newMsg.to_id.user_id = encryptedChat.participant_id;
        }
        newMsg.date = 0;
        newMsg.random_id = random_id;
        return newMsg;
    }

    private void resendMessages(final int startSeq, final int endSeq, final TLRPC.EncryptedChat encryptedChat) {
        if (encryptedChat == null || endSeq - startSeq < 0) {
            return;
        }
        getMessagesStorage().getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SecretChatHelper$ky4zoeC7JZgk0iHzRbk5uAxUq-8
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$resendMessages$14$SecretChatHelper(startSeq, encryptedChat, endSeq);
            }
        });
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r10v0 */
    /* JADX WARN: Type inference failed for: r10v1, types: [boolean, int] */
    /* JADX WARN: Type inference failed for: r10v10 */
    public /* synthetic */ void lambda$resendMessages$14$SecretChatHelper(int startSeq, TLRPC.EncryptedChat encryptedChat, int endSeq) {
        boolean exists;
        int seq_out;
        ArrayList<TLRPC.Message> arrayList;
        long dialog_id;
        SparseArray<TLRPC.Message> messagesToResend;
        TLRPC.Message messageCreateDeleteMessage;
        int sSeq = startSeq;
        try {
            if (encryptedChat.admin_id == getUserConfig().getClientUserId() && sSeq % 2 == 0) {
                sSeq++;
            }
            ?? r10 = 0;
            int i = 1;
            int i2 = 3;
            SQLiteCursor cursor = getMessagesStorage().getDatabase().queryFinalized(String.format(Locale.US, "SELECT uid FROM requested_holes WHERE uid = %d AND ((seq_out_start >= %d AND %d <= seq_out_end) OR (seq_out_start >= %d AND %d <= seq_out_end))", Integer.valueOf(encryptedChat.id), Integer.valueOf(sSeq), Integer.valueOf(sSeq), Integer.valueOf(endSeq), Integer.valueOf(endSeq)), new Object[0]);
            boolean exists2 = cursor.next();
            cursor.dispose();
            if (exists2) {
                return;
            }
            long dialog_id2 = ((long) encryptedChat.id) << 32;
            SparseArray<TLRPC.Message> messagesToResend2 = new SparseArray<>();
            ArrayList<TLRPC.Message> arrayList2 = new ArrayList<>();
            for (int a = sSeq; a < endSeq; a += 2) {
                messagesToResend2.put(a, null);
            }
            SQLiteCursor sQLiteCursorQueryFinalized = getMessagesStorage().getDatabase().queryFinalized(String.format(Locale.US, "SELECT m.data, r.random_id, s.seq_in, s.seq_out, m.ttl, s.mid FROM messages_seq as s LEFT JOIN randoms as r ON r.mid = s.mid LEFT JOIN messages as m ON m.mid = s.mid WHERE m.uid = %d AND m.out = 1 AND s.seq_out >= %d AND s.seq_out <= %d ORDER BY seq_out ASC", Long.valueOf(dialog_id2), Integer.valueOf(sSeq), Integer.valueOf(endSeq)), new Object[0]);
            while (sQLiteCursorQueryFinalized.next()) {
                long random_id = sQLiteCursorQueryFinalized.longValue(i);
                if (random_id == 0) {
                    random_id = Utilities.random.nextLong();
                }
                int seq_in = sQLiteCursorQueryFinalized.intValue(2);
                int seq_out2 = sQLiteCursorQueryFinalized.intValue(i2);
                int mid = sQLiteCursorQueryFinalized.intValue(5);
                long random_id2 = random_id;
                NativeByteBuffer nativeByteBufferByteBufferValue = sQLiteCursorQueryFinalized.byteBufferValue(r10);
                if (nativeByteBufferByteBufferValue != 0) {
                    TLRPC.Message messageTLdeserialize = TLRPC.Message.TLdeserialize(nativeByteBufferByteBufferValue, nativeByteBufferByteBufferValue.readInt32(r10), r10);
                    messageTLdeserialize.readAttachPath(nativeByteBufferByteBufferValue, getUserConfig().clientUserId);
                    nativeByteBufferByteBufferValue.reuse();
                    messageTLdeserialize.random_id = random_id2;
                    messageTLdeserialize.dialog_id = dialog_id2;
                    messageTLdeserialize.seq_in = seq_in;
                    seq_out = seq_out2;
                    messageTLdeserialize.seq_out = seq_out;
                    exists = exists2;
                    messageTLdeserialize.ttl = sQLiteCursorQueryFinalized.intValue(4);
                    arrayList = arrayList2;
                    dialog_id = dialog_id2;
                    messageCreateDeleteMessage = messageTLdeserialize;
                    messagesToResend = messagesToResend2;
                } else {
                    exists = exists2;
                    seq_out = seq_out2;
                    arrayList = arrayList2;
                    dialog_id = dialog_id2;
                    messagesToResend = messagesToResend2;
                    messageCreateDeleteMessage = createDeleteMessage(mid, seq_out, seq_in, random_id2, encryptedChat);
                }
                arrayList.add(messageCreateDeleteMessage);
                messagesToResend.remove(seq_out);
                messagesToResend2 = messagesToResend;
                arrayList2 = arrayList;
                exists2 = exists;
                dialog_id2 = dialog_id;
                r10 = 0;
                i = 1;
                i2 = 3;
            }
            SparseArray<TLRPC.Message> messagesToResend3 = messagesToResend2;
            final ArrayList<TLRPC.Message> arrayList3 = arrayList2;
            sQLiteCursorQueryFinalized.dispose();
            if (messagesToResend3.size() != 0) {
                for (int a2 = 0; a2 < messagesToResend3.size(); a2++) {
                    arrayList3.add(createDeleteMessage(getUserConfig().getNewMessageId(), messagesToResend3.keyAt(a2), 0, Utilities.random.nextLong(), encryptedChat));
                }
                getUserConfig().saveConfig(false);
            }
            Collections.sort(arrayList3, new Comparator() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SecretChatHelper$nIcmARGDD0um9vOpjl3nxWJSoQA
                @Override // java.util.Comparator
                public final int compare(Object obj, Object obj2) {
                    return AndroidUtilities.compare(((TLRPC.Message) obj).seq_out, ((TLRPC.Message) obj2).seq_out);
                }
            });
            ArrayList<TLRPC.EncryptedChat> encryptedChats = new ArrayList<>();
            encryptedChats.add(encryptedChat);
            try {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SecretChatHelper$xSg5ZU3lVvZVXH0zuqvxltrtb5o
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$13$SecretChatHelper(arrayList3);
                    }
                });
                getSendMessagesHelper().processUnsentMessages(arrayList3, null, new ArrayList<>(), new ArrayList<>(), encryptedChats);
                getMessagesStorage().getDatabase().executeFast(String.format(Locale.US, "REPLACE INTO requested_holes VALUES(%d, %d, %d)", Integer.valueOf(encryptedChat.id), Integer.valueOf(sSeq), Integer.valueOf(endSeq))).stepThis().dispose();
                return;
            } catch (Exception e) {
                e = e;
            }
        } catch (Exception e2) {
            e = e2;
        }
        FileLog.e(e);
    }

    public /* synthetic */ void lambda$null$13$SecretChatHelper(ArrayList messages) {
        for (int a = 0; a < messages.size(); a++) {
            TLRPC.Message message = (TLRPC.Message) messages.get(a);
            MessageObject messageObject = new MessageObject(this.currentAccount, message, false);
            messageObject.resendAsIs = true;
            getSendMessagesHelper().retrySendMessage(messageObject, true);
        }
    }

    public void checkSecretHoles(TLRPC.EncryptedChat chat, ArrayList<TLRPC.Message> messages) {
        ArrayList<TL_decryptedMessageHolder> holes = this.secretHolesQueue.get(chat.id);
        if (holes == null) {
            return;
        }
        Collections.sort(holes, new Comparator() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SecretChatHelper$YL39HgmvbEgLZ3hZqdYjDzHWMsQ
            @Override // java.util.Comparator
            public final int compare(Object obj, Object obj2) {
                return SecretChatHelper.lambda$checkSecretHoles$15((SecretChatHelper.TL_decryptedMessageHolder) obj, (SecretChatHelper.TL_decryptedMessageHolder) obj2);
            }
        });
        boolean update = false;
        int a = 0;
        while (a < holes.size()) {
            TL_decryptedMessageHolder holder = holes.get(a);
            if (holder.layer.out_seq_no != chat.seq_in && chat.seq_in != holder.layer.out_seq_no - 2) {
                break;
            }
            applyPeerLayer(chat, holder.layer.layer);
            chat.seq_in = holder.layer.out_seq_no;
            chat.in_seq_no = holder.layer.in_seq_no;
            holes.remove(a);
            int a2 = a - 1;
            update = true;
            if (holder.decryptedWithVersion == 2) {
                chat.mtproto_seq = Math.min(chat.mtproto_seq, chat.seq_in);
            }
            TLRPC.Message message = processDecryptedObject(chat, holder.file, holder.date, holder.layer.message, holder.new_key_used);
            if (message != null) {
                messages.add(message);
            }
            a = a2 + 1;
        }
        if (holes.isEmpty()) {
            this.secretHolesQueue.remove(chat.id);
        }
        if (update) {
            getMessagesStorage().updateEncryptedChatSeq(chat, true);
        }
    }

    static /* synthetic */ int lambda$checkSecretHoles$15(TL_decryptedMessageHolder lhs, TL_decryptedMessageHolder rhs) {
        if (lhs.layer.out_seq_no > rhs.layer.out_seq_no) {
            return 1;
        }
        if (lhs.layer.out_seq_no < rhs.layer.out_seq_no) {
            return -1;
        }
        return 0;
    }

    private boolean decryptWithMtProtoVersion(NativeByteBuffer is, byte[] keyToDecrypt, byte[] messageKey, int version, boolean incoming, boolean encryptOnError) {
        boolean incoming2;
        if (version != 1) {
            incoming2 = incoming;
        } else {
            incoming2 = false;
        }
        MessageKeyData keyData = MessageKeyData.generateMessageKeyData(keyToDecrypt, messageKey, incoming2, version);
        Utilities.aesIgeEncryption(is.buffer, keyData.aesKey, keyData.aesIv, false, false, 24, is.limit() - 24);
        int len = is.readInt32(false);
        if (version == 2) {
            if (!Utilities.arraysEquals(messageKey, 0, Utilities.computeSHA256(keyToDecrypt, (incoming2 ? 8 : 0) + 88, 32, is.buffer, 24, is.buffer.limit()), 8)) {
                if (encryptOnError) {
                    Utilities.aesIgeEncryption(is.buffer, keyData.aesKey, keyData.aesIv, true, false, 24, is.limit() - 24);
                    is.position(24);
                }
                return false;
            }
        } else {
            int l = len + 28;
            if (l < is.buffer.limit() - 15 || l > is.buffer.limit()) {
                l = is.buffer.limit();
            }
            byte[] messageKeyFull = Utilities.computeSHA1(is.buffer, 24, l);
            if (!Utilities.arraysEquals(messageKey, 0, messageKeyFull, messageKeyFull.length - 16)) {
                if (encryptOnError) {
                    Utilities.aesIgeEncryption(is.buffer, keyData.aesKey, keyData.aesIv, true, false, 24, is.limit() - 24);
                    is.position(24);
                }
                return false;
            }
        }
        if (len <= 0 || len > is.limit() - 28) {
            return false;
        }
        int padding = (is.limit() - 28) - len;
        if ((version == 2 && (padding < 12 || padding > 1024)) || (version == 1 && padding > 15)) {
            return false;
        }
        return true;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:37:0x0092  */
    /* JADX WARN: Type inference failed for: r5v16 */
    /* JADX WARN: Type inference failed for: r5v18 */
    /* JADX WARN: Type inference failed for: r5v6 */
    /* JADX WARN: Type inference failed for: r5v7, types: [boolean, int] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    protected java.util.ArrayList<im.uwrkaxlmjj.tgnet.TLRPC.Message> decryptMessage(im.uwrkaxlmjj.tgnet.TLRPC.EncryptedMessage r25) {
        /*
            Method dump skipped, instruction units count: 672
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.SecretChatHelper.decryptMessage(im.uwrkaxlmjj.tgnet.TLRPC$EncryptedMessage):java.util.ArrayList");
    }

    public /* synthetic */ void lambda$decryptMessage$16$SecretChatHelper(TLRPC.TL_encryptedChatDiscarded newChat) {
        getMessagesController().putEncryptedChat(newChat, false);
        getMessagesStorage().updateEncryptedChat(newChat);
        getNotificationCenter().postNotificationName(NotificationCenter.encryptedChatUpdated, newChat);
    }

    public void requestNewSecretChatKey(TLRPC.EncryptedChat encryptedChat) {
        if (AndroidUtilities.getPeerLayerVersion(encryptedChat.layer) < 20) {
            return;
        }
        byte[] salt = new byte[256];
        Utilities.random.nextBytes(salt);
        BigInteger i_g_a = BigInteger.valueOf(getMessagesStorage().getSecretG());
        byte[] g_a = i_g_a.modPow(new BigInteger(1, salt), new BigInteger(1, getMessagesStorage().getSecretPBytes())).toByteArray();
        if (g_a.length > 256) {
            byte[] correctedAuth = new byte[256];
            System.arraycopy(g_a, 1, correctedAuth, 0, 256);
            g_a = correctedAuth;
        }
        encryptedChat.exchange_id = getSendMessagesHelper().getNextRandomId();
        encryptedChat.a_or_b = salt;
        encryptedChat.g_a = g_a;
        getMessagesStorage().updateEncryptedChat(encryptedChat);
        sendRequestKeyMessage(encryptedChat, null);
    }

    public void processAcceptedSecretChat(final TLRPC.EncryptedChat encryptedChat) {
        BigInteger p = new BigInteger(1, getMessagesStorage().getSecretPBytes());
        BigInteger i_authKey = new BigInteger(1, encryptedChat.g_a_or_b);
        if (!Utilities.isGoodGaAndGb(i_authKey, p)) {
            declineSecretChat(encryptedChat.id);
            return;
        }
        byte[] authKey = i_authKey.modPow(new BigInteger(1, encryptedChat.a_or_b), p).toByteArray();
        if (authKey.length > 256) {
            byte[] correctedAuth = new byte[256];
            System.arraycopy(authKey, authKey.length - 256, correctedAuth, 0, 256);
            authKey = correctedAuth;
        } else if (authKey.length < 256) {
            byte[] correctedAuth2 = new byte[256];
            System.arraycopy(authKey, 0, correctedAuth2, 256 - authKey.length, authKey.length);
            for (int a = 0; a < 256 - authKey.length; a++) {
                correctedAuth2[a] = 0;
            }
            authKey = correctedAuth2;
        }
        byte[] authKeyHash = Utilities.computeSHA1(authKey);
        byte[] authKeyId = new byte[8];
        System.arraycopy(authKeyHash, authKeyHash.length - 8, authKeyId, 0, 8);
        long fingerprint = Utilities.bytesToLong(authKeyId);
        if (encryptedChat.key_fingerprint == fingerprint) {
            encryptedChat.auth_key = authKey;
            encryptedChat.key_create_date = getConnectionsManager().getCurrentTime();
            encryptedChat.seq_in = -2;
            encryptedChat.seq_out = 1;
            getMessagesStorage().updateEncryptedChat(encryptedChat);
            getMessagesController().putEncryptedChat(encryptedChat, false);
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SecretChatHelper$RvKZjDVw6U4dEPEv-i5uW1YCTPg
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$processAcceptedSecretChat$17$SecretChatHelper(encryptedChat);
                }
            });
            return;
        }
        final TLRPC.TL_encryptedChatDiscarded newChat = new TLRPC.TL_encryptedChatDiscarded();
        newChat.id = encryptedChat.id;
        newChat.user_id = encryptedChat.user_id;
        newChat.auth_key = encryptedChat.auth_key;
        newChat.key_create_date = encryptedChat.key_create_date;
        newChat.key_use_count_in = encryptedChat.key_use_count_in;
        newChat.key_use_count_out = encryptedChat.key_use_count_out;
        newChat.seq_in = encryptedChat.seq_in;
        newChat.seq_out = encryptedChat.seq_out;
        newChat.admin_id = encryptedChat.admin_id;
        newChat.mtproto_seq = encryptedChat.mtproto_seq;
        getMessagesStorage().updateEncryptedChat(newChat);
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SecretChatHelper$RA36FhTvEHm38uHRki7hLmW3Pdw
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$processAcceptedSecretChat$18$SecretChatHelper(newChat);
            }
        });
        declineSecretChat(encryptedChat.id);
    }

    public /* synthetic */ void lambda$processAcceptedSecretChat$17$SecretChatHelper(TLRPC.EncryptedChat encryptedChat) {
        getNotificationCenter().postNotificationName(NotificationCenter.encryptedChatUpdated, encryptedChat);
        sendNotifyLayerMessage(encryptedChat, null);
    }

    public /* synthetic */ void lambda$processAcceptedSecretChat$18$SecretChatHelper(TLRPC.TL_encryptedChatDiscarded newChat) {
        getMessagesController().putEncryptedChat(newChat, false);
        getNotificationCenter().postNotificationName(NotificationCenter.encryptedChatUpdated, newChat);
    }

    public void declineSecretChat(int chat_id) {
        TLRPC.TL_messages_discardEncryption req = new TLRPC.TL_messages_discardEncryption();
        req.chat_id = chat_id;
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SecretChatHelper$VAFdzPJkxpMnbkskO8NiJPiM6h8
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                SecretChatHelper.lambda$declineSecretChat$19(tLObject, tL_error);
            }
        });
    }

    static /* synthetic */ void lambda$declineSecretChat$19(TLObject response, TLRPC.TL_error error) {
    }

    public void acceptSecretChat(final TLRPC.EncryptedChat encryptedChat) {
        if (this.acceptingChats.get(encryptedChat.id) != null) {
            return;
        }
        this.acceptingChats.put(encryptedChat.id, encryptedChat);
        TLRPC.TL_messages_getDhConfig req = new TLRPC.TL_messages_getDhConfig();
        req.random_length = 256;
        req.version = getMessagesStorage().getLastSecretVersion();
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SecretChatHelper$18nXIUzICwi4NK8gTgL4hDZVH94
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$acceptSecretChat$22$SecretChatHelper(encryptedChat, tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$acceptSecretChat$22$SecretChatHelper(final TLRPC.EncryptedChat encryptedChat, TLObject response, TLRPC.TL_error error) {
        if (error == null) {
            TLRPC.messages_DhConfig res = (TLRPC.messages_DhConfig) response;
            if (response instanceof TLRPC.TL_messages_dhConfig) {
                if (!Utilities.isGoodPrime(res.p, res.g)) {
                    this.acceptingChats.remove(encryptedChat.id);
                    declineSecretChat(encryptedChat.id);
                    return;
                } else {
                    getMessagesStorage().setSecretPBytes(res.p);
                    getMessagesStorage().setSecretG(res.g);
                    getMessagesStorage().setLastSecretVersion(res.version);
                    getMessagesStorage().saveSecretParams(getMessagesStorage().getLastSecretVersion(), getMessagesStorage().getSecretG(), getMessagesStorage().getSecretPBytes());
                }
            }
            byte[] salt = new byte[256];
            for (int a = 0; a < 256; a++) {
                salt[a] = (byte) (((byte) (Utilities.random.nextDouble() * 256.0d)) ^ res.random[a]);
            }
            encryptedChat.a_or_b = salt;
            encryptedChat.seq_in = -1;
            encryptedChat.seq_out = 0;
            BigInteger p = new BigInteger(1, getMessagesStorage().getSecretPBytes());
            BigInteger g_b = BigInteger.valueOf(getMessagesStorage().getSecretG());
            BigInteger g_b2 = g_b.modPow(new BigInteger(1, salt), p);
            BigInteger g_a = new BigInteger(1, encryptedChat.g_a);
            if (!Utilities.isGoodGaAndGb(g_a, p)) {
                this.acceptingChats.remove(encryptedChat.id);
                declineSecretChat(encryptedChat.id);
                return;
            }
            byte[] g_b_bytes = g_b2.toByteArray();
            if (g_b_bytes.length > 256) {
                byte[] correctedAuth = new byte[256];
                System.arraycopy(g_b_bytes, 1, correctedAuth, 0, 256);
                g_b_bytes = correctedAuth;
            }
            byte[] authKey = g_a.modPow(new BigInteger(1, salt), p).toByteArray();
            if (authKey.length <= 256) {
                if (authKey.length < 256) {
                    byte[] correctedAuth2 = new byte[256];
                    System.arraycopy(authKey, 0, correctedAuth2, 256 - authKey.length, authKey.length);
                    for (int a2 = 0; a2 < 256 - authKey.length; a2++) {
                        correctedAuth2[a2] = 0;
                    }
                    authKey = correctedAuth2;
                }
            } else {
                byte[] correctedAuth3 = new byte[256];
                System.arraycopy(authKey, authKey.length - 256, correctedAuth3, 0, 256);
                authKey = correctedAuth3;
            }
            byte[] authKeyHash = Utilities.computeSHA1(authKey);
            byte[] authKeyId = new byte[8];
            System.arraycopy(authKeyHash, authKeyHash.length - 8, authKeyId, 0, 8);
            encryptedChat.auth_key = authKey;
            encryptedChat.key_create_date = getConnectionsManager().getCurrentTime();
            TLRPC.TL_messages_acceptEncryption req2 = new TLRPC.TL_messages_acceptEncryption();
            req2.g_b = g_b_bytes;
            req2.peer = new TLRPC.TL_inputEncryptedChat();
            req2.peer.chat_id = encryptedChat.id;
            req2.peer.access_hash = encryptedChat.access_hash;
            req2.key_fingerprint = Utilities.bytesToLong(authKeyId);
            FileLog.e("J----------------------> TL_messages_acceptEncryption req");
            getConnectionsManager().sendRequest(req2, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SecretChatHelper$hi9-Yc-4_JJgzahrrJENerRSV08
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$null$21$SecretChatHelper(encryptedChat, tLObject, tL_error);
                }
            });
            return;
        }
        this.acceptingChats.remove(encryptedChat.id);
    }

    public /* synthetic */ void lambda$null$21$SecretChatHelper(TLRPC.EncryptedChat encryptedChat, TLObject response1, TLRPC.TL_error error1) {
        this.acceptingChats.remove(encryptedChat.id);
        FileLog.e("J----------------------> TL_messages_acceptEncryption res");
        if (error1 == null) {
            final TLRPC.EncryptedChat newChat = (TLRPC.EncryptedChat) response1;
            newChat.auth_key = encryptedChat.auth_key;
            newChat.user_id = encryptedChat.user_id;
            newChat.seq_in = encryptedChat.seq_in;
            newChat.seq_out = encryptedChat.seq_out;
            newChat.key_create_date = encryptedChat.key_create_date;
            newChat.key_use_count_in = encryptedChat.key_use_count_in;
            newChat.key_use_count_out = encryptedChat.key_use_count_out;
            getMessagesStorage().updateEncryptedChat(newChat);
            getMessagesController().putEncryptedChat(newChat, false);
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SecretChatHelper$ZYPTNi-rwWZnn9-hN_hF0eb4LmE
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$20$SecretChatHelper(newChat);
                }
            });
        }
    }

    public /* synthetic */ void lambda$null$20$SecretChatHelper(TLRPC.EncryptedChat newChat) {
        getNotificationCenter().postNotificationName(NotificationCenter.encryptedChatUpdated, newChat);
        sendNotifyLayerMessage(newChat, null);
    }

    public void startSecretChat(final Context context, final TLRPC.User user) {
        if (user == null || context == null) {
            return;
        }
        this.startingSecretChat = true;
        final AlertDialog progressDialog = new AlertDialog(context, 3);
        TLRPC.TL_messages_getDhConfig req = new TLRPC.TL_messages_getDhConfig();
        req.random_length = 256;
        req.version = getMessagesStorage().getLastSecretVersion();
        final int reqId = getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SecretChatHelper$xggzOL09M0VhIgpaZJMQzQQe67U
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$startSecretChat$29$SecretChatHelper(context, progressDialog, user, tLObject, tL_error);
            }
        }, 2);
        progressDialog.setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SecretChatHelper$V-lqqDU5b9kAvnKuzgPRXPo0MB4
            @Override // android.content.DialogInterface.OnCancelListener
            public final void onCancel(DialogInterface dialogInterface) {
                this.f$0.lambda$startSecretChat$30$SecretChatHelper(reqId, dialogInterface);
            }
        });
        try {
            progressDialog.show();
        } catch (Exception e) {
        }
    }

    public /* synthetic */ void lambda$startSecretChat$29$SecretChatHelper(final Context context, final AlertDialog progressDialog, final TLRPC.User user, TLObject response, TLRPC.TL_error error) {
        byte[] g_a;
        if (error != null) {
            this.delayedEncryptedChatUpdates.clear();
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SecretChatHelper$P7BAlck8No63BLVNidJFcbaV3-M
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$28$SecretChatHelper(context, progressDialog);
                }
            });
            return;
        }
        TLRPC.messages_DhConfig res = (TLRPC.messages_DhConfig) response;
        if (response instanceof TLRPC.TL_messages_dhConfig) {
            if (!Utilities.isGoodPrime(res.p, res.g)) {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SecretChatHelper$MqdMT5guCr1ycCBnOrVZgMvZO3M
                    @Override // java.lang.Runnable
                    public final void run() {
                        SecretChatHelper.lambda$null$23(context, progressDialog);
                    }
                });
                return;
            }
            getMessagesStorage().setSecretPBytes(res.p);
            getMessagesStorage().setSecretG(res.g);
            getMessagesStorage().setLastSecretVersion(res.version);
            getMessagesStorage().saveSecretParams(getMessagesStorage().getLastSecretVersion(), getMessagesStorage().getSecretG(), getMessagesStorage().getSecretPBytes());
        }
        final byte[] salt = new byte[256];
        for (int a = 0; a < 256; a++) {
            salt[a] = (byte) (((byte) (Utilities.random.nextDouble() * 256.0d)) ^ res.random[a]);
        }
        BigInteger i_g_a = BigInteger.valueOf(getMessagesStorage().getSecretG());
        byte[] g_a2 = i_g_a.modPow(new BigInteger(1, salt), new BigInteger(1, getMessagesStorage().getSecretPBytes())).toByteArray();
        if (g_a2.length <= 256) {
            g_a = g_a2;
        } else {
            byte[] correctedAuth = new byte[256];
            System.arraycopy(g_a2, 1, correctedAuth, 0, 256);
            g_a = correctedAuth;
        }
        TLRPC.TL_messages_requestEncryption req2 = new TLRPC.TL_messages_requestEncryption();
        req2.g_a = g_a;
        req2.user_id = getMessagesController().getInputUser(user);
        req2.random_id = Utilities.random.nextInt();
        getConnectionsManager().sendRequest(req2, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SecretChatHelper$DlxbY87H_CcXsu95i6INVTOL_rc
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$null$27$SecretChatHelper(context, progressDialog, salt, user, tLObject, tL_error);
            }
        }, 2);
    }

    static /* synthetic */ void lambda$null$23(Context context, AlertDialog progressDialog) {
        try {
            if (!((Activity) context).isFinishing()) {
                progressDialog.dismiss();
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public /* synthetic */ void lambda$null$27$SecretChatHelper(final Context context, final AlertDialog progressDialog, final byte[] salt, final TLRPC.User user, final TLObject response1, TLRPC.TL_error error1) {
        if (error1 == null) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SecretChatHelper$CQB8KaK3-euzVGZhuKoTBNOy6tc
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$25$SecretChatHelper(context, progressDialog, response1, salt, user);
                }
            });
        } else {
            this.delayedEncryptedChatUpdates.clear();
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SecretChatHelper$Lj0GQsXTBZD1qprVS4aoMsbmKt8
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$26$SecretChatHelper(context, progressDialog);
                }
            });
        }
    }

    public /* synthetic */ void lambda$null$25$SecretChatHelper(Context context, AlertDialog progressDialog, TLObject response1, byte[] salt, TLRPC.User user) {
        this.startingSecretChat = false;
        if (!((Activity) context).isFinishing()) {
            try {
                progressDialog.dismiss();
            } catch (Exception e) {
                FileLog.e(e);
            }
        }
        TLRPC.EncryptedChat chat = (TLRPC.EncryptedChat) response1;
        chat.user_id = chat.participant_id;
        chat.seq_in = -2;
        chat.seq_out = 1;
        chat.a_or_b = salt;
        getMessagesController().putEncryptedChat(chat, false);
        TLRPC.Dialog dialog = new TLRPC.TL_dialog();
        dialog.id = DialogObject.makeSecretDialogId(chat.id);
        dialog.unread_count = 0;
        dialog.top_message = 0;
        dialog.last_message_date = getConnectionsManager().getCurrentTime();
        getMessagesController().dialogs_dict.put(dialog.id, dialog);
        getMessagesController().allDialogs.add(dialog);
        getMessagesController().sortDialogs(null);
        getMessagesStorage().putEncryptedChat(chat, user, dialog);
        getNotificationCenter().postNotificationName(NotificationCenter.dialogsNeedReload, new Object[0]);
        getNotificationCenter().postNotificationName(NotificationCenter.encryptedChatCreated, chat);
        Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SecretChatHelper$E1kl0VM8aDs6zg0VYLYM-SUfFgM
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$24$SecretChatHelper();
            }
        });
    }

    public /* synthetic */ void lambda$null$24$SecretChatHelper() {
        if (!this.delayedEncryptedChatUpdates.isEmpty()) {
            getMessagesController().processUpdateArray(this.delayedEncryptedChatUpdates, null, null, false, 0);
            this.delayedEncryptedChatUpdates.clear();
        }
    }

    public /* synthetic */ void lambda$null$26$SecretChatHelper(Context context, AlertDialog progressDialog) {
        if (!((Activity) context).isFinishing()) {
            this.startingSecretChat = false;
            try {
                progressDialog.dismiss();
            } catch (Exception e) {
                FileLog.e(e);
            }
            AlertDialog.Builder builder = new AlertDialog.Builder(context);
            builder.setTitle(LocaleController.getString("AppName", mpEIGo.juqQQs.esbSDO.R.string.AppName));
            builder.setMessage(LocaleController.getString("CreateEncryptedChatError", mpEIGo.juqQQs.esbSDO.R.string.CreateEncryptedChatError));
            builder.setPositiveButton(LocaleController.getString("OK", mpEIGo.juqQQs.esbSDO.R.string.OK), null);
            builder.show().setCanceledOnTouchOutside(true);
        }
    }

    public /* synthetic */ void lambda$null$28$SecretChatHelper(Context context, AlertDialog progressDialog) {
        this.startingSecretChat = false;
        if (!((Activity) context).isFinishing()) {
            try {
                progressDialog.dismiss();
            } catch (Exception e) {
                FileLog.e(e);
            }
        }
    }

    public /* synthetic */ void lambda$startSecretChat$30$SecretChatHelper(int reqId, DialogInterface dialog) {
        getConnectionsManager().cancelRequest(reqId, true);
    }
}
