package im.uwrkaxlmjj.ui.hui.visualcall;

import android.text.TextUtils;
import com.socks.library.KLog;
import im.uwrkaxlmjj.messenger.AccountInstance;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.tgnet.TLRPCCall;
import java.util.ArrayList;

/* JADX INFO: loaded from: classes5.dex */
public class AVideoCallInterface {

    public interface AVideoRequestCallBack {
        void onError(TLRPC.TL_error tL_error);

        void onSuccess(TLObject tLObject);
    }

    public static void StartAVideoCall(boolean blnVideo, ArrayList<TLRPC.InputPeer> userId, TLRPC.InputPeer channelId, final AVideoRequestCallBack callBack) {
        TLRPCCall.TL_MeetRequestCall req = new TLRPCCall.TL_MeetRequestCall();
        if (channelId != null) {
            req.flags = 7;
        } else {
            req.flags = 3;
        }
        req.video = blnVideo;
        req.channel_id = channelId;
        req.userIdList = userId;
        req.random_id = AccountInstance.getInstance(UserConfig.selectedAccount).getSendMessagesHelper().getNextRandomId();
        AccountInstance.getInstance(UserConfig.selectedAccount).getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$AVideoCallInterface$ToUsD6R2tk2cLkNb6YraLnTw-iU
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$AVideoCallInterface$4dfeSubmvtvcrmzfgsUQDi7B1Jk
                    @Override // java.lang.Runnable
                    public final void run() {
                        AVideoCallInterface.lambda$null$0(tLObject, tL_error, aVideoRequestCallBack);
                    }
                });
            }
        });
    }

    static /* synthetic */ void lambda$null$0(TLObject response, TLRPC.TL_error error, AVideoRequestCallBack callBack) {
        if (response != null) {
            TLRPC.Updates updates = (TLRPC.Updates) response;
            TLRPCCall.TL_UpdateMeetCallWaiting res = (TLRPCCall.TL_UpdateMeetCallWaiting) updates.updates.get(0);
            if (error != null) {
                if (callBack != null) {
                    callBack.onError(error);
                    return;
                }
                return;
            } else {
                String str = res.data.data;
                if (callBack != null) {
                    callBack.onSuccess(res);
                    return;
                }
                return;
            }
        }
        if (callBack != null) {
            callBack.onError(error);
        }
    }

    public static void AcceptAVideoCall(String strID, final AVideoRequestCallBack callBack) {
        if (TextUtils.isEmpty(strID)) {
            return;
        }
        FileLog.d("AcceptAVideoCall" + strID);
        TLRPCCall.TL_MeetAcceptCall req = new TLRPCCall.TL_MeetAcceptCall();
        req.peer = new TLRPCCall.TL_InputMeetCall();
        req.peer.id = strID;
        AccountInstance.getInstance(UserConfig.selectedAccount).getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$AVideoCallInterface$1it4XXwHurPLPA__EDfECyOS1qY
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$AVideoCallInterface$1yFVQOG6vdxw-g5kxZkNccr3MO0
                    @Override // java.lang.Runnable
                    public final void run() {
                        AVideoCallInterface.lambda$null$2(tL_error, aVideoRequestCallBack);
                    }
                });
            }
        });
    }

    static /* synthetic */ void lambda$null$2(TLRPC.TL_error error, AVideoRequestCallBack callBack) {
        if (error != null) {
            FileLog.d("AcceptAVideoCall res111111");
            if (callBack != null) {
                callBack.onError(error);
            }
        }
    }

    public static void DiscardAVideoCall(String strID, int iDur, boolean blnVideo) {
        TLRPCCall.TL_MeetDiscardCall req = new TLRPCCall.TL_MeetDiscardCall();
        req.peer = new TLRPCCall.TL_InputMeetCall();
        req.peer.id = strID;
        req.duration = iDur;
        req.flags = 0;
        req.video = blnVideo;
        req.reason = new TLRPC.TL_phoneCallDiscardReasonHangup();
        KLog.d("aaaa 开始发挂断消息");
        AccountInstance.getInstance(UserConfig.selectedAccount).getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$AVideoCallInterface$ZTIzSyk-yuZu-BIHIfUAco8iPU4
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                AVideoCallInterface.lambda$DiscardAVideoCall$4(tLObject, tL_error);
            }
        });
    }

    static /* synthetic */ void lambda$DiscardAVideoCall$4(TLObject response, TLRPC.TL_error error) {
        if (error != null) {
            KLog.d("aaaa 发挂断消息异常");
        }
    }

    public static void ConfirmCall(String strID, long lFinger, final AVideoRequestCallBack callBack) {
        TLRPCCall.TL_MeetConfirmCall req = new TLRPCCall.TL_MeetConfirmCall();
        req.peer = new TLRPCCall.TL_InputMeetCall();
        req.peer.id = strID;
        req.key_fingerprint = lFinger;
        AccountInstance.getInstance(UserConfig.selectedAccount).getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$AVideoCallInterface$rPvEnwhPxTLVJw2MTgS4EdiOGYI
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$AVideoCallInterface$Y-XQHsHJNCG8g35tMOrYlJRSF0s
                    @Override // java.lang.Runnable
                    public final void run() {
                        AVideoCallInterface.lambda$null$5(tLObject, tL_error, aVideoRequestCallBack);
                    }
                });
            }
        });
    }

    static /* synthetic */ void lambda$null$5(TLObject response, TLRPC.TL_error error, AVideoRequestCallBack callBack) {
        if (response != null) {
            TLRPC.Updates updates = (TLRPC.Updates) response;
            if (error != null) {
                if (callBack != null) {
                    callBack.onError(error);
                    return;
                }
                return;
            } else {
                if (callBack != null) {
                    callBack.onSuccess(updates.updates.get(0));
                    return;
                }
                return;
            }
        }
        if (callBack != null) {
            callBack.onError(error);
        }
    }

    public static void IsBusyingNow(String strID) {
        KLog.d("----------收到音视频2888");
        TLRPCCall.TL_MeetReceivedCall req = new TLRPCCall.TL_MeetReceivedCall();
        req.peer = new TLRPCCall.TL_InputMeetCall();
        req.peer.id = strID;
        AccountInstance.getInstance(UserConfig.selectedAccount).getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$AVideoCallInterface$XUt8t2-z1p1ZHT4vJEmJxegg7ao
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$AVideoCallInterface$OiN33LOrq5viZsspWWSicgPTXR8
                    @Override // java.lang.Runnable
                    public final void run() {
                        AVideoCallInterface.lambda$null$7(tL_error);
                    }
                });
            }
        });
    }

    static /* synthetic */ void lambda$null$7(TLRPC.TL_error error) {
        if (error != null) {
            FileLog.d("IsBusyingNow res111111");
        }
    }

    public static void sendJumpPacket(String strID, final AVideoRequestCallBack callBack) {
        KLog.d("+++++++ sendJumpPacket = " + strID);
        TLRPCCall.TL_MeetKeepCallV1 req = new TLRPCCall.TL_MeetKeepCallV1();
        req.peer = new TLRPCCall.TL_InputMeetCall();
        req.peer.id = strID;
        AccountInstance.getInstance(UserConfig.selectedAccount).getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$AVideoCallInterface$FtPn1bP1f95bA3ic2C0-i7IJBdA
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$AVideoCallInterface$6xzU_sMWiGtkgmGGfBBL7XSezSM
                    @Override // java.lang.Runnable
                    public final void run() {
                        AVideoCallInterface.lambda$null$9(tL_error, tLObject, aVideoRequestCallBack);
                    }
                });
            }
        });
    }

    static /* synthetic */ void lambda$null$9(TLRPC.TL_error error, TLObject response, AVideoRequestCallBack callBack) {
        if (error != null) {
            KLog.d("------keepcall error = " + error.text);
            return;
        }
        if (response != null) {
            TLRPCCall.TL_MeetModel meetModel = (TLRPCCall.TL_MeetModel) response;
            if (callBack != null) {
                callBack.onSuccess(meetModel);
            }
        }
    }

    public static void GetCallHistory(TLRPC.InputPeer uid, boolean blnVideo, int offset_id, int offset_date, int add_offset, int limit, int max_id, int min_id, int hash, final AVideoRequestCallBack callBack) {
        TLRPCCall.TL_MeetGetCallHistory req = new TLRPCCall.TL_MeetGetCallHistory();
        req.peer = uid;
        req.flags = 1;
        req.video = blnVideo;
        req.offset_id = offset_id;
        req.offset_date = offset_date;
        req.add_offset = add_offset;
        req.limit = limit;
        req.max_id = max_id;
        req.min_id = min_id;
        req.hash = hash;
        AccountInstance.getInstance(UserConfig.selectedAccount).getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$AVideoCallInterface$lcznxZ_m2TRV1NXdB9zbYiPIsRo
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$AVideoCallInterface$Y9VY6DFzESkc0mv-rwHR74wrjGM
                    @Override // java.lang.Runnable
                    public final void run() {
                        AVideoCallInterface.lambda$null$11(tLObject, tL_error, aVideoRequestCallBack);
                    }
                });
            }
        });
    }

    static /* synthetic */ void lambda$null$11(TLObject response, TLRPC.TL_error error, AVideoRequestCallBack callBack) {
        TLRPCCall.TL_UpdateMeetCallHistory res = (TLRPCCall.TL_UpdateMeetCallHistory) response;
        if (error != null) {
            if (callBack != null) {
                callBack.onError(error);
            }
        } else {
            String str = res.data.data;
            if (callBack != null) {
                callBack.onSuccess(response);
            }
        }
    }

    public static void ChangeToVoiceCall(String strID, boolean blnVideo) {
        TLRPCCall.TL_MeetChangeCall req = new TLRPCCall.TL_MeetChangeCall();
        req.peer = new TLRPCCall.TL_InputMeetCall();
        req.peer.id = strID;
        req.flags = 0;
        req.video = blnVideo;
        AccountInstance.getInstance(UserConfig.selectedAccount).getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$AVideoCallInterface$xufNTRyN7yFov5VPrOb50ikBLd0
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                AVideoCallInterface.lambda$ChangeToVoiceCall$13(tLObject, tL_error);
            }
        });
    }

    static /* synthetic */ void lambda$ChangeToVoiceCall$13(TLObject response, TLRPC.TL_error error) {
    }
}
