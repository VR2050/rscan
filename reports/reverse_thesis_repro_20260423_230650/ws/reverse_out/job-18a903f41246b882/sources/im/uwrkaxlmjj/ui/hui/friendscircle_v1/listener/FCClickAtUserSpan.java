package im.uwrkaxlmjj.ui.hui.friendscircle_v1.listener;

import android.os.Bundle;
import android.text.TextPaint;
import android.view.View;
import android.widget.TextView;
import com.bjz.comm.net.bean.FCEntitysResponse;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.hui.chats.NewProfileActivity;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcPageOthersActivity;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.listener.SpanAtUserCallBack;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.span.ClickAtUserSpan;

/* JADX INFO: loaded from: classes5.dex */
public class FCClickAtUserSpan extends ClickAtUserSpan {
    private int guid;
    private FCEntitysResponse mFcEntitysResponse;
    private SpanAtUserCallBack spanClickCallBack;

    public FCClickAtUserSpan(int guid, FCEntitysResponse FCEntitysResponse, int color, SpanAtUserCallBack spanClickCallBack) {
        super(FCEntitysResponse, color, spanClickCallBack);
        this.spanClickCallBack = spanClickCallBack;
        this.guid = guid;
        this.mFcEntitysResponse = FCEntitysResponse;
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.span.ClickAtUserSpan, android.text.style.ClickableSpan
    public void onClick(View view) {
        FCEntitysResponse fCEntitysResponse;
        super.onClick(view);
        if (view instanceof TextView) {
            ((TextView) view).setHighlightColor(0);
        }
        if (this.spanClickCallBack != null && (fCEntitysResponse = this.mFcEntitysResponse) != null && fCEntitysResponse.getUserID() != 0 && this.mFcEntitysResponse.getAccessHash() != 0) {
            this.spanClickCallBack.onPresentFragment(new FcPageOthersActivity(this.mFcEntitysResponse.getUserID(), this.mFcEntitysResponse.getAccessHash()));
        }
    }

    private void getUserInfo() {
        boolean clientActivated = UserConfig.getInstance(UserConfig.selectedAccount).isClientActivated();
        if (!clientActivated) {
            return;
        }
        ConnectionsManager connectionsManager = ConnectionsManager.getInstance(UserConfig.selectedAccount);
        MessagesController messagesController = MessagesController.getInstance(UserConfig.selectedAccount);
        if (connectionsManager != null && messagesController != null && this.guid != 0) {
            TLRPC.TL_users_getFullUser req = new TLRPC.TL_users_getFullUser();
            TLRPC.TL_inputUser user = new TLRPC.TL_inputUser();
            user.user_id = this.mFcEntitysResponse.getUserID();
            user.access_hash = this.mFcEntitysResponse.getAccessHash();
            req.id = user;
            int reqId = connectionsManager.sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.listener.-$$Lambda$FCClickAtUserSpan$A_grqzuQtYWTcRbi3D6oSRLYQTk
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$getUserInfo$1$FCClickAtUserSpan(tLObject, tL_error);
                }
            });
            connectionsManager.bindRequestToGuid(reqId, this.guid);
        }
    }

    public /* synthetic */ void lambda$getUserInfo$1$FCClickAtUserSpan(final TLObject response, TLRPC.TL_error error) {
        if (error == null) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.listener.-$$Lambda$FCClickAtUserSpan$YwjdEup_3ROe0hbrVtpAoihzfL8
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$0$FCClickAtUserSpan(response);
                }
            });
        }
    }

    public /* synthetic */ void lambda$null$0$FCClickAtUserSpan(TLObject response) {
        TLRPC.UserFull userFull = (TLRPC.UserFull) response;
        MessagesController.getInstance(UserConfig.selectedAccount).putUser(userFull.user, false);
        Bundle bundle = new Bundle();
        bundle.putInt("user_id", userFull.user.id);
        SpanAtUserCallBack spanAtUserCallBack = this.spanClickCallBack;
        if (spanAtUserCallBack != null) {
            spanAtUserCallBack.onPresentFragment(new NewProfileActivity(bundle));
        }
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.span.ClickAtUserSpan, android.text.style.ClickableSpan, android.text.style.CharacterStyle
    public void updateDrawState(TextPaint ds) {
        super.updateDrawState(ds);
    }
}
