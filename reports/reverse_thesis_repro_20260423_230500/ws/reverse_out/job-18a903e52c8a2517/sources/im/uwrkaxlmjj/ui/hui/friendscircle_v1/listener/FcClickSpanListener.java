package im.uwrkaxlmjj.ui.hui.friendscircle_v1.listener;

import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.text.TextUtils;
import com.bjz.comm.net.bean.FCEntitysResponse;
import com.bjz.comm.net.expandViewModel.LinkType;
import com.just.agentweb.DefaultWebClient;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.browser.Browser;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.hui.chats.NewProfileActivity;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.expandTextView.ExpandableTextView;

/* JADX INFO: loaded from: classes5.dex */
public class FcClickSpanListener implements ExpandableTextView.OnLinkClickListener {
    private FcItemActionClickListener listener;
    private final Context mContext;
    private final int mGuid;

    public FcClickSpanListener(Context context, int guid, FcItemActionClickListener listener) {
        this.mContext = context;
        this.mGuid = guid;
        this.listener = listener;
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.hui.friendscircle_v1.listener.FcClickSpanListener$1, reason: invalid class name */
    static /* synthetic */ class AnonymousClass1 {
        static final /* synthetic */ int[] $SwitchMap$com$bjz$comm$net$expandViewModel$LinkType;

        static {
            int[] iArr = new int[LinkType.values().length];
            $SwitchMap$com$bjz$comm$net$expandViewModel$LinkType = iArr;
            try {
                iArr[LinkType.LINK_TYPE.ordinal()] = 1;
            } catch (NoSuchFieldError e) {
            }
            try {
                $SwitchMap$com$bjz$comm$net$expandViewModel$LinkType[LinkType.MENTION_TYPE.ordinal()] = 2;
            } catch (NoSuchFieldError e2) {
            }
            try {
                $SwitchMap$com$bjz$comm$net$expandViewModel$LinkType[LinkType.SELF.ordinal()] = 3;
            } catch (NoSuchFieldError e3) {
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.expandTextView.ExpandableTextView.OnLinkClickListener
    public void onLinkClickListener(LinkType type, String content, String selfContent, FCEntitysResponse entityPosition) {
        int i = AnonymousClass1.$SwitchMap$com$bjz$comm$net$expandViewModel$LinkType[type.ordinal()];
        if (i == 1) {
            if (!TextUtils.isEmpty(content) && this.mContext != null) {
                if ((content.contains("tel:") && TextUtils.isDigitsOnly(content.replace("tel:", ""))) || TextUtils.isDigitsOnly(content)) {
                    this.mContext.startActivity(new Intent("android.intent.action.DIAL", Uri.parse(content)));
                    return;
                }
                if (Browser.isInternalUrl(content, null)) {
                    Browser.openUrl(this.mContext, content, true);
                    return;
                }
                String realUrl = content;
                if (!realUrl.contains("://") && (!realUrl.startsWith(DefaultWebClient.HTTP_SCHEME) || !realUrl.startsWith(DefaultWebClient.HTTPS_SCHEME))) {
                    realUrl = DefaultWebClient.HTTP_SCHEME + realUrl;
                }
                Intent intent = new Intent();
                intent.setAction("android.intent.action.VIEW");
                Uri content_url = Uri.parse(realUrl);
                intent.setData(content_url);
                this.mContext.startActivity(intent);
                return;
            }
            return;
        }
        if (i == 2 && entityPosition != null) {
            getUserInfo(entityPosition);
        }
    }

    private void getUserInfo(FCEntitysResponse fcEntitysResponse) {
        boolean clientActivated = UserConfig.getInstance(UserConfig.selectedAccount).isClientActivated();
        if (!clientActivated) {
            return;
        }
        ConnectionsManager connectionsManager = ConnectionsManager.getInstance(UserConfig.selectedAccount);
        MessagesController messagesController = MessagesController.getInstance(UserConfig.selectedAccount);
        if (connectionsManager != null && messagesController != null && this.mGuid != 0) {
            TLRPC.TL_users_getFullUser req = new TLRPC.TL_users_getFullUser();
            TLRPC.TL_inputUser user = new TLRPC.TL_inputUser();
            user.user_id = fcEntitysResponse.getUserID();
            user.access_hash = fcEntitysResponse.getAccessHash();
            req.id = user;
            int reqId = connectionsManager.sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.listener.-$$Lambda$FcClickSpanListener$u9JJh-P60u_rIXVmbq3RE5pczF4
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$getUserInfo$1$FcClickSpanListener(tLObject, tL_error);
                }
            });
            connectionsManager.bindRequestToGuid(reqId, this.mGuid);
        }
    }

    public /* synthetic */ void lambda$getUserInfo$1$FcClickSpanListener(final TLObject response, TLRPC.TL_error error) {
        if (error == null) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.listener.-$$Lambda$FcClickSpanListener$3VEU9mF9pulqX3UaVPJylyf4keg
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$0$FcClickSpanListener(response);
                }
            });
        }
    }

    public /* synthetic */ void lambda$null$0$FcClickSpanListener(TLObject response) {
        TLRPC.UserFull userFull = (TLRPC.UserFull) response;
        MessagesController.getInstance(UserConfig.selectedAccount).putUser(userFull.user, false);
        Bundle bundle = new Bundle();
        bundle.putInt("user_id", userFull.user.id);
        FcItemActionClickListener fcItemActionClickListener = this.listener;
        if (fcItemActionClickListener != null) {
            fcItemActionClickListener.onPresentFragment(new NewProfileActivity(bundle));
        }
    }
}
