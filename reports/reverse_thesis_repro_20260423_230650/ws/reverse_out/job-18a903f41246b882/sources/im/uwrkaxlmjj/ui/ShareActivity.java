package im.uwrkaxlmjj.ui;

import android.app.Activity;
import android.app.Dialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.View;
import android.view.ViewGroup;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.MessageObject;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.Utilities;
import im.uwrkaxlmjj.tgnet.SerializedData;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.components.ShareAlert;

/* JADX INFO: loaded from: classes5.dex */
public class ShareActivity extends Activity {
    private Dialog visibleDialog;

    @Override // android.app.Activity
    protected void onCreate(Bundle savedInstanceState) {
        ApplicationLoader.postInitApplication();
        AndroidUtilities.checkDisplaySize(this, getResources().getConfiguration());
        requestWindowFeature(1);
        setTheme(2131755401);
        super.onCreate(savedInstanceState);
        setContentView(new View(this), new ViewGroup.LayoutParams(-1, -1));
        Intent intent = getIntent();
        if (intent == null || !"android.intent.action.VIEW".equals(intent.getAction()) || intent.getData() == null) {
            finish();
            return;
        }
        Uri data = intent.getData();
        String scheme = data.getScheme();
        String url = data.toString();
        String hash = data.getQueryParameter("hash");
        if (!"hchat".equals(scheme) || !url.toLowerCase().startsWith("hchat://share_game_score") || TextUtils.isEmpty(hash)) {
            finish();
            return;
        }
        SharedPreferences sharedPreferences = ApplicationLoader.applicationContext.getSharedPreferences("botshare", 0);
        String message = sharedPreferences.getString(hash + "_m", null);
        if (TextUtils.isEmpty(message)) {
            finish();
            return;
        }
        SerializedData serializedData = new SerializedData(Utilities.hexToBytes(message));
        TLRPC.Message mess = TLRPC.Message.TLdeserialize(serializedData, serializedData.readInt32(false), false);
        mess.readAttachPath(serializedData, 0);
        serializedData.cleanup();
        if (mess == null) {
            finish();
            return;
        }
        String link = sharedPreferences.getString(hash + "_link", null);
        MessageObject messageObject = new MessageObject(UserConfig.selectedAccount, mess, false);
        messageObject.messageOwner.with_my_score = true;
        try {
            ShareAlert shareAlertCreateShareAlert = ShareAlert.createShareAlert(this, messageObject, null, false, link, false);
            this.visibleDialog = shareAlertCreateShareAlert;
            shareAlertCreateShareAlert.setCanceledOnTouchOutside(true);
            this.visibleDialog.setOnDismissListener(new DialogInterface.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ShareActivity$6uDbh7Mz8IpRRNPsH0jXcqz5zEg
                @Override // android.content.DialogInterface.OnDismissListener
                public final void onDismiss(DialogInterface dialogInterface) {
                    this.f$0.lambda$onCreate$0$ShareActivity(dialogInterface);
                }
            });
            this.visibleDialog.show();
        } catch (Exception e) {
            FileLog.e(e);
            finish();
        }
    }

    public /* synthetic */ void lambda$onCreate$0$ShareActivity(DialogInterface dialog) {
        if (!isFinishing()) {
            finish();
        }
        this.visibleDialog = null;
    }

    @Override // android.app.Activity
    public void onPause() {
        super.onPause();
        try {
            if (this.visibleDialog != null && this.visibleDialog.isShowing()) {
                this.visibleDialog.dismiss();
                this.visibleDialog = null;
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
    }
}
