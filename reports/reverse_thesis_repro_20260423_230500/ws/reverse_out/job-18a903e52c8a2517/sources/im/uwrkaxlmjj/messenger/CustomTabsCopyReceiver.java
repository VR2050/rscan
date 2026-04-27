package im.uwrkaxlmjj.messenger;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;

/* JADX INFO: loaded from: classes2.dex */
public class CustomTabsCopyReceiver extends BroadcastReceiver {
    @Override // android.content.BroadcastReceiver
    public void onReceive(Context context, Intent intent) {
        String url = intent.getDataString();
        if (url != null) {
            AndroidUtilities.addToClipboard(url);
            ToastUtils.show(mpEIGo.juqQQs.esbSDO.R.string.LinkCopied);
        }
    }
}
