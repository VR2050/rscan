package im.uwrkaxlmjj.messenger.voip;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.view.KeyEvent;

/* JADX INFO: loaded from: classes2.dex */
public class VoIPMediaButtonReceiver extends BroadcastReceiver {
    @Override // android.content.BroadcastReceiver
    public void onReceive(Context context, Intent intent) {
        if (!"android.intent.action.MEDIA_BUTTON".equals(intent.getAction()) || VoIPService.getSharedInstance() == null) {
            return;
        }
        KeyEvent ev = (KeyEvent) intent.getParcelableExtra("android.intent.extra.KEY_EVENT");
        VoIPService.getSharedInstance().onMediaButtonEvent(ev);
    }
}
