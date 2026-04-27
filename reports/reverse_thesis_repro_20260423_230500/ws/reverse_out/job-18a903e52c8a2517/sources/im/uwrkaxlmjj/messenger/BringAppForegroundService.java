package im.uwrkaxlmjj.messenger;

import android.app.IntentService;
import android.content.Intent;
import com.google.android.exoplayer2.C;
import im.uwrkaxlmjj.ui.LaunchActivity;

/* JADX INFO: loaded from: classes2.dex */
public class BringAppForegroundService extends IntentService {
    public BringAppForegroundService() {
        super("BringAppForegroundService");
    }

    @Override // android.app.IntentService
    protected void onHandleIntent(Intent intent) {
        Intent intent2 = new Intent(this, (Class<?>) LaunchActivity.class);
        intent2.setFlags(C.ENCODING_PCM_MU_LAW);
        intent2.setAction("android.intent.action.MAIN");
        startActivity(intent2);
    }
}
