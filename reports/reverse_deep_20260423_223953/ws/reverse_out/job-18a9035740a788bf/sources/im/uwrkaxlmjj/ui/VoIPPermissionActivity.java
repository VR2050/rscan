package im.uwrkaxlmjj.ui;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import im.uwrkaxlmjj.messenger.voip.VoIPService;
import im.uwrkaxlmjj.ui.components.voip.VoIPHelper;

/* JADX INFO: loaded from: classes5.dex */
public class VoIPPermissionActivity extends Activity {
    @Override // android.app.Activity
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        requestPermissions(new String[]{"android.permission.RECORD_AUDIO"}, 101);
    }

    @Override // android.app.Activity
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        if (requestCode == 101) {
            if (grantResults.length > 0 && grantResults[0] == 0) {
                if (VoIPService.getSharedInstance() != null) {
                    VoIPService.getSharedInstance().acceptIncomingCall();
                }
                finish();
                startActivity(new Intent(this, (Class<?>) VoIPActivity.class));
                return;
            }
            if (!shouldShowRequestPermissionRationale("android.permission.RECORD_AUDIO")) {
                if (VoIPService.getSharedInstance() != null) {
                    VoIPService.getSharedInstance().declineIncomingCall();
                }
                VoIPHelper.permissionDenied(this, new Runnable() { // from class: im.uwrkaxlmjj.ui.VoIPPermissionActivity.1
                    @Override // java.lang.Runnable
                    public void run() {
                        VoIPPermissionActivity.this.finish();
                    }
                });
                return;
            }
            finish();
        }
    }
}
