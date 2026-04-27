package im.uwrkaxlmjj.ui;

import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import im.uwrkaxlmjj.ui.components.voip.VoIPHelper;

/* JADX INFO: loaded from: classes5.dex */
public class VoIPFeedbackActivity extends Activity {
    @Override // android.app.Activity
    protected void onCreate(Bundle savedInstanceState) {
        getWindow().addFlags(524288);
        super.onCreate(savedInstanceState);
        overridePendingTransition(0, 0);
        setContentView(new View(this));
        VoIPHelper.showRateAlert(this, new Runnable() { // from class: im.uwrkaxlmjj.ui.VoIPFeedbackActivity.1
            @Override // java.lang.Runnable
            public void run() {
                VoIPFeedbackActivity.this.finish();
            }
        }, getIntent().getLongExtra("call_id", 0L), getIntent().getLongExtra("call_access_hash", 0L), getIntent().getIntExtra("account", 0), false);
    }

    @Override // android.app.Activity
    public void finish() {
        super.finish();
        overridePendingTransition(0, 0);
    }
}
